"""Small unit fixtures are code tests, never research data or experiment metrics."""
import json
import tempfile
import unittest
from pathlib import Path

from src.common import epoch_ns, frame_key, unique_index
from src.dataset_audit import compare_frames, profile_csv
from src.feature_extraction import rssi_per_frame, sequence_increment, stable_ie_ids, stream_quality
from src.label_validation import audit_label_join, identity_status, training_gate
from src.pcap_tools import filter_matches, read_official_filter
from src.preprocessing import FORBIDDEN, validate_feature_names

PROJECT = Path(__file__).resolve().parents[1]
POLICY = json.loads((PROJECT / 'configs/experiment.yaml').read_text())['label_policy']


def beacon(**changes):
    row = dict(pcap='pcaps/7. Evil_Twin.pcap', frame_number='1', frame_time_epoch='1608065662.005638000',
        frame_len='342', bssid='0c:9d:92:54:fe:34', capabilities='0x1111',
        beacon_role_label='NORMAL', attack_related_label='unknown',
        attack_label_status='not_selected_by_filter', tsf='1000000', beacon_interval_tu='100',
        sequence_number='4095')
    return row | changes


class JoinTests(unittest.TestCase):
    def test_same_frame_different_capture_is_distinct(self):
        self.assertEqual(len(unique_index([beacon(), beacon(pcap='pcaps/4. Rogue_AP.pcap')])), 2)

    def test_duplicate_key_rejected_even_if_identical(self):
        with self.assertRaises(ValueError):
            unique_index([beacon(), beacon()])

    def test_original_frame_required(self):
        row = beacon(); del row['frame_number']
        with self.assertRaises(KeyError):
            frame_key(row)

    def test_nonpositive_frame_rejected(self):
        with self.assertRaises(ValueError):
            frame_key(beacon(frame_number='0'))

    def test_unknown_not_promoted_by_missing_attack_row(self):
        row = beacon(beacon_role_label='unknown')
        result = audit_label_join([row], [])
        self.assertTrue(result[0]['agrees'])
        self.assertEqual(row['beacon_role_label'], 'unknown')

    def test_metadata_mismatch_detected(self):
        label = dict(pcap='pcaps/7. Evil_Twin.pcap', frame_number='1', attack_related_label='Evil_Twin',
            frame_time_epoch='1608065662.005638001', frame_len='342', wlan_bssid='0c:9d:92:54:fe:34',
            wlan_capabilities='0x1111', wlan_fc_type_subtype='0x0008')
        row = beacon(attack_related_label='Evil_Twin', attack_label_status='matched_filter_label')
        result = audit_label_join([row], [label])[0]
        self.assertFalse(result['agrees'])
        self.assertIn('frame_time_epoch', result['mismatched_fields'])

    def test_one_nanosecond_is_preserved(self):
        self.assertEqual(epoch_ns('1608065662.005638001') - epoch_ns('1608065662.005638000'), 1)

    def test_subnanosecond_rejected(self):
        with self.assertRaises(ValueError):
            epoch_ns('1.0000000001')

    def test_missing_reextracted_frame_reported(self):
        result = compare_frames([beacon()], [], ['tsf'])[0]
        self.assertEqual(result['mismatched_fields'], 'missing_reextracted_record')

    def test_rssi_separator_normalized(self):
        a = beacon(radiotap_rssi_dbm='-35;-41;-35')
        b = beacon(radiotap_rssi_dbm='-35,-41,-35')
        self.assertTrue(compare_frames([a], [b], ['radiotap_rssi_dbm'])[0]['agrees'])


class LabelTests(unittest.TestCase):
    def test_documented_mapping_is_candidate_only(self):
        self.assertEqual(identity_status(beacon(), POLICY)[0], 'candidate_legitimate')

    def test_same_bssid_other_capture_remains_unknown(self):
        self.assertEqual(identity_status(beacon(pcap='pcaps/4. Rogue_AP.pcap'), POLICY)[0], 'unknown')

    def test_legacy_role_conflict_is_unknown(self):
        self.assertEqual(identity_status(beacon(beacon_role_label='EVIL_TWIN'), POLICY), ('unknown', 'legacy_role_conflict'))

    def test_candidate_classes_do_not_unlock_training(self):
        gate = training_gate([{'identity_status': 'candidate_legitimate'}, {'identity_status': 'candidate_evil_twin'}], True)
        self.assertFalse(gate['supervised_training_allowed'])

    def test_integrity_failure_blocks_verified_classes(self):
        gate = training_gate([{'identity_status': 'verified_legitimate'}, {'identity_status': 'verified_evil_twin'}], False)
        self.assertFalse(gate['supervised_training_allowed'])


class FeatureTests(unittest.TestCase):
    def test_sequence_wraparound(self):
        self.assertEqual(sequence_increment(4095, 0), 1)
        self.assertEqual(sequence_increment(100, 100), 0)

    def test_sequence_range(self):
        with self.assertRaises(ValueError):
            sequence_increment(4096, 0)

    def test_rssi_antenna_median(self):
        self.assertEqual(rssi_per_frame('-35;-41;-35'), -35)
        self.assertIsNone(rssi_per_frame(''))

    def test_dynamic_ie_exclusion(self):
        self.assertEqual(stable_ie_ids('0;1;5;11;48;221;48'), (1, 48))

    def test_leakage_deny_all_unapproved_names(self):
        for name in FORBIDDEN | {'renamed_mac', 'new_unreviewed_feature'}:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_feature_names(['rssi_median_dbm', name])

    def test_allowlist(self):
        self.assertEqual(validate_feature_names(['rssi_median_dbm', 'tsf_slope_s_per_s']), ['rssi_median_dbm', 'tsf_slope_s_per_s'])

    def test_tsf_reset_detected_without_regression(self):
        records = [beacon(), beacon(frame_number='2', frame_time_epoch='1608065662.108038000', tsf='10', sequence_number='0')]
        result = stream_quality(records, 1.5)[0]
        self.assertEqual(result['tsf_nonpositive'], 1)
        self.assertEqual(result['arrival_gaps'], 0)
        self.assertNotIn('tsf_slope_s_per_s', result)

    def test_large_gap_detected(self):
        records = [beacon(), beacon(frame_number='2', frame_time_epoch='1608065663.005638000', tsf='2000000', sequence_number='0')]
        result = stream_quality(records, 1.5)[0]
        self.assertEqual(result['arrival_gaps'], 1)
        self.assertEqual(result['tsf_gaps'], 1)


class SourceTests(unittest.TestCase):
    def test_filter_read_from_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'Read_me.txt'
            p.write_text('Rogue_AP\n\nwlan.fc.type_subtype==8\n')
            self.assertEqual(read_official_filter(p, 'Rogue_AP'), 'wlan.fc.type_subtype==8')
            with self.assertRaises(ValueError):
                read_official_filter(p, 'Evil_Twin')

    def test_beacon_before_filter_is_not_filter_positive(self):
        r = beacon(frame_number='1351181', subtype='0x0008', frame_len='241', protected='0',
            ip_addresses='', wlan_addresses='0c:9d:92:54:fe:35')
        self.assertFalse(filter_matches('Evil_Twin', r))

    def test_csv_missing_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); p = root / 'tiny.csv'; p.write_text('a,b\n1,\n2,x\n')
            result = profile_csv(p, root)
            self.assertEqual(result['rows'], 2)
            self.assertEqual(result['columns'][1]['missing'], 1)


if __name__ == '__main__':
    unittest.main()
