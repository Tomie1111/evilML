"""Unit fixtures test mechanics only; never enter research experiment outputs."""
import unittest
import numpy as np
import pandas as pd
from src.window_aggregation import make_windows, conservative_label
from src.dataset_splitting import boundaries, assign_splits, validate_splits
from src.train_models import make_pipeline
from src.stream_grouping import group_streams


def records(count=20):
    rows = []
    for i in range(count):
        rows.append(dict(pcap='test.pcap', bssid='aa:bb:cc:dd:ee:01', ssid_hex='41',
            frame_number=str(i + 1), frame_time_epoch=f'{1 + i * 0.1024:.9f}', tsf=str(1_000_000 + i * 102400),
            frame_len='100', captured_len='100', malformed='', capabilities='0x0001',
            beacon_interval_tu='100', ie_tag_ids='0;1;5', rsn_version='', supported_rates='0x8c;0x12',
            extended_supported_rates='', radiotap_rssi_dbm='-35;-40', radiotap_channel_freq='5180',
            sequence_number=str((4090 + i) % 4096), retry='False',
            identity_status='candidate_legitimate', identity_evidence_id='unit_fixture'))
    return rows


class WindowsTests(unittest.TestCase):
    def test_nonoverlap_and_tail(self):
        w, membership = make_windows(records(45), 20)
        self.assertEqual([r['n_frames'] for r in w], [20, 20, 5])
        self.assertEqual(len({r['frame_number'] for r in membership}), 45)
        self.assertFalse(w[-1]['quality_valid'])
        self.assertEqual(w[0]['n_intervals'], 19)

    def test_units_and_raw_mad(self):
        w, _ = make_windows(records(), 20)
        self.assertTrue(w[0]['quality_valid'])
        self.assertAlmostEqual(w[0]['median_interarrival_ms'], 102.4)
        self.assertAlmostEqual(w[0]['mad_interarrival_ms'], 0)
        self.assertAlmostEqual(w[0]['tsf_slope_s_per_s'], 1)
        self.assertAlmostEqual(w[0]['sequence_increment_median'], 1)

    def test_reset_never_regressed(self):
        rows = records(); rows[10]['tsf'] = '1'
        w, _ = make_windows(rows, 20)
        self.assertFalse(w[0]['quality_valid'])
        self.assertTrue(np.isnan(w[0]['tsf_slope_s_per_s']))

    def test_missing_timestamp_flagged(self):
        rows = records(); rows[10]['frame_time_epoch'] = ''
        w, _ = make_windows(rows, 20)
        self.assertFalse(w[0]['quality_valid'])

    def test_incoming_gap_invalidates_next_window(self):
        rows = records(40)
        for row in rows[20:]:
            row['frame_time_epoch'] = f'{float(row["frame_time_epoch"]) + 1:.9f}'
            row['tsf'] = str(int(row['tsf']) + 1000000)
        w, _ = make_windows(rows, 20)
        self.assertTrue(w[0]['quality_valid'])
        self.assertFalse(w[1]['quality_valid'])
        self.assertIn('incoming_arrival_gap', w[1]['quality_reasons'])

    def test_unknown_and_mixed_never_labeled(self):
        rows = records(); rows[-1]['identity_status'] = 'unknown'
        self.assertIsNone(conservative_label(rows)[0])
        rows[-1]['identity_status'] = 'candidate_evil_twin'
        self.assertIsNone(conservative_label(rows)[0])

    def test_capture_streams_never_merge(self):
        a = records(2); b = records(2)
        for row in b: row['pcap'] = 'other.pcap'
        self.assertEqual(len(group_streams(a + b, 'bssid')), 2)

    def test_split_crossing_excluded(self):
        w = pd.DataFrame([dict(start_ns=1,end_ns=11),dict(start_ns=12,end_ns=18),dict(start_ns=22,end_ns=25)])
        w['quality_valid'] = True; w['target'] = 0
        assigned = assign_splits(w, (10,20))
        self.assertEqual(assigned.split.tolist(), ['boundary_excluded','validation','development_test'])

    def test_duplicate_membership_rejected(self):
        w, m = make_windows(records(), 20)
        w = assign_splits(pd.DataFrame(w), (10**12, 2*10**12))
        with self.assertRaises(ValueError): validate_splits(w, pd.DataFrame(m + m[:1]))


class PipelineTests(unittest.TestCase):
    def test_scaler_fitted_only_on_training(self):
        train = pd.DataFrame({'rssi_median_dbm': [-50.,-40.,-30.,-20.], 'capabilities_encoded': ['a','a','b','b']})
        features = list(train)
        model = make_pipeline('logistic_regression',features,{'C':1},42)
        model.fit(train,[0,0,1,1])
        before = model.named_steps['preprocess'].named_transformers_['numeric'].named_steps['scale'].mean_.copy()
        test = pd.DataFrame({'rssi_median_dbm':[10000.], 'capabilities_encoded':['unseen']})
        self.assertTrue(np.isfinite(model.predict_proba(test)).all())
        after = model.named_steps['preprocess'].named_transformers_['numeric'].named_steps['scale'].mean_
        np.testing.assert_array_equal(before,after)
        self.assertEqual(before[0],-35.)


if __name__ == '__main__': unittest.main()
