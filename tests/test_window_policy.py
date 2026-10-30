import unittest
import numpy as np
from test_ml import records
from src.window_policy import evaluate_policy


class PolicyTests(unittest.TestCase):
    def test_capture_gap_rejects_temporal_but_keeps_non_temporal_ml(self):
        rows=records()
        for row in rows[10:]:
            row['frame_time_epoch']=f'{float(row["frame_time_epoch"])+1:.9f}'
            row['tsf']=str(int(row['tsf'])+1000000)
        windows,_=evaluate_policy(rows,20,'bssid_capabilities',1.5)
        self.assertEqual(len(windows),1)
        self.assertFalse(windows[0]['time_shield_temporal_eligible'])
        self.assertTrue(windows[0]['ml_feature_eligible'])
        self.assertTrue(np.isfinite(windows[0]['frame_len_mean']))

    def test_tsf_reset_disables_slope_without_losing_radio_frame(self):
        rows=records(); rows[10]['tsf']='1'
        windows,_=evaluate_policy(rows,20,'bssid_capabilities',1.5)
        w=windows[0]
        self.assertTrue(w['ml_feature_eligible'])
        self.assertFalse(w['time_shield_temporal_eligible'])
        self.assertTrue(np.isnan(w['tsf_slope_s_per_s']))
        self.assertTrue(np.isfinite(w['rssi_median_dbm']))

    def test_missing_tsf_recovers_non_temporal_features(self):
        rows=records();rows[10]['tsf']=''
        windows,_=evaluate_policy(rows,20,'bssid_capabilities',1.5)
        w=windows[0]
        self.assertTrue(w['ml_feature_eligible'])
        self.assertFalse(w['time_shield_temporal_eligible'])
        self.assertTrue(np.isfinite(w['sequence_increment_median']))

    def test_incomplete_frames_still_rejected_for_both(self):
        windows,_=evaluate_policy(records(19),20,'bssid_capabilities',1.5)
        self.assertFalse(windows[0]['ml_feature_eligible'])
        self.assertFalse(windows[0]['time_shield_temporal_eligible'])

    def test_mixed_label_rejected_for_both(self):
        rows=records();rows[-1]['identity_status']='candidate_evil_twin'
        windows,_=evaluate_policy(rows,20,'bssid_capabilities',1.5)
        self.assertFalse(windows[0]['ml_feature_eligible'])
        self.assertFalse(windows[0]['time_shield_temporal_eligible'])

    def test_segmentation_conserves_real_members(self):
        rows=records(40)
        for row in rows[20:]:
            row['frame_time_epoch']=f'{float(row["frame_time_epoch"])+1:.9f}'
            row['tsf']=str(int(row['tsf'])+1000000)
        windows,members=evaluate_policy(rows,20,'bssid_capabilities',1.5,'gap_segmented')
        self.assertEqual(len(members),40)
        self.assertEqual(len({(m['pcap'],m['frame_number']) for m in members}),40)
        self.assertEqual(len({w['window_id'] for w in windows}),2)
        self.assertTrue(all(w['time_shield_temporal_eligible'] for w in windows))


if __name__=='__main__':unittest.main()
