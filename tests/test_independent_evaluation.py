import hashlib
import tempfile
import unittest
from pathlib import Path

from src.independent_evaluation import readiness, validate_session


PROTOCOL = {
    'development_capture_sha256s': ['0' * 64],
    'minimum_independent_sessions_per_class': 1,
    'verified_roles': ['verified_legitimate', 'verified_evil_twin'],
    'allowed_evidence_types': ['device_log', 'event_log'],
    'allowed_scenarios': ['normal_operation', 'ssid_bssid_clone'],
    'countable_ground_truth_scope': 'transmitter_identity',
    'cloned_bssid_requires_frame_attribution': True,
    'require_authorized_testbed': True,
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class IndependentEvaluationTests(unittest.TestCase):
    def test_empty_registry_is_blocked_without_scores(self):
        report = readiness({'schema_version': 1}, [], '.', PROTOCOL)
        self.assertFalse(report['scoring_authorized_by_data_gate'])
        self.assertTrue(report['no_scores_computed'])

    def test_verified_session_requires_real_hashed_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); capture = b'pcap'; log = b'device-log'
            (root/'capture.pcap').write_bytes(capture); (root/'log.json').write_bytes(log)
            session = {
                'session_id': 'session-01', 'capture_path': 'capture.pcap',
                'capture_sha256': digest(capture), 'capture_start_epoch': '1',
                'capture_end_epoch': '10', 'environment_id': 'env-a', 'receiver_id': 'rx-a',
                'independent_from_development': True, 'authorized_testbed': True,
                'evidence': [{'evidence_id': 'e1', 'type': 'device_log', 'path': 'log.json', 'sha256': digest(log)}],
                'devices': [{'device_id': 'ap1', 'ground_truth_role': 'verified_legitimate', 'evidence_ids': ['e1']}],
                'intervals': [{'interval_id': 'i1', 'start_epoch': '2', 'end_epoch': '9',
                    'scenario': 'normal_operation', 'ground_truth_scope': 'transmitter_identity',
                    'device_ids': ['ap1'], 'evidence_ids': ['e1']}],
            }
            result = validate_session(session, root, PROTOCOL)
            self.assertTrue(result['valid'])
            self.assertEqual(result['countable_verified_roles'], ['verified_legitimate'])
            session['capture_sha256'] = 'f' * 64
            self.assertFalse(validate_session(session, root, PROTOCOL)['valid'])

    def test_cloned_bssid_needs_external_frame_attribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); data = b'x'
            (root/'capture.pcap').write_bytes(data); (root/'log.json').write_bytes(data)
            session = {
                'session_id': 'clone-01', 'capture_path': 'capture.pcap', 'capture_sha256': digest(data),
                'capture_start_epoch': '1', 'capture_end_epoch': '10', 'environment_id': 'e', 'receiver_id': 'r',
                'independent_from_development': True, 'authorized_testbed': True,
                'evidence': [{'evidence_id': 'e1', 'type': 'event_log', 'path': 'log.json', 'sha256': digest(data)}],
                'devices': [{'device_id': 'evil', 'ground_truth_role': 'verified_evil_twin', 'evidence_ids': ['e1']}],
                'intervals': [{'interval_id': 'i1', 'start_epoch': '2', 'end_epoch': '9',
                    'scenario': 'ssid_bssid_clone', 'ground_truth_scope': 'transmitter_identity',
                    'device_ids': ['evil'], 'evidence_ids': ['e1']}],
            }
            result = validate_session(session, root, PROTOCOL)
            self.assertTrue(result['valid'])
            self.assertEqual(result['countable_verified_roles'], [])
            self.assertEqual(result['countable_interval_count'], 0)
            self.assertTrue(result['warnings'])
            session['intervals'][0]['frame_attribution_evidence_id'] = 'e1'
            attributed = validate_session(session, root, PROTOCOL)
            self.assertEqual(attributed['countable_verified_roles'], ['verified_evil_twin'])
            self.assertEqual(attributed['countable_interval_count'], 1)


if __name__ == '__main__':
    unittest.main()
