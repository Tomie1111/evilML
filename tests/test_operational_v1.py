"""Engineering fixtures only; these observations never enter research outputs."""
import copy
import itertools
import unittest
from unittest.mock import patch
import numpy as np
import pandas as pd
from src.decision_fusion import fuse
from src.external_inference import verified_metrics
from src.independent_evaluation import readiness
from src.trusted_temporal import enroll, monitor
from src.temporal_drift import TEMPORAL_FEATURES, distance


def enrollment_fixture():
    frame = pd.DataFrame({
        'window_id': ['a','b','c','d'], 'identity_status': ['verified_legitimate']*4,
        'time_shield_temporal_eligible': [True]*4, 'label_provenance': ['test-only']*4,
        'pcap': ['fixture']*4, 'candidate_stream_id': ['stream']*4,
        'start_epoch': ['1','3','5','7'], 'end_epoch': ['2','4','6','8'],
        'first_frame': [1,21,41,61], 'physical_device_id': ['device']*4,
        TEMPORAL_FEATURES[0]: [100,102,101,104], TEMPORAL_FEATURES[1]: [1,2,4,3],
        TEMPORAL_FEATURES[2]: [1,1.001,1.003,1.002]})
    evidence = {'test-only': dict(review_status='verified_legitimate', source_sha256='a'*64,
                                 physical_device_id='device', window_ids=['a','b','c','d'])}
    return frame, evidence


class OperationalTests(unittest.TestCase):
    def test_fusion_cartesian_rules(self):
        for score, status, baseline, ml, temporal in itertools.product(
                [0.1,0.2,0.5,0.8,0.9], ['STABLE','DRIFT','UNAVAILABLE'], [False,True], [False,True], [False,True]):
            with self.subTest(score=score,status=status,baseline=baseline,ml=ml,temporal=temporal):
                expected = 'Pending'
                if ml:
                    if score >= .8: expected = 'Evil Twin Suspected'
                    elif baseline and temporal and status == 'DRIFT': expected = 'Suspicious Trusted AP'
                    elif baseline and temporal and status == 'STABLE' and score <= .2: expected = 'Consistent with Trusted Baseline'
                self.assertEqual(fuse(score,.2,.8,status,baseline,ml,temporal), expected)

    def test_legitimate_only_metrics_no_attack_recall(self):
        result = verified_metrics(['verified_legitimate']*2,[.1,.9],.5)
        self.assertIsNone(result['attack_recall'])
        self.assertIsNone(result['attack_f1'])
        with self.assertRaises(ValueError): verified_metrics(['candidate_legitimate'],[.1],.5)

    def test_enrollment_evidence_and_chronology(self):
        frame, evidence = enrollment_fixture()
        baseline = enroll(frame,evidence,'10')
        self.assertFalse(baseline['updates_allowed'])
        for mutation in ('candidate','overlap','quality','evidence','mixed'):
            with self.subTest(mutation=mutation):
                f=frame.copy(); e=copy.deepcopy(evidence); cutoff='10'
                if mutation=='candidate': f.loc[0,'identity_status']='candidate_legitimate'
                if mutation=='overlap': cutoff='8'
                if mutation=='quality': f.loc[0,'time_shield_temporal_eligible']=False
                if mutation=='evidence': e['test-only']['window_ids']=[]
                if mutation=='mixed': f.loc[0,'candidate_stream_id']='other'
                with self.assertRaises(ValueError): enroll(f,e,cutoff)

    def test_monitor_reset_gap_missing_and_frozen_baseline(self):
        frame,evidence=enrollment_fixture(); baseline=enroll(frame,evidence,'10'); before=copy.deepcopy(baseline)
        frame.start_epoch=['11','13','15','17']
        for reason in ('tsf_reset','capture_gap','missing_timestamp'):
            with self.subTest(reason=reason):
                f=frame.copy(); f.loc[1,'time_shield_temporal_eligible']=False
                if reason=='missing_timestamp': f.loc[1,'start_epoch']=''
                if reason=='tsf_reset': f.loc[1,TEMPORAL_FEATURES[2]]=np.nan
                result=monitor(f,baseline,100,beta=0,K=2)
                self.assertEqual([r['status'] for r in result],['UNAVAILABLE','UNAVAILABLE','UNAVAILABLE','STABLE'])
        self.assertEqual(before,baseline)
        self.assertTrue(all(r['status']=='UNAVAILABLE' for r in monitor(frame,None,100)))

    def test_regularized_distance_finite(self):
        frame,evidence=enrollment_fixture()
        for shrinkage in [.01,.1,.5,1]:
            baseline=enroll(frame,evidence,'10',shrinkage)
            self.assertTrue(np.isfinite(distance(frame[TEMPORAL_FEATURES].to_numpy(),baseline)).all())

    def test_duplicate_capture_cannot_manufacture_sessions(self):
        valid=dict(session_id='a',valid=True,capture_sha256='a'*64,countable_verified_roles=['verified_legitimate'])
        other=dict(valid,session_id='b')
        protocol=dict(verified_roles=['verified_legitimate'],minimum_independent_sessions_per_class=2)
        with patch('src.independent_evaluation.validate_session',side_effect=[valid,other]):
            result=readiness({'schema_version':1},[{},{}],'.',protocol)
        self.assertFalse(result['scoring_authorized_by_data_gate'])
        self.assertEqual(result['countable_independent_sessions_by_role']['verified_legitimate'],1)
