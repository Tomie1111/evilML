import unittest
import numpy as np
from src.temporal_drift import TemporalState, distance, fit_baseline, TEMPORAL_FEATURES
from src.decision_fusion import fuse


class TemporalTests(unittest.TestCase):
    def test_no_drift_is_not_automatically_stable(self):
        s = TemporalState(2, beta=0, K=3)
        self.assertEqual(s.update(1)['status'], 'UNAVAILABLE')
        self.assertEqual(s.update(1)['status'], 'UNAVAILABLE')
        self.assertEqual(s.update(1)['status'], 'STABLE')
        self.assertEqual(s.update(3)['status'], 'UNAVAILABLE')

    def test_persistence_strict_threshold(self):
        s = TemporalState(2,beta=0,K=2)
        self.assertEqual(s.update(2)['status'],'UNAVAILABLE')
        self.assertEqual(s.update(2)['status'],'STABLE')
        s.update(3)
        self.assertEqual(s.update(3)['status'],'DRIFT')

    def test_invalid_resets_ewma_and_streak(self):
        s = TemporalState(2,beta=0.5,K=2)
        s.update(100); s.update(100)
        self.assertEqual(s.update(None,valid=False)['status'],'UNAVAILABLE')
        r=s.update(1)
        self.assertEqual(r['smoothed_distance'],1)
        self.assertEqual(r['status'],'UNAVAILABLE')

    def test_no_baseline_never_stable(self):
        s = TemporalState(2,K=1)
        self.assertEqual(s.update(0,baseline_available=False)['status'],'UNAVAILABLE')

    def test_identity_correlation_agrees_with_euclidean(self):
        b=dict(features=TEMPORAL_FEATURES,mean=[1,2,3],scale=[2,3,4],regularized_correlation=np.eye(3).tolist())
        x=np.array([[3,5,7],[5,8,11]])
        np.testing.assert_allclose(distance(x,b),distance(x,b,'standardized_euclidean'))

    def test_degenerate_enrollment_rejected(self):
        with self.assertRaises(ValueError):fit_baseline(np.ones((10,3)))


class FusionTests(unittest.TestCase):
    def test_invalid_data_overrides_high_score(self):
        self.assertEqual(fuse(1,.2,.8,'DRIFT',True,False),'Pending')

    def test_high_ml_without_baseline(self):
        self.assertEqual(fuse(.9,.2,.8,'UNAVAILABLE',False,True),'Evil Twin Suspected')

    def test_drift_alone_is_not_evil_twin(self):
        self.assertEqual(fuse(.1,.2,.8,'DRIFT',True,True),'Suspicious Trusted AP')

    def test_low_ml_requires_stability_and_baseline(self):
        self.assertEqual(fuse(.1,.2,.8,'UNAVAILABLE',True,True),'Pending')
        self.assertEqual(fuse(.1,.2,.8,'STABLE',False,True),'Pending')
        self.assertEqual(fuse(.1,.2,.8,'STABLE',True,True),'Consistent with Trusted Baseline')

    def test_disabled_low_threshold(self):
        self.assertEqual(fuse(0,None,.8,'STABLE',True,True),'Pending')

    def test_bad_thresholds_rejected(self):
        with self.assertRaises(ValueError):fuse(.5,.9,.8,'STABLE',True,True)


if __name__ == '__main__':unittest.main()
