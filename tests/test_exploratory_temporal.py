import unittest
import numpy as np
import pandas as pd
from src.exploratory_temporal import fit_candidate_baseline, replay_sequence, score_sequence
from src.temporal_drift import TEMPORAL_FEATURES


def fixture(n=8):
    return pd.DataFrame(dict(window_id=[f'w{i}' for i in range(n)],
        identity_status=['candidate_legitimate']*n,time_shield_temporal_eligible=[True]*n,
        pcap=['fixture']*n,candidate_stream_id=['stream']*n,start_ns=np.arange(n)*10,
        first_frame=np.arange(n)*20,
        median_interarrival_ms=100+np.arange(n)%3,
        mad_interarrival_ms=1+np.arange(n)%4,
        tsf_slope_s_per_s=1+np.arange(n)*1e-5))


class ExploratoryTemporalTests(unittest.TestCase):
    def test_candidate_scope_is_explicit(self):
        baseline=fit_candidate_baseline(fixture(),.1)
        self.assertFalse(baseline['verified_enrollment'])
        self.assertEqual(baseline['trust_scope'],'candidate_legitimate_exploratory_only')
        bad=fixture();bad.loc[0,'identity_status']='verified_legitimate'
        with self.assertRaises(ValueError):fit_candidate_baseline(bad,.1)

    def test_invalid_window_resets_ewma_and_persistence(self):
        data=fixture();baseline=fit_candidate_baseline(data,.1)
        data.loc[2,'time_shield_temporal_eligible']=False
        scored=score_sequence(data,baseline,0.3,'mahalanobis')
        self.assertIsNone(scored[2]['distance'])
        self.assertEqual(scored[3]['distance'],scored[3]['smoothed_distance'])
        states=replay_sequence(data,baseline,100,0.3,3,'mahalanobis')
        self.assertEqual([x['status'] for x in states[:6]],
                         ['UNAVAILABLE','UNAVAILABLE','UNAVAILABLE','UNAVAILABLE','UNAVAILABLE','STABLE'])

    def test_nonfinite_slope_is_unavailable(self):
        data=fixture();baseline=fit_candidate_baseline(data,.1);data.loc[3,TEMPORAL_FEATURES[2]]=np.nan
        result=score_sequence(data,baseline,.3,'standardized_euclidean')
        self.assertFalse(result[3]['temporal_valid'])


if __name__=='__main__':unittest.main()
