"""Candidate-role Time-Shield mechanics with explicit exploratory provenance."""
import numpy as np
from .temporal_drift import TEMPORAL_FEATURES, TemporalState, distance, fit_baseline


def fit_candidate_baseline(windows, shrinkage, minimum=4):
    if len(windows) < minimum:
        raise ValueError('Insufficient valid candidate enrollment windows')
    if windows.window_id.duplicated().any():
        raise ValueError('Duplicate enrollment windows')
    if not windows.identity_status.eq('candidate_legitimate').all():
        raise ValueError('Exploratory baseline accepts candidate legitimate only')
    if not windows.time_shield_temporal_eligible.eq(True).all():
        raise ValueError('Enrollment contains temporal-invalid windows')
    if len(windows[['pcap','candidate_stream_id']].drop_duplicates()) != 1:
        raise ValueError('Enrollment must contain one candidate stream')
    baseline=fit_baseline(windows[TEMPORAL_FEATURES].to_numpy(float),shrinkage)
    baseline.update(trust_scope='candidate_legitimate_exploratory_only',verified_enrollment=False,
                    enrollment_window_ids=windows.window_id.tolist(),baseline_updates=False)
    return baseline


def score_sequence(windows, baseline, beta, method):
    """Return raw/EWMA scores; invalid windows reset smoothing."""
    previous=None; rows=[]
    for row in windows.sort_values(['start_ns','first_frame']).itertuples():
        valid=bool(row.time_shield_temporal_eligible)
        values=np.array([getattr(row,name) for name in TEMPORAL_FEATURES],float)
        valid=valid and bool(np.isfinite(values).all())
        if valid:
            raw=float(np.asarray(distance(values,baseline,method)).item())
            previous=raw if previous is None else beta*previous+(1-beta)*raw
            smooth=previous
        else:
            raw=smooth=None;previous=None
        rows.append(dict(window_id=row.window_id,temporal_valid=valid,distance=raw,smoothed_distance=smooth))
    return rows


def replay_sequence(windows, baseline, threshold, beta, K, method):
    """Apply persistence; no alert is STABLE only after K consecutive valid scores."""
    scores=score_sequence(windows,baseline,beta,method);state=TemporalState(threshold,beta=0,K=K)
    output=[]
    for row in scores:
        # score_sequence already applies EWMA; beta=0 prevents double smoothing.
        result=state.update(row['smoothed_distance'],row['temporal_valid'],True)
        output.append(dict(**row,status=result['status'],reason=result['reason'],streak=result['streak']))
    return output
