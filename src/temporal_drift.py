"""Frozen trusted-baseline scoring with explicit indeterminate states."""
import numpy as np

TEMPORAL_FEATURES = ['median_interarrival_ms', 'mad_interarrival_ms', 'tsf_slope_s_per_s']


def fit_baseline(enrollment, shrinkage=0.1):
    if not 0 < shrinkage <= 1: raise ValueError('Invalid shrinkage')
    x = np.asarray(enrollment, dtype=float)
    if x.ndim != 2 or x.shape[1] != 3 or len(x) < 4 or not np.isfinite(x).all():
        raise ValueError('At least four finite trusted enrollment windows required')
    mean = x.mean(axis=0); scale = x.std(axis=0, ddof=1)
    if np.any(scale <= 0): raise ValueError('Degenerate enrollment variance')
    z = (x - mean) / scale; corr = np.cov(z, rowvar=False, ddof=1)
    reg = (1-shrinkage) * corr + shrinkage * np.eye(3)
    return dict(features=TEMPORAL_FEATURES, mean=mean.tolist(), scale=scale.tolist(),
                regularized_correlation=reg.tolist(), shrinkage=shrinkage, fit_n=len(x))


def distance(values, baseline, method='mahalanobis'):
    if baseline.get('features') != TEMPORAL_FEATURES: raise ValueError('Temporal feature/units contract mismatch')
    x = np.asarray(values, dtype=float); mean = np.asarray(baseline['mean']); scale = np.asarray(baseline['scale'])
    if np.any(scale <= 0) or not np.isfinite(x).all(): raise ValueError('Invalid temporal feature vector')
    u = (x - mean) / scale
    if method == 'standardized_euclidean': return np.sqrt(np.sum(u * u, axis=-1))
    if method != 'mahalanobis': raise ValueError(method)
    correlation = np.asarray(baseline['regularized_correlation'])
    if np.linalg.eigvalsh(correlation).min() <= 0: raise ValueError('Baseline covariance not positive definite')
    result = np.einsum('...i,...i->...', u, np.linalg.solve(correlation, np.atleast_2d(u).T).T)
    return np.sqrt(np.maximum(0, result))


class TemporalState:
    def __init__(self, threshold, beta=0.3, K=3):
        if not np.isfinite(threshold) or threshold < 0 or not 0 <= beta < 1 or not isinstance(K,int) or K < 1:
            raise ValueError('Invalid temporal parameters')
        self.threshold, self.beta, self.K = float(threshold), beta, K
        self.reset()

    def reset(self):
        self.previous = None; self.above = 0; self.below = 0

    def update(self, d, valid=True, baseline_available=True):
        if not valid or not baseline_available or d is None or not np.isfinite(d):
            self.reset()
            return dict(status='UNAVAILABLE', reason='invalid_data_or_no_baseline', smoothed_distance=None, streak=0)
        self.previous = float(d) if self.previous is None else self.beta*self.previous + (1-self.beta)*float(d)
        if self.previous > self.threshold:
            self.above += 1; self.below = 0
        else:
            self.below += 1; self.above = 0
        status = 'DRIFT' if self.above >= self.K else 'STABLE' if self.below >= self.K else 'UNAVAILABLE'
        return dict(status=status, reason='persistent_exceedance' if status=='DRIFT' else 'persistent_within_threshold' if status=='STABLE' else 'insufficient_consecutive_evidence',
            smoothed_distance=self.previous, streak=self.above if self.above else -self.below)


def smoothed_values(windows, baseline, beta, method):
    scores = []
    for _, group in windows.groupby('candidate_stream_id', sort=True):
        previous = None
        for _, r in group.sort_values('first_frame').iterrows():
            if not r.quality_valid:
                previous = None; continue
            d = float(np.asarray(distance(r[TEMPORAL_FEATURES].to_numpy(dtype=float), baseline, method)).item())
            previous = d if previous is None else beta*previous+(1-beta)*d
            scores.append(previous)
    return np.asarray(scores)


def replay(windows, baseline, registry, threshold, beta=0.3, K=3, method='mahalanobis'):
    """registry is an explicit set of (session/capture, BSSID), never inferred from ML."""
    results = []
    for (_, _, _), group in windows.groupby(['pcap','candidate_stream_id','split'], sort=True):
        state = TemporalState(threshold,beta,K)
        for _, row in group.sort_values('first_frame').iterrows():
            available = (row.pcap,row.bssid) in registry
            d = float(np.asarray(distance(row[TEMPORAL_FEATURES].to_numpy(dtype=float), baseline, method)).item()) if available and row.quality_valid else None
            update = state.update(d, bool(row.quality_valid), available)
            results.append(dict(window_id=row.window_id, baseline_available=available, distance=d, **update))
    return results
