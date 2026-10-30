"""Evidence-gated temporal enrollment and chronological monitoring.

Evidence review must happen outside the model: records bind reviewed device
evidence to exact window IDs. A MAC address alone is never an enrollment key.
"""
from copy import deepcopy
import numpy as np
from .common import epoch_ns
from .temporal_drift import TEMPORAL_FEATURES, fit_baseline, distance, TemporalState


def enroll(windows, evidence, monitoring_start_epoch, shrinkage=0.1):
    if windows.empty or windows.window_id.duplicated().any():
        raise ValueError('Enrollment must contain unique windows')
    if not windows.identity_status.eq('verified_legitimate').all():
        raise ValueError('Trusted enrollment requires verified legitimate observations')
    if not windows.time_shield_temporal_eligible.eq(True).all():
        raise ValueError('Enrollment contains temporal-invalid windows')
    keys = windows[['pcap', 'candidate_stream_id']].drop_duplicates()
    if len(keys) != 1:
        raise ValueError('Enroll one attributed stream per baseline')
    if not windows.label_provenance.isin(evidence).all():
        raise ValueError('Missing reviewed enrollment provenance')
    devices = set()
    for row in windows.itertuples():
        item = evidence[row.label_provenance]
        if (item.get('review_status') != 'verified_legitimate'
                or not item.get('source_sha256')
                or row.window_id not in item.get('window_ids', [])
                or not item.get('physical_device_id')):
            raise ValueError('Evidence must bind verified device identity to enrollment windows')
        devices.add(item['physical_device_id'])
    if len(devices) != 1:
        raise ValueError('Enrollment mixes physical devices')
    starts = [epoch_ns(x) for x in windows.start_epoch]
    ends = [epoch_ns(x) for x in windows.end_epoch]
    order = sorted(zip(starts, ends))
    if any(left > right for left, right in order) or any(b[0] <= a[1] for a, b in zip(order, order[1:])):
        raise ValueError('Enrollment windows overlap or have reversed time')
    cutoff = epoch_ns(monitoring_start_epoch)
    if max(ends) >= cutoff:
        raise ValueError('Enrollment must strictly precede monitoring')
    baseline = fit_baseline(windows[TEMPORAL_FEATURES].to_numpy(float), shrinkage)
    baseline.update(physical_device_id=next(iter(devices)), enrollment_window_ids=windows.window_id.tolist(),
                    enrollment_end_ns=max(ends), monitoring_start_ns=cutoff,
                    evidence_ids=sorted(set(windows.label_provenance)), updates_allowed=False)
    return baseline


def monitor(windows, baseline, threshold, beta=0.3, K=3, method='mahalanobis'):
    """Call with one externally attributed physical device; never adapt the baseline."""
    frozen = deepcopy(baseline)
    results = []
    for _, group in windows.groupby(['pcap', 'candidate_stream_id'], sort=True):
        state = TemporalState(threshold, beta, K)
        for row in group.sort_values('first_frame').itertuples():
            valid = bool(row.time_shield_temporal_eligible)
            available = baseline is not None
            reason = 'no_verified_baseline' if not available else ''
            if available:
                if getattr(row, 'physical_device_id', None) != baseline['physical_device_id']:
                    available = False; reason = 'unattributed_or_different_device'
                try:
                    if epoch_ns(row.start_epoch) < baseline['monitoring_start_ns']:
                        raise ValueError('Monitoring overlaps enrollment or predates declared cutoff')
                except (ValueError, ArithmeticError):
                    valid = False; reason = 'invalid_monitoring_time'
            values = np.array([getattr(row, field) for field in TEMPORAL_FEATURES], float)
            valid = valid and bool(np.isfinite(values).all())
            d = float(np.asarray(distance(values, baseline, method)).item()) if available and valid else None
            update = state.update(d, valid, available)
            results.append(dict(window_id=row.window_id, distance=d, baseline_available=available,
                                temporal_valid=valid, gating_reason=reason, **update))
    if baseline != frozen:
        raise AssertionError('Baseline mutated during monitoring')
    return results
