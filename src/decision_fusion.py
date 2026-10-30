"""Triage states are decisions, not ground-truth class labels."""
import math


def fuse(score, low, high, temporal_status, baseline_available, quality_valid, temporal_valid=True):
    """quality_valid is ML eligibility; temporal invalidity disables baseline evidence.

    Default retains historical callers. High valid ML evidence can still produce
    suspicion during a gap/reset; temporal evidence can never produce stability then.
    """
    if not 0 <= high <= 1 or (low is not None and not 0 <= low < high):
        raise ValueError('Require 0 <= low < high <= 1; low=None disables stable acceptance')
    if temporal_status not in ('STABLE','DRIFT','UNAVAILABLE'):
        raise ValueError('Unknown temporal status')
    if not quality_valid or score is None or not math.isfinite(score): return 'Pending'
    if not 0 <= score <= 1: raise ValueError('ML score must be in [0,1]')
    if not temporal_valid:
        temporal_status = 'UNAVAILABLE'
    if score >= high: return 'Evil Twin Suspected'
    if baseline_available and temporal_status == 'DRIFT': return 'Suspicious Trusted AP'
    if low is not None and baseline_available and temporal_status == 'STABLE' and score <= low: return 'Consistent with Trusted Baseline'
    return 'Pending'
