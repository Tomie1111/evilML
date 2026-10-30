"""Frozen inference on compatible windows; no fitting and no inferred labels."""
import joblib
import numpy as np
from .common import sha256
from .preprocessing import validate_feature_names
from .window_aggregation import CATEGORICAL


def predict_frozen(artifact, expected_sha256, windows):
    # Only load locally trusted artifacts whose hashes came from the frozen selection.
    if sha256(artifact) != expected_sha256:
        raise ValueError('Frozen artifact checksum mismatch')
    bundle = joblib.load(artifact)
    features = validate_feature_names(bundle['features'])
    if list(bundle['pipeline'].feature_names_in_) != features:
        raise ValueError('Frozen preprocessing feature order mismatch')
    missing = set(features) - set(windows)
    if missing: raise ValueError(f'Missing features: {sorted(missing)}')
    if not windows.window_size.eq(bundle['window_size']).all():
        raise ValueError('Window size mismatch')
    x = windows[features]
    numeric = [name for name in features if name not in CATEGORICAL]
    if x.isna().any().any() or not np.isfinite(x[numeric].to_numpy(float)).all():
        raise ValueError('Source features missing or nonfinite')
    scores = bundle['pipeline'].predict_proba(x)[:, 1]
    if sha256(artifact) != expected_sha256:
        raise ValueError('Frozen artifact changed')
    return scores


def verified_metrics(roles, scores, threshold):
    """Undefined positive metrics stay null for legitimate-only observations."""
    roles = np.asarray(roles); scores = np.asarray(scores, dtype=float)
    if (len(roles) != len(scores) or not len(scores) or not np.isfinite(scores).all()
            or np.any((scores < 0) | (scores > 1)) or not 0 <= threshold <= 1):
        raise ValueError('Invalid observations or frozen threshold')
    if not set(roles) <= {'verified_legitimate', 'verified_evil_twin'}:
        raise ValueError('Metrics require reviewed independent labels')
    positive = roles == 'verified_evil_twin'; predicted = scores >= threshold
    tp = int((positive & predicted).sum()); fn = int((positive & ~predicted).sum())
    fp = int((~positive & predicted).sum()); tn = int((~positive & ~predicted).sum())
    return dict(tn=tn, fp=fp, fn=fn, tp=tp, support_evil_twin=tp+fn, support_legitimate=tn+fp,
                attack_recall=tp/(tp+fn) if tp+fn else None,
                attack_precision=tp/(tp+fp) if tp+fn and tp+fp else None,
                attack_f1=2*tp/(2*tp+fp+fn) if tp+fn and 2*tp+fp+fn else None,
                observed_legitimate_alert_fraction=fp/(tn+fp) if tn+fp else None,
                final_fpr=None, unseen_ap_generalization=None)
