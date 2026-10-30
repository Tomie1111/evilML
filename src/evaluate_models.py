"""Metrics against accepted dataset roles; physical identity FPR stays unreported."""
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score


def evaluate(y, score, threshold=0.5):
    y = np.asarray(y, dtype=int); score = np.asarray(score, dtype=float)
    if len(y) == 0 or not np.isfinite(score).all():
        raise ValueError('Empty labels or nonfinite scores')
    prediction = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    metrics = dict(precision=float(precision_score(y, prediction, zero_division=0)),
        recall=float(recall_score(y, prediction, zero_division=0)),
        f1=float(f1_score(y, prediction, zero_division=0)),
        tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
        support_legitimate=int((y == 0).sum()), support_evil_twin=int((y == 1).sum()),
        independently_verified_fpr=None,
        candidate_legitimate_alert_fraction=float(fp / (tn + fp)) if tn + fp else None,
        label_scope='accepted author-documented candidate dataset roles', positive_class='Evil Twin (1)',
        decision_threshold=threshold)
    report = classification_report(y, prediction, labels=[0, 1], target_names=['candidate_legitimate', 'candidate_evil_twin'], output_dict=True, zero_division=0)
    return metrics, report


def prediction_table(windows, score, threshold):
    columns = ['window_id', 'window_size', 'pcap', 'candidate_stream_id', 'bssid', 'observed_capabilities',
               'first_frame', 'last_frame', 'start_epoch', 'end_epoch', 'duration_s', 'target',
               'identity_status', 'label_provenance', 'quality_valid', 'split']
    output = windows[columns].copy()
    output['evil_twin_score'] = score
    output['predicted_role'] = (np.asarray(score) >= threshold).astype(int)
    return output
