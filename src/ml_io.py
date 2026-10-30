"""Stable CSV feature types and binary-float round trips across pandas versions."""
import pandas as pd
from .preprocessing import FEATURE_GROUPS
from .window_aggregation import CATEGORICAL


def load_windows(path):
    numeric = {f for group in FEATURE_GROUPS.values() for f in group} - set(CATEGORICAL)
    return pd.read_csv(path, dtype={**{f: str for f in CATEGORICAL}, 'start_epoch': str, 'end_epoch': str},
                       converters={f: lambda x: float(x) if x else float('nan') for f in numeric})
