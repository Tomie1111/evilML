"""Declared before evaluation; same split and CART search across all eight groups."""
from .preprocessing import FEATURE_GROUPS

ABLATIONS = {
    'configuration_only': ['configuration'],
    'radio_only': ['radio'],
    'frame_only': ['frame'],
    'temporal_only': ['temporal'],
    'configuration_radio': ['configuration', 'radio'],
    'configuration_frame': ['configuration', 'frame'],
    'configuration_radio_frame': ['configuration', 'radio', 'frame'],
    'all': ['configuration', 'radio', 'frame', 'temporal'],
}


def features_for(name):
    return [f for group in ABLATIONS[name] for f in FEATURE_GROUPS[group]]
