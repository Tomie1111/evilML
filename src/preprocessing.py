"""Predictive feature contract, enforced before future model fitting."""

FEATURE_GROUPS = {
    'configuration': ['capabilities_encoded', 'rsn_present', 'rsn_capabilities_encoded',
                      'group_cipher_encoded', 'pairwise_ciphers_encoded', 'akm_suites_encoded',
                      'supported_rates_encoded', 'stable_ie_structure_encoded', 'beacon_interval_tu'],
    'radio': ['rssi_median_dbm', 'rssi_std_dbm', 'channel_frequency_mhz'],
    'frame': ['frame_len_mean', 'frame_len_std', 'sequence_increment_median',
              'sequence_discontinuity_rate', 'retry_fraction'],
    'temporal': ['median_interarrival_ms', 'mad_interarrival_ms', 'tsf_slope_s_per_s',
                 'tsf_nonpositive_fraction'],
}
FORBIDDEN = {
    'ssid', 'ssid_hex', 'bssid', 'source_mac', 'wlan.sa', 'wlan.ta', 'frame_number',
    'original_frame_number', 'frame_time_epoch', 'start_epoch', 'end_epoch', 'tsf', 'ap_tsf',
    'capture_label', 'pcap', 'capture_filename', 'candidate_stream_id', 'identity_status',
    'beacon_role_label', 'attack_related_label', 'attack_label_status', 'split',
}


def validate_feature_names(names):
    allowed = {name for group in FEATURE_GROUPS.values() for name in group}
    bad = set(names) - allowed
    if bad:
        raise ValueError(f'Unapproved or leaking predictive features: {sorted(bad)}')
    if len(names) != len(set(names)):
        raise ValueError('Duplicate predictive features')
    return list(names)
