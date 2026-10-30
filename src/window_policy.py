"""Separate non-temporal ML quality from continuity needed by Time-Shield."""
import numpy as np
from .feature_extraction import rssi_per_frame, sequence_increment
from .stream_grouping import group_streams
from .window_aggregation import make_windows, interval_flags, CATEGORICAL, config_features
from .preprocessing import FEATURE_GROUPS

STRUCTURAL_REASONS = {
    'incomplete_window', 'mixed_bssid', 'mixed_ssid', 'malformed_frame',
    'truncated_frame', 'configuration_change', 'missing_rsn_field',
    'invalid_interval', 'missing_rssi', 'channel_change', 'feature_parse_error',
    'missing_timestamp',
}
TEMPORAL_REASONS = {
    'arrival_gap', 'tsf_gap', 'incoming_arrival_gap', 'incoming_tsf_gap',
    'arrival_nonpositive', 'tsf_nonpositive',
    'incoming_arrival_nonpositive', 'incoming_tsf_nonpositive',
    'missing_or_invalid_timing', 'incoming_missing_or_invalid_timing',
    'nonfinite_feature', 'feature_parse_error',
}
ML_GROUPS = ('configuration', 'radio', 'frame')
ML_NUMERIC = [f for group in ML_GROUPS for f in FEATURE_GROUPS[group] if f not in CATEGORICAL]


def quality_flags(window):
    reasons = {x for x in str(window['quality_reasons']).split(';') if x}
    structural = reasons & STRUCTURAL_REASONS
    # A generic parse failure may be confined to timing. Use the actual
    # non-temporal feature values to determine ML eligibility independently.
    structural.discard('feature_parse_error')
    if any(not np.isfinite(window[f]) for f in ML_NUMERIC):
        structural.add('missing_non_temporal_feature')
    if window['target'] is None or (isinstance(window['target'], float) and np.isnan(window['target'])):
        structural.add('mixed_or_unknown_identity')
    # Original strict status is the frozen Time-Shield temporal gate.
    temporal = reasons & TEMPORAL_REASONS
    if structural:
        temporal.add('ml_structural_quality')
    return dict(ml_feature_eligible=not structural,
                time_shield_temporal_eligible=not structural and not temporal,
                ml_quality_reasons=';'.join(sorted(structural)),
                temporal_quality_reasons=';'.join(sorted(temporal)))


def recover_non_temporal(window, frames):
    """Keep scientifically usable config/radio/frame values if TSF parsing failed."""
    if 'feature_parse_error' not in window['quality_reasons']:
        return
    try:
        configs = [config_features(r) for r in frames]
        if any(c != configs[0] for c in configs):
            window['quality_reasons'] += ';configuration_change'
        window.update(configs[0])
        signals = [rssi_per_frame(r['radiotap_rssi_dbm']) for r in frames]
        if any(v is None for v in signals): raise ValueError('missing_rssi')
        window['rssi_median_dbm'] = float(np.median(signals))
        window['rssi_std_dbm'] = float(np.std(signals,ddof=1))
        frequency = {int(r['radiotap_channel_freq']) for r in frames}
        if len(frequency) != 1: window['quality_reasons'] += ';channel_change'
        window['channel_frequency_mhz'] = int(frames[0]['radiotap_channel_freq'])
        lengths = [int(r['frame_len']) for r in frames]
        window['frame_len_mean'] = float(np.mean(lengths))
        window['frame_len_std'] = float(np.std(lengths,ddof=1))
        steps = [sequence_increment(a['sequence_number'],b['sequence_number']) for a,b in zip(frames,frames[1:])]
        window['sequence_increment_median'] = float(np.median(steps))
        window['sequence_discontinuity_rate'] = float(np.mean(np.array(steps)!=1))
        if any(r.get('retry') not in ('True','False','0','1') for r in frames):
            window['quality_reasons'] += ';missing_retry'
        window['retry_fraction'] = float(np.mean([r.get('retry') in ('True','1') for r in frames]))
    except (ValueError,KeyError,ArithmeticError):
        window['quality_reasons'] += ';missing_non_temporal_feature'


def evaluate_policy(rows, size, grouping, gap_factor, construction='fixed'):
    if construction not in ('fixed', 'gap_segmented'):
        raise ValueError(construction)
    indexed = {(r['pcap'],int(r['frame_number'])):r for r in rows}
    def finish(subset, members, segment_index):
        grouped = {}
        for member in members:
            grouped.setdefault(member['window_id'],[]).append(indexed[(member['pcap'],int(member['frame_number']))])
        for window in subset:
            recover_non_temporal(window,grouped[window['window_id']])
            window.update(quality_flags(window))
            window['construction'] = construction
            window['segment_index'] = segment_index
    if construction == 'fixed':
        windows, membership = make_windows(rows,size,grouping,gap_factor,True)
        finish(windows,membership,1)
        return windows,membership
    windows=[];membership=[]
    for sid, stream in group_streams(rows,grouping).items():
        segments=[];current=[]
        for row in stream:
            if current and interval_flags(current[-1],row,gap_factor):
                segments.append(current);current=[]
            current.append(row)
        if current:segments.append(current)
        for segment_index, segment in enumerate(segments,1):
            subset, members = make_windows(segment,size,grouping,gap_factor,False)
            mapping={}
            for window in subset:
                old=window['window_id']; new=f'{old}_segment_{segment_index:04d}'
                mapping[old]=new;window['window_id']=new
            for member in members:
                member['window_id']=mapping[member['window_id']]
            finish(subset,members,segment_index)
            windows.extend(subset);membership.extend(members)
    return windows,membership
