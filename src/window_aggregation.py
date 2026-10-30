"""Non-overlapping frame windows with exact time arithmetic and conservative labels."""
import math
from collections import Counter
import numpy as np
from .common import epoch_ns
from .feature_extraction import rssi_per_frame, sequence_increment, stable_ie_ids
from .preprocessing import FEATURE_GROUPS
from .stream_grouping import group_streams

CATEGORICAL = ['capabilities_encoded', 'rsn_capabilities_encoded', 'group_cipher_encoded',
               'pairwise_ciphers_encoded', 'akm_suites_encoded', 'supported_rates_encoded', 'stable_ie_structure_encoded']


def normalized_set(value):
    return ';'.join(str(v) for v in sorted({int(x, 0) for x in value.split(';') if x}))


def config_features(row):
    tags = stable_ie_ids(row['ie_tag_ids'])
    rsn = 48 in tags
    rates = []
    for x in (row.get('supported_rates', '') + ';' + row.get('extended_supported_rates', '')).split(';'):
        if x:
            v = int(x, 0)
            rates.append(f'{(v & 127) / 2:g}:{int(bool(v & 128))}')
    result = dict(capabilities_encoded=hex(int(row['capabilities'], 0)), rsn_present=int(rsn),
        beacon_interval_tu=float(row['beacon_interval_tu']),
        supported_rates_encoded=';'.join(sorted(set(rates))),
        stable_ie_structure_encoded=';'.join(map(str, tags)))
    for name, source in [('rsn_capabilities_encoded', 'rsn_capabilities'), ('group_cipher_encoded', 'group_cipher'),
                         ('pairwise_ciphers_encoded', 'pairwise_ciphers'), ('akm_suites_encoded', 'akm_suites')]:
        result[name] = normalized_set(row.get(source, '')) if rsn else 'ABSENT_RSN'
        if rsn and not result[name]:
            result[name] = 'MISSING_RSN_FIELD'
    return result


def conservative_label(rows):
    statuses = {r.get('identity_status', 'unknown') for r in rows}
    mapping = {'candidate_legitimate': 0, 'candidate_evil_twin': 1,
               'verified_legitimate': 0, 'verified_evil_twin': 1}
    if len(statuses) != 1 or not statuses <= mapping.keys():
        return None, 'mixed_or_unknown', ';'.join(sorted(statuses))
    status = next(iter(statuses))
    evidence = {r.get('identity_evidence_id', '') for r in rows}
    if len(evidence) != 1 or not next(iter(evidence)):
        return None, 'mixed_or_missing_provenance', status
    return mapping[status], next(iter(evidence)), status


def interval_flags(previous, current, gap_factor):
    flags = []
    try:
        da = epoch_ns(current['frame_time_epoch']) - epoch_ns(previous['frame_time_epoch'])
        dt = int(current['tsf']) - int(previous['tsf'])
        interval = int(previous['beacon_interval_tu']) * 1024
        if da <= 0: flags.append('arrival_nonpositive')
        if dt <= 0: flags.append('tsf_nonpositive')
        if interval <= 0: flags.append('invalid_interval')
        if da > gap_factor * interval * 1000: flags.append('arrival_gap')
        if dt > gap_factor * interval: flags.append('tsf_gap')
    except (ValueError, KeyError, ArithmeticError):
        flags.append('missing_or_invalid_timing')
    return flags


def make_windows(rows, size, grouping='bssid_capabilities', gap_factor=1.5, check_incoming=True):
    if size < 2 or not math.isfinite(gap_factor) or gap_factor <= 1:
        raise ValueError('Invalid window/gap configuration')
    windows, membership = [], []
    for sid, stream in group_streams(rows, grouping).items():
        for offset in range(0, len(stream), size):
            g = stream[offset:offset + size]
            wid = f'n{size}_{sid}_{offset // size + 1:05d}'
            reasons = []
            if len(g) != size: reasons.append('incomplete_window')
            if len({r['bssid'] for r in g}) != 1: reasons.append('mixed_bssid')
            if len({r['ssid_hex'] for r in g}) != 1: reasons.append('mixed_ssid')
            if any(r.get('malformed') for r in g): reasons.append('malformed_frame')
            if any(int(r['captured_len']) < int(r['frame_len']) for r in g): reasons.append('truncated_frame')
            internal = [f for a, b in zip(g, g[1:]) for f in interval_flags(a, b, gap_factor)]
            incoming = interval_flags(stream[offset - 1], g[0], gap_factor) if offset and check_incoming else []
            reasons.extend(internal)
            reasons.extend('incoming_' + f for f in incoming)
            target, provenance, status = conservative_label(g)
            values = {f: np.nan for features in FEATURE_GROUPS.values() for f in features}
            for field in CATEGORICAL: values[field] = 'MISSING'
            try:
                profiles = [config_features(r) for r in g]
                if any(p != profiles[0] for p in profiles): reasons.append('configuration_change')
                if any('MISSING_RSN_FIELD' in p.values() for p in profiles): reasons.append('missing_rsn_field')
                values.update(profiles[0])
                if values['beacon_interval_tu'] <= 0: reasons.append('invalid_interval')
                arrival = np.array([epoch_ns(r['frame_time_epoch']) for r in g], dtype=np.int64)
                tsf = np.array([int(r['tsf']) for r in g], dtype=np.int64)
                dt = np.diff(arrival) / 1e6
                if len(dt):
                    values['median_interarrival_ms'] = float(np.median(dt))
                    values['mad_interarrival_ms'] = float(np.median(np.abs(dt - np.median(dt))))
                    values['tsf_nonpositive_fraction'] = float(np.mean(np.diff(tsf) <= 0))
                if len(g) > 1 and np.all(np.diff(arrival) > 0) and np.all(np.diff(tsf) > 0):
                    x = (arrival - arrival[0]) / 1e9; y = (tsf - tsf[0]) / 1e6
                    xc = x - x.mean()
                    values['tsf_slope_s_per_s'] = float(xc @ (y - y.mean()) / (xc @ xc))
                rssi = [rssi_per_frame(r['radiotap_rssi_dbm']) for r in g]
                if any(v is None for v in rssi): reasons.append('missing_rssi')
                else:
                    values['rssi_median_dbm'] = float(np.median(rssi))
                    values['rssi_std_dbm'] = float(np.std(rssi, ddof=1)) if len(g) > 1 else np.nan
                frequencies = {int(r['radiotap_channel_freq']) for r in g}
                if len(frequencies) != 1: reasons.append('channel_change')
                values['channel_frequency_mhz'] = int(g[0]['radiotap_channel_freq'])
                lengths = [int(r['frame_len']) for r in g]
                values['frame_len_mean'] = float(np.mean(lengths))
                values['frame_len_std'] = float(np.std(lengths, ddof=1)) if len(g) > 1 else np.nan
                seq = [sequence_increment(a['sequence_number'], b['sequence_number']) for a, b in zip(g, g[1:])]
                values['sequence_increment_median'] = float(np.median(seq)) if seq else np.nan
                values['sequence_discontinuity_rate'] = float(np.mean(np.array(seq) != 1)) if seq else np.nan
                if any(r.get('retry') not in ('True', 'False', '0', '1') for r in g): reasons.append('missing_retry')
                values['retry_fraction'] = float(np.mean([r.get('retry') in ('True', '1') for r in g]))
                if any(not np.isfinite(v) for k, v in values.items() if k not in CATEGORICAL):
                    reasons.append('nonfinite_feature')
            except (ValueError, KeyError, ArithmeticError):
                reasons.append('feature_parse_error')
            start, end = g[0]['frame_time_epoch'], g[-1]['frame_time_epoch']
            try:
                start_ns, end_ns = epoch_ns(start), epoch_ns(end)
            except (ValueError, ArithmeticError):
                start_ns = end_ns = None; reasons.append('missing_timestamp')
            windows.append(dict(window_id=wid, window_size=size, pcap=g[0]['pcap'], candidate_stream_id=sid,
                bssid=g[0]['bssid'], observed_capabilities=g[0]['capabilities'],
                first_frame=int(g[0]['frame_number']), last_frame=int(g[-1]['frame_number']),
                start_epoch=start, end_epoch=end, start_ns=start_ns, end_ns=end_ns,
                duration_s=(end_ns - start_ns) / 1e9 if start_ns is not None else np.nan,
                n_frames=len(g), n_intervals=max(0, len(g) - 1),
                quality_valid=not reasons, quality_reasons=';'.join(sorted(set(reasons))),
                target=target, identity_status=status, label_provenance=provenance,
                **values))
            membership.extend(dict(window_id=wid, pcap=r['pcap'], frame_number=int(r['frame_number'])) for r in g)
    return windows, membership
