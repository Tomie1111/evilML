"""Feature feasibility and diagnostic measurements; no learned preprocessing."""
from collections import defaultdict
from statistics import median
from .common import epoch_ns


def sequence_increment(previous, current):
    a, b = int(previous), int(current)
    if not (0 <= a < 4096 and 0 <= b < 4096):
        raise ValueError('802.11 sequence numbers must lie in [0,4095]')
    return (b - a) % 4096


def rssi_per_frame(value):
    values = [float(v) for v in value.replace(',', ';').split(';') if v]
    return median(values) if values else None


def stable_ie_ids(value):
    # Structure only: no payload bytes, SSID contents, TIM bitmap or network-load values.
    # Remove SSID(0), TIM(5), BSS Load(11), and vendor-specific(221) identity shortcuts.
    return tuple(sorted({int(v) for v in value.split(';') if v and int(v) not in (0, 5, 11, 221)}))


FEATURE_SPECS = [
    ('capabilities_encoded', 'configuration', ['capabilities'], 'wlan.fixed.capabilities', 'Categorical capability word; encoder fit on train only', 'device_configuration_shortcut'),
    ('rsn_present', 'configuration', ['ie_tag_ids'], 'wlan.tag.number', '48 in parsed IE IDs; absent RSN is structural absence, not unknown cipher', 'device_configuration_shortcut'),
    ('rsn_capabilities_encoded', 'configuration', ['rsn_capabilities'], 'wlan.rsn.capabilities', 'Categorical; preserve absent-RSN separately from parse missing', 'device_configuration_shortcut'),
    ('group_cipher_encoded', 'configuration', ['group_cipher'], 'wlan.rsn.gcs.type', 'Categorical suite; absent RSN explicitly represented', 'device_configuration_shortcut'),
    ('pairwise_ciphers_encoded', 'configuration', ['pairwise_ciphers'], 'wlan.rsn.pcs.type', 'Sorted categorical suite set; train-only encoding', 'device_configuration_shortcut'),
    ('akm_suites_encoded', 'configuration', ['akm_suites'], 'wlan.rsn.akms.type', 'Sorted categorical suite set; train-only encoding', 'device_configuration_shortcut'),
    ('supported_rates_encoded', 'configuration', ['supported_rates'], 'wlan.supported_rates;wlan.extended_supported_rates', 'Normalize rates/basic bit and combine optional extended set; train-only encoding', 'device_configuration_shortcut'),
    ('stable_ie_structure_encoded', 'configuration', ['ie_tag_ids'], 'wlan.tag.number', 'Sorted unique IE IDs excluding 0,5,11,221; no dynamic IE contents', 'device_configuration_shortcut'),
    ('beacon_interval_tu', 'configuration', ['beacon_interval_tu'], 'wlan.fixed.beacon', 'Advertised interval in TU; 1 TU=1024 microseconds; use once across groups', 'may_be_constant'),
    ('rssi_median_dbm', 'radio', ['radiotap_rssi_dbm'], 'radiotap.dbm_antsignal', 'Median across antenna values per frame, then across window', 'receiver_location_confound'),
    ('rssi_std_dbm', 'radio', ['radiotap_rssi_dbm'], 'radiotap.dbm_antsignal', 'Sample std across per-frame antenna medians; >=2 frames', 'receiver_location_confound'),
    ('channel_frequency_mhz', 'radio', ['radiotap_channel_freq'], 'radiotap.channel.freq', 'Require consistent frequency within window', 'may_be_constant'),
    ('frame_len_mean', 'frame', ['frame_len'], 'frame.len', 'Window mean captured-link frame length; includes capture encapsulation', 'filter_definition_and_device_shortcut'),
    ('frame_len_std', 'frame', ['frame_len'], 'frame.len', 'Window sample std; distinguish wire length from capture truncation', 'filter_definition_and_device_shortcut'),
    ('sequence_increment_median', 'frame', ['sequence_number'], 'wlan.seq', 'Modulo 4096 adjacent increments within stream; not packet-loss proof', 'management_traffic_and_retry_confound'),
    ('sequence_discontinuity_rate', 'frame', ['sequence_number'], 'wlan.seq', 'Fraction modulo increments !=1; report zero/retry separately', 'management_traffic_and_retry_confound'),
    ('retry_fraction', 'frame', ['retry'], 'wlan.fc.retry', 'Fraction of frames with retry flag', 'may_be_constant'),
    ('median_interarrival_ms', 'temporal', ['frame_time_epoch'], 'frame.time_epoch', 'Integer-nanosecond differences, then median in ms; capture-order windows', 'capture_clock_and_loss_confound'),
    ('mad_interarrival_ms', 'temporal', ['frame_time_epoch'], 'frame.time_epoch', 'Raw MAD of window interarrival ms; no 1.4826 factor', 'capture_clock_and_loss_confound'),
    ('tsf_slope_s_per_s', 'temporal', ['frame_time_epoch', 'tsf'], 'frame.time_epoch;wlan.fixed.timestamp', 'Centered OLS TSF seconds vs receive seconds; never cross TSF reset', 'relative_clock_not_pure_hardware_skew'),
    ('tsf_nonpositive_fraction', 'temporal', ['tsf'], 'wlan.fixed.timestamp', 'Fraction of within-stream TSF deltas <=0; reset windows flagged', 'quality_indicator_not_attack_proof'),
]


def feature_availability(captures, legacy_columns):
    result = []
    for capture, rows in captures.items():
        for name, group, fields, source, method, risk in FEATURE_SPECS:
            missing = sum(any(not r.get(f, '') for f in fields) for r in rows)
            observed = len(rows) - missing
            result.append(dict(capture=capture, feature=name, group=group, source_pcap_field=source,
                extraction_method=method, required_frame_type='Beacon', beacon_records=len(rows),
                source_missing_records=missing, source_missing_rate=missing / len(rows),
                missing_rate_scope='source-frame fields; window-feature missing rate not yet measured',
                available_in_existing_labeled_csv=all(f in legacy_columns for f in fields),
                observed_in_awid3_pcap=observed > 0,
                local_capture_extractability='Supported by extractor if monitor adapter supplies fields; independent capture not provided',
                eligible_after_label_protocol_and_quality_validation=observed > 0,
                eligible_for_training_now=False, risk=risk))
    return result


def stream_quality(rows, gap_factor):
    groups = defaultdict(list)
    for r in rows:
        # Diagnostic grouping by stable BSSID/capabilities, not independent device identity.
        groups[(r['pcap'], r['bssid'], r['capabilities'])].append(r)
    output = []
    for (pcap, bssid, capabilities), g in sorted(groups.items()):
        g.sort(key=lambda r: int(r['frame_number']))
        missing = sum(not r['tsf'] or not r['beacon_interval_tu'] for r in g)
        arrival_bad = tsf_bad = gaps = tsf_gaps = wraps = seq_zero = 0
        for previous, current in zip(g, g[1:]):
            da = epoch_ns(current['frame_time_epoch']) - epoch_ns(previous['frame_time_epoch'])
            arrival_bad += da <= 0
            if previous['tsf'] and current['tsf']:
                dt = int(current['tsf']) - int(previous['tsf'])
                tsf_bad += dt <= 0
                if previous['beacon_interval_tu']:
                    tsf_gaps += dt > gap_factor * int(previous['beacon_interval_tu']) * 1024
            if previous['beacon_interval_tu']:
                gaps += da > gap_factor * int(previous['beacon_interval_tu']) * 1024 * 1000
            if previous['sequence_number'] and current['sequence_number']:
                inc = sequence_increment(previous['sequence_number'], current['sequence_number'])
                seq_zero += inc == 0
                wraps += int(current['sequence_number']) < int(previous['sequence_number'])
        output.append(dict(pcap=pcap, bssid=bssid, capabilities=capabilities, records=len(g),
            first_frame=g[0]['frame_number'], last_frame=g[-1]['frame_number'],
            first_epoch=g[0]['frame_time_epoch'], last_epoch=g[-1]['frame_time_epoch'],
            missing_tsf_or_interval=missing, arrival_nonpositive=arrival_bad, tsf_nonpositive=tsf_bad,
            arrival_gaps=gaps, tsf_gaps=tsf_gaps, sequence_numeric_decreases=wraps,
            sequence_zero_increments=seq_zero,
            note='Numeric decreases may be wrap/reordering/reset; gap counts do not prove packet loss'))
    return output


def temporal_discontinuities(rows):
    """Record exact boundaries within diagnostic BSSID/capability streams."""
    groups = defaultdict(list)
    for r in rows:
        groups[(r['pcap'], r['bssid'], r['capabilities'])].append(r)
    result = []
    for (pcap, bssid, cap), group in sorted(groups.items()):
        group.sort(key=lambda r: int(r['frame_number']))
        for left, right in zip(group, group[1:]):
            da = epoch_ns(right['frame_time_epoch']) - epoch_ns(left['frame_time_epoch'])
            dt = int(right['tsf']) - int(left['tsf']) if left['tsf'] and right['tsf'] else None
            if da <= 0 or (dt is not None and dt <= 0):
                result.append(dict(pcap=pcap, bssid=bssid, capabilities=cap,
                    previous_frame=left['frame_number'], current_frame=right['frame_number'],
                    previous_epoch=left['frame_time_epoch'], current_epoch=right['frame_time_epoch'],
                    previous_tsf_us=left['tsf'], current_tsf_us=right['tsf'],
                    delta_arrival_ns=da, delta_tsf_us=dt,
                    interpretation='Observed discontinuity; not independently verified reboot or attack onset'))
    return result
