"""Candidate grouping is observation structure, never physical identity proof."""
import hashlib
from collections import defaultdict
from .feature_extraction import stable_ie_ids


def candidate_key(row, method='bssid_capabilities'):
    key = (row['pcap'], row['bssid'].lower())
    if method == 'bssid':
        return key
    if method == 'bssid_capabilities':
        return key + (row['capabilities'].lower(),)
    if method == 'stable_profile':
        return key + (row['capabilities'].lower(), row['rsn_version'], stable_ie_ids(row['ie_tag_ids']))
    raise ValueError(f'Unsupported grouping: {method}')


def group_streams(rows, method='bssid_capabilities'):
    groups = defaultdict(list)
    for row in rows:
        groups[candidate_key(row, method)].append(row)
    result = {}
    for key, records in sorted(groups.items()):
        sid = hashlib.sha256(repr(key).encode()).hexdigest()[:16]
        result[sid] = sorted(records, key=lambda r: int(r['frame_number']))
    return result
