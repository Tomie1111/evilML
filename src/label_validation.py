"""Keep attack-filter annotation and transmitter identity evidence separate."""
from collections import Counter
from .common import epoch_ns, frame_key, unique_index

IDENTITY_STATUSES = (
    'verified_legitimate', 'verified_evil_twin',
    'candidate_legitimate', 'candidate_evil_twin', 'unknown',
)


def identity_status(row, policy):
    for mapping in policy['mappings']:
        if (frame_key(row)[0] == mapping['pcap']
                and row['bssid'].lower() == mapping['bssid'].lower()):
            if not mapping.get('evidence_id'):
                raise ValueError('A mapping must have documented evidence')
            if mapping['status'] not in ('candidate_legitimate', 'candidate_evil_twin'):
                raise ValueError('A MAC mapping cannot independently verify device identity')
            if row['beacon_role_label'] != mapping['legacy_role']:
                return 'unknown', 'legacy_role_conflict'
            return mapping['status'], mapping['evidence_id']
    return 'unknown', 'no_capture_specific_identity_evidence'


def audit_label_join(beacons, attacks):
    """Fail on duplicate keys; compare exact original-frame annotation and metadata."""
    unique_index(beacons)
    lookup = unique_index(attacks)
    results = []
    for row in beacons:
        key = frame_key(row)
        label = lookup.get(key)
        expected = label['attack_related_label'] if label else 'unknown'
        expected_status = 'matched_filter_label' if label else 'not_selected_by_filter'
        bad = []
        if row['attack_related_label'] != expected:
            bad.append('attack_related_label')
        if row['attack_label_status'] != expected_status:
            bad.append('attack_label_status')
        if label:
            for col, other in [('frame_time_epoch', 'frame_time_epoch'), ('frame_len', 'frame_len'),
                               ('bssid', 'wlan_bssid'), ('capabilities', 'wlan_capabilities')]:
                a, b = row[col], label[other]
                if col == 'frame_time_epoch':
                    same = epoch_ns(a) == epoch_ns(b)
                elif col == 'frame_len':
                    same = int(a) == int(b)
                else:
                    same = a.lower() == b.lower()
                if not same:
                    bad.append(col)
            if int(label['wlan_fc_type_subtype'], 0) != 8:
                bad.append('non_beacon_attack_join')
        results.append(dict(pcap=key[0], frame_number=key[1],
                            label_row_present=label is not None,
                            agrees=not bad, mismatched_fields=';'.join(bad)))
    return results


def training_gate(validated_rows, integrity_ok):
    counts = Counter(r['identity_status'] for r in validated_rows)
    verified_classes = all(counts[s] for s in ('verified_legitimate', 'verified_evil_twin'))
    return {
        'supervised_training_allowed': bool(integrity_ok and verified_classes),
        'integrity_checks_passed': integrity_ok,
        'identity_counts': {s: counts[s] for s in IDENTITY_STATUSES},
        'author_documented_candidate_roles_exist': bool(counts['candidate_legitimate'] and counts['candidate_evil_twin']),
        'blockers': ([] if integrity_ok else ['Resolve input/PCAP consistency failures']) +
                    ([] if verified_classes else ['Approve the proposed author-documented dataset-role protocol, or supply independent device/session evidence']),
        'independent_unseen_ap_evaluation_supported': False,
        'normal_class_fpr_on_independently_verified_identity_supported': verified_classes,
        'note': 'Candidate roles are not automatically promoted. This audit does not train any classifier.'
    }
