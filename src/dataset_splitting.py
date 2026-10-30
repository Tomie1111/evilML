"""Global chronological boundaries fixed before modeling; no frame-random split."""
from decimal import Decimal


def boundaries(first_ns, last_ns, train_fraction=0.6, validation_fraction=0.2):
    if not (0 < train_fraction < 1 and 0 < validation_fraction < 1 and train_fraction + validation_fraction < 1):
        raise ValueError('Invalid split fractions')
    duration = last_ns - first_ns
    return (first_ns + int(Decimal(str(train_fraction)) * duration),
            first_ns + int((Decimal(str(train_fraction)) + Decimal(str(validation_fraction))) * duration))


def assign_splits(windows, cutoffs):
    train_end, validation_end = cutoffs
    output = windows.copy()
    def which(row):
        a, b = row['start_ns'], row['end_ns']
        if a <= train_end < b or a <= validation_end < b:
            return 'boundary_excluded'
        if b <= train_end: return 'train'
        if a > train_end and b <= validation_end: return 'validation'
        if a > validation_end: return 'development_test'
        return 'boundary_excluded'
    output['split'] = output.apply(which, axis=1)
    output['eligible'] = output['quality_valid'] & output['target'].notna() & output['split'].ne('boundary_excluded')
    return output


def validate_splits(windows, membership):
    if membership.duplicated(['pcap', 'frame_number']).any():
        raise ValueError('A source frame occurs in multiple windows at this window size')
    if not windows.window_id.is_unique:
        raise ValueError('Duplicate window IDs')
    if set(membership.window_id) != set(windows.window_id):
        raise ValueError('Window membership mismatch')
    counts = membership.groupby('window_id').size()
    if any(counts[row.window_id] != row.n_frames for row in windows.itertuples()):
        raise ValueError('Frame conservation failed')
    for left, right in [('train', 'validation'), ('validation', 'development_test')]:
        a = windows[windows.split.eq(left)]; b = windows[windows.split.eq(right)]
        if not a.empty and not b.empty and not a.end_ns.max() < b.start_ns.min():
            raise ValueError('Non-disjoint chronology')
    support = {}
    for split in ['train', 'validation', 'development_test']:
        group = windows[windows.eligible & windows.split.eq(split)]
        support[split] = {str(i): int(group.target.eq(i).sum()) for i in (0, 1)}
    supported = all(min(v.values()) > 0 for v in support.values())
    return dict(frame_conservation=True, disjoint_membership=True, global_chronology=True,
                support=support, trainable=supported,
                limitation='One previously inspected capture; no independent session or AP generalization')
