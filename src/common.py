"""Small standard-library utilities; no whole-PCAP reads."""
import csv
import hashlib
import json
from decimal import Decimal
from pathlib import Path, PurePosixPath


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields=None):
    rows = iter(rows)
    first = next(rows, None)
    if fields is None:
        if first is None:
            raise ValueError('Empty output requires explicit columns')
        fields = list(first)
    with Path(path).open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        if first is not None:
            writer.writerow(first)
        writer.writerows(rows)


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False) + '\n')


def epoch_ns(value):
    n = Decimal(value) * 1_000_000_000
    if not n.is_finite() or n != n.to_integral_value():
        raise ValueError('Timestamp is not finite integer nanoseconds')
    return int(n)


def frame_key(row):
    # No basename-only fallback: identical filenames in different sessions remain distinct.
    capture = str(PurePosixPath(row['pcap'].replace('\\', '/')))
    if not capture or capture == '.' or '..' in PurePosixPath(capture).parts:
        raise ValueError('Invalid capture identity')
    number = int(row['frame_number'])
    if number < 1:
        raise ValueError('Original frame number must be positive')
    return capture, number


def unique_index(rows):
    result = {}
    for row in rows:
        key = frame_key(row)
        if key in result:
            raise ValueError(f'Duplicate capture/frame key: {key}')
        result[key] = row
    return result


def load_config(path, dataset_root=None):
    path = Path(path).resolve()
    # JSON syntax is a strict YAML subset; audit needs no third-party YAML parser.
    config = json.loads(path.read_text())
    root = Path(dataset_root).resolve() if dataset_root else (path.parent / config['dataset_root']).resolve()
    return config, root
