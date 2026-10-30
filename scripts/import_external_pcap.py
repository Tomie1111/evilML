#!/usr/bin/env python3
"""Import a supplied PCAP as unlabeled Beacon evidence, with field coverage audit."""
import argparse
import csv
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.common import sha256, write_json
from src.pcap_tools import BASE_FIELDS, EXTRA_FIELDS, find_tool, field_registry, pcap_info, stream_extract


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if args.out.exists(): raise FileExistsError(args.out)
    if not args.pcap.is_file(): raise FileNotFoundError(args.pcap)
    tshark = find_tool('tshark'); capinfos = find_tool('capinfos')
    registry = field_registry(tshark)
    fields = {k: v for k, v in (BASE_FIELDS | EXTRA_FIELDS).items() if k in registry or k == '_ws.malformed'}
    args.out.mkdir(parents=True)
    metadata = pcap_info(capinfos, args.pcap)
    dest = args.out / 'beacons.csv'
    command = stream_extract(tshark, args.pcap, 'wlan.fc.type_subtype == 8', fields,
                             dest, args.out/'tshark.stderr.log')
    present = dict.fromkeys(fields, 0); total = 0
    with dest.open() as handle:
        for row in csv.DictReader(handle):
            total += 1
            for key in fields:
                present[key] += bool(row.get(key, '').strip())
    write_json(args.out/'manifest.json', dict(source=str(args.pcap.resolve()), capture=metadata,
        output_sha256=sha256(dest), command=command, beacon_frames=total,
        missing_dissector_fields=sorted(set(BASE_FIELDS | EXTRA_FIELDS)-set(fields)),
        nonempty_counts=present, field_mapping=fields, labels_assigned=False,
        independence_verified=False, model_inference_performed=False,
        note='Field presence is not semantic validity; window quality and external evidence review are required'))


if __name__ == '__main__': main()
