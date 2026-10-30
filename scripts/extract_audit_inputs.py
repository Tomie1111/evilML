#!/usr/bin/env python3
"""Extract reproducible audit evidence without modifying source files."""
import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.common import load_config, sha256, write_json
from src.pcap_tools import (BASE_FIELDS, EXTRA_FIELDS, field_registry, find_tool,
                            pcap_info, read_official_filter, stream_extract)


def main():
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=project / 'configs/experiment.yaml')
    parser.add_argument('--dataset-root', type=Path)
    parser.add_argument('--out', type=Path, default=project / 'data/raw/audit')
    args = parser.parse_args()
    config, root = load_config(args.config, args.dataset_root)
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error('Output already contains files; use a new --out directory')
    out.mkdir(parents=True, exist_ok=True)
    tshark = find_tool('tshark', config['tshark'])
    capinfos = find_tool('capinfos', config['capinfos'])
    registry = field_registry(tshark)
    # _ws.malformed is a protocol, so it is intentionally not in the field registry.
    fields = {k: v for k, v in (BASE_FIELDS | EXTRA_FIELDS).items() if k in registry or k == '_ws.malformed'}
    missing_required = set(BASE_FIELDS) - set(fields)
    if missing_required:
        raise ValueError(f'Missing required dissector fields: {missing_required}')
    write_json(out / 'field_registry.json', {k: registry.get(k, 'protocol') for k in fields})
    metadata = []
    capture_paths = sorted(p for p in (root / config['pcap_directory']).iterdir() if p.suffix in ('.pcap', '.pcapng'))
    for p in capture_paths:
        print(f'Inventory + SHA256: {p.name}', flush=True)
        metadata.append(dict(pcap=p.relative_to(root).as_posix(), **pcap_info(capinfos, p)))
    write_json(out / 'capture_metadata.json', metadata)
    commands = []
    for capture in config['captures']:
        name = capture['scenario']
        source = root / capture['pcap']
        for kind, expression, selected in [
            ('beacons', 'wlan.fc.type_subtype == 8', fields),
            ('official_filter', read_official_filter(root / config['readme'], name),
             {k: BASE_FIELDS[k] for k in ['frame.number', 'frame.time_epoch', 'frame.len',
               'wlan.fc.type_subtype', 'wlan.bssid', 'wlan.fixed.capabilities']}),
        ]:
            print(f'Extract {name}: {kind}', flush=True)
            output = out / f'{name}_{kind}.csv'
            cmd = stream_extract(tshark, source, expression, selected, output, out / f'{name}_{kind}.stderr.log')
            commands.append(dict(scenario=name, kind=kind, pcap=capture['pcap'], filter=expression,
                                 fields=selected, argv=cmd, output=output.name, output_sha256=sha256(output)))
    manifest = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                    config_sha256=sha256(args.config),
                    tshark_version=subprocess.run([tshark, '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0],
                    script_sha256=sha256(__file__), source_readme_sha256=sha256(root / config['readme']),
                    captures=metadata, extractions=commands,
                    missing_optional_fields=sorted(set(EXTRA_FIELDS) - set(fields)),
                    decryption='disabled explicitly; source captures already supplied by dataset',
                    input_pcaps_modified=False)
    write_json(out / 'extraction_manifest.json', manifest)
    print('Extraction finished: ' + str(out), flush=True)


if __name__ == '__main__':
    main()
