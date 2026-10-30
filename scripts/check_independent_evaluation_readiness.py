#!/usr/bin/env python3
"""Validate independent capture intake and frozen artifacts; never score models."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common import sha256, write_json
from src.independent_evaluation import readiness


def safe_relative(project, value):
    path = PurePosixPath(str(value).replace('\\', '/'))
    if path.is_absolute() or '..' in path.parts:
        raise ValueError(f'Unsafe registry manifest path: {value}')
    return project.joinpath(*path.parts)


def main():
    project = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol', type=Path, default=project/'configs/independent_evaluation_protocol.json')
    parser.add_argument('--out', type=Path, default=project/'results/independent_evaluation_readiness.json')
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(args.out)
    protocol = json.loads(args.protocol.read_text())
    registry_path = project / protocol['registry']
    registry = json.loads(registry_path.read_text())
    sessions = []
    for value in registry.get('sessions', []):
        manifest_path = safe_relative(project, value)
        sessions.append(json.loads(manifest_path.read_text()))

    selection_path = project / protocol['frozen_selection_manifest']
    if sha256(selection_path) != protocol['frozen_selection_manifest_sha256']:
        raise ValueError('Frozen selection manifest hash changed')
    selection = json.loads(selection_path.read_text())
    artifact_errors = []
    for identifier, metadata in selection['selected'].items():
        artifact = project / metadata['artifact']
        if not artifact.is_file() or sha256(artifact) != metadata['artifact_sha256']:
            artifact_errors.append(identifier)

    report = readiness(registry, sessions, project, protocol)
    report.update({
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'protocol_id': protocol['id'],
        'protocol_sha256': sha256(args.protocol),
        'registry': protocol['registry'],
        'registry_sha256': sha256(registry_path),
        'frozen_selection_manifest': protocol['frozen_selection_manifest'],
        'frozen_selection_manifest_sha256': sha256(selection_path),
        'frozen_artifact_count': len(selection['selected']),
        'frozen_artifact_errors': artifact_errors,
        'models_loaded_or_scored': False,
    })
    if artifact_errors:
        report['status'] = 'blocked_frozen_artifact_integrity_failure'
        report['scoring_authorized_by_data_gate'] = False
    write_json(args.out, report)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
