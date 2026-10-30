#!/usr/bin/env python3
"""Run unit checks and repeat reports from saved PCAP evidence."""
import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.common import load_config, sha256, write_json
from src.dataset_audit import run


def main():
    project = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=project / 'configs/experiment.yaml')
    p.add_argument('--dataset-root', type=Path)
    p.add_argument('--audit', type=Path, default=project / 'results/audit')
    p.add_argument('--extractions', type=Path, default=project / 'data/raw/audit')
    p.add_argument('--out', type=Path, default=project / 'results/verification.json')
    args = p.parse_args()
    if args.out.exists():
        p.error('Verification output exists; use a new --out')
    _, root = load_config(args.config, args.dataset_root)
    log = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(project / 'tests'))
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    print(log.getvalue())
    if not result.wasSuccessful():
        raise RuntimeError('Unit tests failed')
    audit = json.loads((args.audit / 'dataset_audit.json').read_text())
    for name, digest in audit['inputs'].items():
        if sha256(root / name) != digest:
            raise ValueError(f'Input changed: {name}')
    files = sorted(f for f in args.audit.iterdir() if f.is_file())
    before = {f.name: sha256(f) for f in files}
    with tempfile.TemporaryDirectory(prefix='evil_twin_audit_verify_') as temp:
        out = Path(temp) / 'audit'
        with contextlib.redirect_stdout(io.StringIO()):
            run(args.config, args.dataset_root, args.extractions, out)
        repeated = json.loads((out / 'dataset_audit.json').read_text())
        original = dict(audit)
        original.pop('timestamp_utc'); repeated.pop('timestamp_utc')
        if original != repeated:
            raise ValueError('Audit manifest repeat differs beyond runtime timestamp')
        same_bytes = []
        for source in files:
            if source.name == 'dataset_audit.json':
                continue
            if source.read_bytes() != (out / source.name).read_bytes():
                raise ValueError(f'Non-deterministic output: {source.name}')
            same_bytes.append(source.name)
    try:
        run(args.config, args.dataset_root, args.extractions, args.audit)
    except FileExistsError:
        overwrite_refused = True
    else:
        raise AssertionError('Existing audit outputs were not protected')
    if before != {f.name: sha256(f) for f in files}:
        raise ValueError('Verification changed original audit outputs')
    old = root / 'evilML/time_shield'
    reference = root / 'evilML/awid3_attack_audit_complete/time_shield'
    legacy_matches = None
    if old.is_dir() and reference.is_dir():
        refs = [f for f in reference.rglob('*') if f.is_file()]
        legacy_matches = all((old / f.relative_to(reference)).is_file()
                             and sha256(f) == sha256(old / f.relative_to(reference)) for f in refs)
        if not legacy_matches:
            raise ValueError('Original Time-Shield differs from packaged reference')
    report = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
        unit_tests_run=result.testsRun, unit_failures=len(result.failures), unit_errors=len(result.errors),
        report_repeat_byte_identical_files=same_bytes,
        manifest_repeat_equal_except_runtime_timestamp=True,
        original_audit_hashes_unchanged=True, audited_input_hashes_unchanged=True,
        original_time_shield_matches_packaged_reference=legacy_matches,
        existing_output_overwrite_refused=overwrite_refused,
        canonical_pcap_integrity=audit['training_gate']['integrity_checks_passed'],
        supervised_training_allowed=audit['training_gate']['supervised_training_allowed'],
        verification_scope='Unit tests and repeat audit from hash-checked saved TShark exports; not a second full PCAP scan',
        code_hashes={str(f.relative_to(project)): sha256(f)
                     for folder in ['src', 'tests', 'scripts'] for f in sorted((project / folder).glob('*.py'))})
    write_json(args.out, report)
    args.out.with_suffix('.log').write_text(log.getvalue())
    print(f'PASS: {result.testsRun} tests; {len(same_bytes)} byte-identical outputs; manifest matches except timestamp')


if __name__ == '__main__':
    main()
