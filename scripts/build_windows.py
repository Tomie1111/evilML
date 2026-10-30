#!/usr/bin/env python3
"""Prepare accepted-role windows and frozen chronological split memberships."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pandas as pd
from src.common import epoch_ns, read_csv, unique_index, sha256, write_json
from src.pcap_tools import BASE_FIELDS, EXTRA_FIELDS
from src.window_aggregation import make_windows
from src.dataset_splitting import assign_splits, boundaries, validate_splits


def main():
    project = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=project / 'configs/ml_experiment.yaml')
    p.add_argument('--project-root', type=Path, default=project)
    args = p.parse_args(); project = args.project_root.resolve()
    cfg = json.loads(args.config.read_text())
    acceptance_path = args.config.parent / cfg['acceptance']
    acceptance = json.loads(acceptance_path.read_text())
    if acceptance['status'] != 'accepted_for_preliminary_dataset_role_training':
        raise ValueError('Missing protocol acceptance')
    if sha256(project / 'labeling_protocol_accepted.md') != acceptance['accepted_protocol_sha256']:
        raise ValueError('Accepted protocol has changed')
    audit = json.loads((project / 'results/audit/dataset_audit.json').read_text())
    if not audit['training_gate']['integrity_checks_passed']:
        raise ValueError('Canonical integrity audit must pass')
    if sha256(project / cfg['audited_identities']) != sha256(project / 'results/audit/identity_label_audit.csv'):
        raise ValueError('Use the audited identity table')
    extraction = json.loads((project / 'data/raw/audit/extraction_manifest.json').read_text())
    expected = next(x['output_sha256'] for x in extraction['extractions'] if x['scenario'] == 'Evil_Twin' and x['kind'] == 'beacons')
    if sha256(project / cfg['source_beacons']) != expected:
        raise ValueError('Beacon extraction fingerprint changed')
    columns = BASE_FIELDS | EXTRA_FIELDS
    rows = [dict(pcap=cfg['canonical_pcap'], **{columns[k]: v for k, v in r.items()}) for r in read_csv(project / cfg['source_beacons'])]
    unique_index(rows)
    labels = unique_index(read_csv(project / cfg['audited_identities']))
    for r in rows:
        lab = labels[(r['pcap'], int(r['frame_number']))]
        r.update(identity_status=lab['identity_status'], identity_evidence_id=lab['identity_evidence_id'])
    first, last = min(epoch_ns(r['frame_time_epoch']) for r in rows), max(epoch_ns(r['frame_time_epoch']) for r in rows)
    cutoff = boundaries(first, last, cfg['split']['train_fraction'], cfg['split']['validation_fraction'])
    paths = [project / f'data/processed/window_features_{n}.csv' for n in cfg['window_sizes']]
    paths += [project / f'data/splits/membership_{n}.csv' for n in cfg['window_sizes']]
    paths += [project / 'results/audit/window_quality_report.csv', project / 'data/splits/split_manifest.json']
    if any(f.exists() for f in paths):
        raise FileExistsError('Window outputs already exist; use a new project/run directory')
    summaries = []; split_checks = {}; output_hashes = {}
    for size in cfg['window_sizes']:
        records, membership = make_windows(rows, size, cfg['grouping'], cfg['quality']['gap_factor'], cfg['quality']['check_incoming_boundary'])
        w = assign_splits(pd.DataFrame(records), cutoff); m = pd.DataFrame(membership)
        checks = validate_splits(w, m)
        if len(m) != len(rows): raise ValueError('Frame conservation across candidate streams failed')
        split_checks[str(size)] = checks
        file = project / f'data/processed/window_features_{size}.csv'
        w.to_csv(file, index=False, float_format='%.17g')
        output_hashes[str(file.relative_to(project))] = sha256(file)
        file = project / f'data/splits/membership_{size}.csv'
        m.to_csv(file, index=False); output_hashes[str(file.relative_to(project))] = sha256(file)
        for (split, status), g in w.groupby(['split', 'identity_status']):
            summaries.append(dict(window_size=size, split=split, identity_status=status,
                candidate_windows=len(g), quality_valid=int(g.quality_valid.sum()), eligible=int(g.eligible.sum()),
                quality_invalid=int((~g.quality_valid).sum()), frames=int(g.n_frames.sum())))
        print(size, checks, flush=True)
    pd.DataFrame(summaries).to_csv(project / 'results/audit/window_quality_report.csv', index=False)
    manifest = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(), config=cfg,
        config_sha256=sha256(args.config), acceptance=acceptance, acceptance_sha256=sha256(acceptance_path),
        source_beacons_sha256=sha256(project / cfg['source_beacons']),
        identity_table_sha256=sha256(project / cfg['audited_identities']),
        capture_first_ns=first, capture_last_ns=last, train_end_ns=cutoff[0], validation_end_ns=cutoff[1],
        boundary_source='0.6/0.8 of full capture time, fixed before modeling, independent of class or model scores',
        window_sets=split_checks, outputs_sha256=output_hashes,
        code_sha256={f.name: sha256(f) for f in sorted((project / 'src').glob('*.py'))},
        verified_device_identity=False, author_documented_role_protocol_accepted=True)
    write_json(project / 'data/splits/split_manifest.json', manifest)


if __name__ == '__main__':
    main()
