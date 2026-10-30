#!/usr/bin/env python3
"""Select every model on validation before opening any development-test scores."""
import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

for name in ['OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'VECLIB_MAXIMUM_THREADS']:
    os.environ.setdefault(name, '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import joblib
import numpy as np
import pandas as pd
import sklearn
from src.common import sha256, write_json
from src.feature_ablation import ABLATIONS, features_for
from src.train_models import select_model, explanation
from src.evaluate_models import evaluate, prediction_table
from src.ml_io import load_windows


def main():
    project = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=project / 'configs/ml_experiment.yaml')
    p.add_argument('--project-root', type=Path, default=project)
    args = p.parse_args(); project = args.project_root.resolve()
    cfg = json.loads(args.config.read_text())
    splits = json.loads((project / 'data/splits/split_manifest.json').read_text())
    if splits['config_sha256'] != sha256(args.config): raise ValueError('Config changed after split freeze')
    acceptance = json.loads((args.config.parent / cfg['acceptance']).read_text())
    if acceptance != splits['acceptance']: raise ValueError('Acceptance changed after split freeze')
    for name, digest in splits['outputs_sha256'].items():
        if sha256(project / name) != digest: raise ValueError(f'Prepared input changed: {name}')
    selection_path = project / 'models/selection_manifest.json'
    if selection_path.exists() or any((project / 'models').glob('*.joblib')):
        raise FileExistsError('Models already exist; create a separate run')
    for name in ['model_comparison.csv', 'feature_ablation.csv', 'classification_reports.json']:
        if (project / 'results/metrics' / name).exists(): raise FileExistsError(name)
    tables = {n: load_windows(project / f'data/processed/window_features_{n}.csv') for n in cfg['window_sizes']}
    jobs = []
    skipped = []
    for size in cfg['window_sizes']:
        if not splits['window_sets'][str(size)]['trainable']:
            skipped.append(dict(window_size=size, reason='one_or_more_splits_lack_both_eligible_classes', support=splits['window_sets'][str(size)]['support']))
            continue
        for model in cfg['hyperparameters']:
            jobs.append((size, model, 'all'))
    for ablation in ABLATIONS:
        if ablation != 'all' and splits['window_sets'][str(cfg['primary_window_size'])]['trainable']:
            jobs.append((cfg['primary_window_size'], cfg['ablation_model'], ablation))
    selected = {}; searches = []
    for size, model, ablation in jobs:
        identifier = f'n{size}_{model}_{ablation}'
        w = tables[size]; train = w[w.eligible & w.split.eq('train')]; validation = w[w.eligible & w.split.eq('validation')]
        features = features_for(ablation)
        print('Select on validation:', identifier, flush=True)
        best = select_model(train, validation, features, model, cfg['hyperparameters'][model], cfg['random_seed'], cfg['model_selection']['classification_threshold'])
        bundle = dict(pipeline=best['pipeline'], features=features, model=model, ablation=ablation,
            window_size=size, parameters=best['params'], config_sha256=sha256(args.config),
            label_protocol=acceptance, label_scope='accepted_candidate_dataset_roles',
            training_window_ids=train.window_id.tolist(), validation_window_ids=validation.window_id.tolist())
        artifact = project / 'models' / f'{identifier}.joblib'
        joblib.dump(bundle, artifact, compress=3)
        reloaded = joblib.load(artifact)
        original_scores = best['pipeline'].predict_proba(validation[features])
        restored_scores = reloaded['pipeline'].predict_proba(validation[features])
        # Parallel forest reductions may differ at the final floating-point bits.
        if not np.allclose(original_scores, restored_scores, rtol=1e-12, atol=1e-12) or not np.array_equal(
                original_scores[:, 1] >= cfg['model_selection']['classification_threshold'],
                restored_scores[:, 1] >= cfg['model_selection']['classification_threshold']):
            raise ValueError('Saved/reloaded predictions differ beyond numerical tolerance or change decisions')
        selected[identifier] = dict(window_size=size, model=model, ablation=ablation, features=features,
            parameters=best['params'], candidate_index=best['candidate_index'], fit_seconds=best['fit_seconds'],
            validation_metrics=best['validation_metrics'], warnings=best['warnings'],
            train_only_constant_features=best['train_only_constant_features'],
            artifact=str(artifact.relative_to(project)), artifact_sha256=sha256(artifact),
            model_size_bytes=artifact.stat().st_size, explanation=explanation(best['pipeline']))
        selected[identifier]['serialization_max_abs_score_difference'] = float(np.max(np.abs(original_scores - restored_scores)))
        for record in best['search_log']:
            searches.append(dict(experiment_id=identifier, **record))
    # All hyperparameters/feature groups/artifacts are now frozen, before test evaluation.
    selection = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(), selected=selected, skipped=skipped,
        selection_data='train fit, validation selection only', split_manifest_sha256=sha256(project / 'data/splits/split_manifest.json'),
        config_sha256=sha256(args.config), primary_model=cfg['primary_model'], primary_window_size=cfg['primary_window_size'])
    write_json(selection_path, selection)
    write_json(project / 'results/metrics/validation_search.json', searches)
    comparisons = []; ablations = []; reports = {}
    for identifier, meta in selected.items():
        w = tables[meta['window_size']]; test = w[w.eligible & w.split.eq('development_test')]
        bundle = joblib.load(project / meta['artifact']); features = bundle['features']
        score = bundle['pipeline'].predict_proba(test[features])[:, 1]
        metrics, report = evaluate(test.target, score, cfg['model_selection']['classification_threshold'])
        full_test = w[w.split.eq('development_test') & w.target.notna()]
        all_positive = int(full_test.target.eq(1).sum())
        coverage = dict(candidate_test_windows=len(full_test), eligible_test_windows=len(test),
            quality_pending_windows=int((~full_test.quality_valid).sum()),
            total_candidate_evil_windows=all_positive,
            eligible_evil_fraction=float(test.target.eq(1).sum() / all_positive) if all_positive else None,
            end_to_end_candidate_evil_alert_recall=float(metrics['tp'] / all_positive) if all_positive else None,
            end_to_end_definition='Invalid windows remain pending, included in candidate attack denominator; no imputation')
        record = dict(experiment_id=identifier, model=meta['model'], window_size=meta['window_size'],
            ablation=meta['ablation'], evaluation_split='development_test', feature_count=len(features),
            encoded_feature_count=len(meta['explanation']['transformed_features']),
            model_size_bytes=meta['model_size_bytes'], selected_fit_seconds=meta['fit_seconds'],
            tree_depth=meta['explanation']['tree_depth'], leaf_count=meta['explanation']['leaf_count'], **coverage, **metrics)
        if meta['ablation'] == 'all': comparisons.append(record)
        if meta['window_size'] == cfg['primary_window_size'] and meta['model'] == cfg['ablation_model']:
            ablations.append(record)
        reports[identifier] = dict(development_test=report, validation=meta['validation_metrics'],
            target_provenance='author-documented candidate roles, user accepted protocol',
            independent_test=False, class_counts=selection['selected'][identifier]['validation_metrics'])
        prediction_table(test, score, cfg['model_selection']['classification_threshold']).to_csv(
            project / 'results/predictions' / f'{identifier}.csv', index=False, float_format='%.17g')
        print('Evaluated frozen model:', identifier, 'F1=', metrics['f1'], flush=True)
    pd.DataFrame(comparisons).to_csv(project / 'results/metrics/model_comparison.csv', index=False)
    pd.DataFrame(ablations).to_csv(project / 'results/metrics/feature_ablation.csv', index=False)
    write_json(project / 'results/metrics/classification_reports.json', reports)
    write_json(project / 'results/ml_validation.json', dict(
        passed=bool(selected), config_matches_prepared_windows=True, all_split_checks=splits['window_sets'],
        all_selections_frozen_before_test_scores=True, preprocessing_fit_train_only=True,
        all_saved_models_reloaded_with_identical_validation_decisions=True,
        serialization_probability_tolerance=1e-12,
        selection_manifest_sha256=sha256(selection_path), skipped_experiments=skipped,
        label_protocol_accepted=True, independent_generalization_validated=False,
        python=platform.python_version(), numpy=np.__version__, pandas=pd.__version__, sklearn=sklearn.__version__))
    write_json(project / 'results/ml_manifest.json', dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
        config=cfg, config_sha256=sha256(args.config), selection_manifest_sha256=sha256(selection_path),
        split_manifest_sha256=sha256(project / 'data/splits/split_manifest.json'), acceptance=acceptance,
        code_sha256={str(f.relative_to(project)): sha256(f) for folder in ['src', 'scripts'] for f in sorted((project / folder).glob('*.py'))},
        versions=dict(python=platform.python_version(), numpy=np.__version__, pandas=pd.__version__, sklearn=sklearn.__version__),
        no_synthetic_experiment_records=True, model_count=len(selected), label_scope='preliminary_author_documented_roles'))


if __name__ == '__main__':
    main()
