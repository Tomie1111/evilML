#!/usr/bin/env python3
"""Benchmark the frozen primary non-temporal models without changing scores."""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd

from src.common import sha256


def main():
    project = Path(__file__).resolve().parents[1]
    selection_path = project / 'models/preliminary_non_temporal_v1/selection_manifest.json'
    selection = json.loads(selection_path.read_text())
    output = project / 'results/preliminary_non_temporal_v1/resource_measurements'
    summary_path = project / 'results/preliminary_non_temporal_v1/resource_benchmarks.csv'
    if output.exists() or summary_path.exists():
        raise FileExistsError('Non-temporal benchmark output already exists')
    output.mkdir()
    environment = dict(os.environ, OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1',
                       VECLIB_MAXIMUM_THREADS='1')
    summaries = []
    for identifier, meta in selection['selected'].items():
        if meta['ablation'] != 'configuration_radio_frame':
            continue
        model = project / meta['artifact']
        if sha256(model) != meta['artifact_sha256']:
            raise ValueError(f'Frozen model changed: {identifier}')
        destination = output / f'{identifier}.json'
        windows = project / f'data/processed/ml_non_temporal_v1/window_features_{meta["window_size"]}.csv'
        print('Benchmark:', identifier, flush=True)
        subprocess.run([
            sys.executable, '-m', 'src.resource_benchmark', '--model', str(model),
            '--windows', str(windows), '--out', str(destination), '--repeats', '30',
            '--warmup', '5', '--eligibility-column', 'ml_eligible'
        ], cwd=project, env=environment, check=True)
        result = json.loads(destination.read_text())
        single = result['single_window']
        summaries.append({
            'experiment_id': identifier,
            'model_size_bytes': result['model_size_bytes'],
            'single_window_median_ms': single['median_ms'],
            'single_window_p95_ms': single['p95_ms'],
            'batch_amortized_median_ms': result['batch_amortized_median_ms'],
            'batch_size': result['batch_size'],
            'cpu_percent_one_core_scale': single['cpu_percent_one_core_scale'],
            'peak_rss_mib': single['peak_rss_mib'],
            'baseline_rss_mib': single['baseline_rss_mib'],
            'rss_growth_mib': single['rss_growth_mib'],
            'eligibility_column': result['eligibility_column'],
            'resource_scope': single['scope'],
        })
    pd.DataFrame(summaries).to_csv(summary_path, index=False)


if __name__ == '__main__':
    main()
