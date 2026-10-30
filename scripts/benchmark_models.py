#!/usr/bin/env python3
"""Benchmark each frozen artifact in its own process using real eligible windows."""
import json
import os
import subprocess
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pandas as pd
from src.common import sha256


def main():
    project=Path(__file__).resolve().parents[1]
    selection=json.loads((project/'models/selection_manifest.json').read_text())
    cfg=json.loads((project/'configs/ml_experiment.yaml').read_text())
    output=project/'results/resource_measurements'
    if output.exists():raise FileExistsError(output)
    output.mkdir()
    env=dict(os.environ,OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',VECLIB_MAXIMUM_THREADS='1')
    summaries=[]
    for identifier,meta in selection['selected'].items():
        model=project/meta['artifact']
        if sha256(model)!=meta['artifact_sha256']:raise ValueError('Frozen model changed')
        print('Benchmark:',identifier,flush=True)
        destination=output/f'{identifier}.json'
        subprocess.run([sys.executable,'-m','src.resource_benchmark','--model',str(model),
            '--windows',str(project/f'data/processed/window_features_{meta["window_size"]}.csv'),
            '--out',str(destination),'--repeats',str(cfg['resource_benchmark']['repeats']),
            '--warmup',str(cfg['resource_benchmark']['warmup'])],cwd=project,env=env,check=True)
        r=json.loads(destination.read_text());single=r['single_window']
        summaries.append(dict(experiment_id=identifier,model_size_bytes=r['model_size_bytes'],
            single_window_median_ms=single['median_ms'],single_window_p95_ms=single['p95_ms'],
            batch_amortized_median_ms=r['batch_amortized_median_ms'],batch_size=r['batch_size'],
            cpu_percent_one_core_scale=single['cpu_percent_one_core_scale'],
            peak_rss_mib=single['peak_rss_mib'],baseline_rss_mib=single['baseline_rss_mib'],rss_growth_mib=single['rss_growth_mib'],
            resource_scope='isolated process warm inference including preprocessing; sampled RSS includes runtime'))
    pd.DataFrame(summaries).to_csv(project/'results/metrics/resource_benchmarks.csv',index=False)


if __name__=='__main__':main()
