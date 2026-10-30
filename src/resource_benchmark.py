"""Inference cost measured in a fresh process, including preprocessing."""
import argparse
import json
import os
import platform
import threading
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import psutil
from .common import write_json
from .ml_io import load_windows


def measure(callable_, repeats=30, warmup=5, period=0.002):
    if repeats < 2 or warmup < 0: raise ValueError('Invalid benchmark repetitions')
    for _ in range(warmup): callable_()
    process = psutil.Process(); baseline = process.memory_info().rss; peak = [baseline]
    stop = threading.Event()
    def sample():
        while not stop.wait(period): peak[0] = max(peak[0], process.memory_info().rss)
    thread = threading.Thread(target=sample, daemon=True); thread.start()
    cpu_start = process.cpu_times(); start = time.perf_counter(); durations = []
    try:
        for _ in range(repeats):
            before = time.perf_counter_ns(); callable_(); durations.append((time.perf_counter_ns() - before) / 1e6)
            peak[0] = max(peak[0], process.memory_info().rss)
    finally:
        elapsed = time.perf_counter() - start; cpu_end = process.cpu_times(); stop.set(); thread.join()
    cpu_seconds = cpu_end.user + cpu_end.system - cpu_start.user - cpu_start.system
    return dict(repeats=repeats, warmup=warmup, median_ms=float(np.median(durations)), p95_ms=float(np.quantile(durations, .95)),
        cpu_seconds=cpu_seconds, cpu_percent_one_core_scale=cpu_seconds / elapsed * 100 if elapsed else None,
        baseline_rss_mib=baseline / 2**20, peak_rss_mib=peak[0] / 2**20, rss_growth_mib=(peak[0] - baseline) / 2**20,
        memory_sample_period_s=period, elapsed_seconds=elapsed,
        scope='Warm inference incl preprocessing; sampled process RSS includes interpreter/libraries, not training peak')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--model', type=Path, required=True); p.add_argument('--windows', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True); p.add_argument('--repeats', type=int, default=30)
    p.add_argument('--warmup', type=int, default=5)
    p.add_argument('--eligibility-column', default='eligible',
                   help='Boolean column selecting benchmark windows (default preserves the strict-policy runner)')
    args = p.parse_args()
    if args.out.exists(): raise FileExistsError(args.out)
    bundle = joblib.load(args.model)
    data = load_windows(args.windows)
    if args.eligibility_column not in data.columns:
        raise ValueError(f'Missing eligibility column: {args.eligibility_column}')
    eligible = data[args.eligibility_column]
    if eligible.dtype != bool:
        raise ValueError(f'Eligibility column is not boolean: {args.eligibility_column}')
    x = data[eligible & data.split.eq('development_test')][bundle['features']]
    if x.empty: raise ValueError('No eligible benchmark observations')
    single = measure(lambda: bundle['pipeline'].predict_proba(x.iloc[:1]), args.repeats, args.warmup)
    batch = measure(lambda: bundle['pipeline'].predict_proba(x), args.repeats, args.warmup)
    write_json(args.out, dict(model=str(args.model), model_size_bytes=args.model.stat().st_size,
        eligibility_column=args.eligibility_column,
        batch_size=len(x), single_window=single, batch=batch,
        batch_amortized_median_ms=batch['median_ms'] / len(x),
        platform=platform.platform(), machine=platform.machine(), cpu_logical=psutil.cpu_count(),
        physical_memory_bytes=psutil.virtual_memory().total, model_n_jobs=bundle['pipeline'].named_steps['model'].get_params().get('n_jobs'),
        thread_environment={n: os.environ.get(n) for n in ['OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','VECLIB_MAXIMUM_THREADS']}))


if __name__ == '__main__': main()
