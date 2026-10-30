#!/usr/bin/env python3
"""Candidate-role Time-Shield validation with frozen chronological protocol."""
import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from src.common import sha256, write_json
from src.decision_fusion import fuse
from src.exploratory_temporal import fit_candidate_baseline, replay_sequence, score_sequence
from src.ml_io import load_windows
from src.resource_benchmark import measure
from src.temporal_drift import TEMPORAL_FEATURES


def quantiles(values):
    values=pd.Series(values,dtype=float).dropna()
    return dict(n=len(values),minimum=float(values.min()) if len(values) else None,
        p05=float(values.quantile(.05)) if len(values) else None,
        median=float(values.median()) if len(values) else None,
        p95=float(values.quantile(.95)) if len(values) else None,
        p99=float(values.quantile(.99)) if len(values) else None,
        maximum=float(values.max()) if len(values) else None)


def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--protocol',type=Path,default=project/'configs/time_shield_exploratory_v2.json')
    p.add_argument('--out',type=Path,default=project/'results/time_shield_exploratory_v2')
    a=p.parse_args();out=a.out.resolve()
    if out.exists():raise FileExistsError(out)
    cfg=json.loads(a.protocol.read_text())
    protected={str(f.relative_to(project)):sha256(f) for folder in ['models','data','results']
               for f in (project/folder).rglob('*') if f.is_file()}
    source=project/cfg['source'];table=load_windows(source)
    size=cfg['window_size']
    if set(table.window_size)!={size}:raise ValueError('Source window size mismatch')
    candidate=table[table.identity_status.eq(cfg['candidate_role'])].copy()
    train=candidate[candidate.split.eq('train')].sort_values(['start_ns','first_frame'])
    cut=int(np.floor(len(train)*cfg['enrollment_fraction_of_ordered_train_windows']))
    if cut<=0 or cut>=len(train):raise ValueError('Invalid chronological enrollment fraction')
    enrollment_all=train.iloc[:cut].copy();calibration=train.iloc[cut:].copy()
    enrollment=enrollment_all[enrollment_all.time_shield_temporal_eligible].copy()
    if len(enrollment)<cfg['minimum_valid_enrollment_windows']:
        raise ValueError('Insufficient exploratory enrollment')
    if enrollment.end_ns.max()>=calibration.start_ns.min():raise ValueError('Enrollment/calibration overlap')
    out.mkdir(parents=True)
    pd.concat([enrollment_all.assign(phase='enrollment_candidate'),calibration.assign(phase='calibration_candidate')])[
        ['window_id','phase','start_epoch','end_epoch','time_shield_temporal_eligible','temporal_quality_reasons']
    ].to_csv(out/'enrollment_calibration_membership.csv',index=False)
    sensitivity=[];threshold_rows=[];distribution=[];traces={};baselines={}
    for shrinkage in cfg['shrinkage_values']:
        baseline=fit_candidate_baseline(enrollment,shrinkage,cfg['minimum_valid_enrollment_windows'])
        baselines[str(shrinkage)]=baseline
        for method in cfg['methods']:
            cal=pd.DataFrame(score_sequence(calibration,baseline,cfg['beta'],method))
            cal_scores=cal.smoothed_distance.dropna()
            if len(cal_scores)<cfg['minimum_valid_calibration_windows']:
                raise ValueError('Insufficient exploratory calibration')
            threshold=float(np.quantile(cal_scores,cfg['threshold_percentile']/100,method='linear'))
            threshold_rows.append(dict(shrinkage=shrinkage,method=method,threshold=threshold,
                percentile=cfg['threshold_percentile'],calibration_windows=len(cal),valid_smoothed_scores=len(cal_scores)))
            for split in ['validation','development_test']:
                monitoring=candidate[candidate.split.eq(split)].copy()
                replay=pd.DataFrame(replay_sequence(monitoring,baseline,threshold,cfg['beta'],cfg['K'],method))
                joined=monitoring.merge(replay,on='window_id',validate='one_to_one')
                counts=joined.status.value_counts()
                sensitivity.append(dict(shrinkage=shrinkage,method=method,split=split,
                    windows=len(joined),temporal_valid=int(joined.temporal_valid.sum()),
                    STABLE=int(counts.get('STABLE',0)),DRIFT=int(counts.get('DRIFT',0)),
                    UNAVAILABLE=int(counts.get('UNAVAILABLE',0)),threshold=threshold))
                for kind,column in [('distance','distance'),('smoothed_distance','smoothed_distance')]:
                    distribution.append(dict(shrinkage=shrinkage,method=method,split=split,score=kind,
                                             **quantiles(joined[column])))
                if shrinkage==cfg['primary_shrinkage'] and method==cfg['primary_method']:
                    traces[split]=joined
                    joined.to_csv(out/f'{split}_mahalanobis_trace.csv',index=False,float_format='%.17g')
    pd.DataFrame(threshold_rows).to_csv(out/'calibration_thresholds.csv',index=False)
    pd.DataFrame(sensitivity).to_csv(out/'regularization_sensitivity.csv',index=False)
    pd.DataFrame(distribution).to_csv(out/'score_distributions.csv',index=False)
    primary=baselines[str(cfg['primary_shrinkage'])]
    primary_threshold=next(r['threshold'] for r in threshold_rows if r['shrinkage']==cfg['primary_shrinkage'] and r['method']==cfg['primary_method'])
    primary.update(threshold=primary_threshold,threshold_percentile=cfg['threshold_percentile'],beta=cfg['beta'],K=cfg['K'],
                   protocol_id=cfg['id'],verified_enrollment_enabled=False,
                   enrollment_first_epoch=str(enrollment.start_epoch.min()),enrollment_last_epoch=str(enrollment.end_epoch.max()),
                   calibration_first_epoch=str(calibration.start_epoch.min()),calibration_last_epoch=str(calibration.end_epoch.max()))
    write_json(out/'baseline_candidate_exploratory.json',primary)
    # Coverage preserves every candidate role; this is availability, not attack performance.
    coverage=[]
    for (split,status),group in table.groupby(['split','identity_status']):
        coverage.append(dict(split=split,identity_status=status,windows=len(group),
            temporal_valid=int(group.time_shield_temporal_eligible.sum()),
            temporal_valid_fraction=float(group.time_shield_temporal_eligible.mean()),verified_windows=0))
    pd.DataFrame(coverage).to_csv(out/'temporal_coverage.csv',index=False)
    state_rows=[]
    for split,trace in traces.items():
        counts=trace.status.value_counts()
        invalid=int((~trace.temporal_valid).sum())
        unavailable=int(counts.get('UNAVAILABLE',0))
        state_rows.append(dict(split=split,windows=len(trace),temporal_valid=int(trace.temporal_valid.sum()),
            STABLE=int(counts.get('STABLE',0)),DRIFT=int(counts.get('DRIFT',0)),UNAVAILABLE=unavailable,
            unavailable_invalid=invalid,unavailable_persistence_warmup=unavailable-invalid))
    pd.DataFrame(state_rows).to_csv(out/'state_counts.csv',index=False)
    # Fusion replay uses frozen development predictions. Only the registered candidate-legitimate stream gets baseline evidence.
    fusion=[];test_trace=traces['development_test'].set_index('window_id')
    for prediction_path in sorted((project/'results/preliminary_non_temporal_v1').glob('n20_*_configuration_radio_frame_predictions.csv')):
        experiment=prediction_path.name.removesuffix('_predictions.csv');pred=pd.read_csv(prediction_path)
        for row in pred.itertuples():
            registered=row.identity_status==cfg['candidate_role'] and row.window_id in test_trace.index
            temporal=test_trace.loc[row.window_id] if registered else None
            status=temporal.status if registered else 'UNAVAILABLE'
            temporal_valid=bool(temporal.temporal_valid) if registered else False
            fusion.append(dict(experiment_id=experiment,window_id=row.window_id,identity_status=row.identity_status,
                ml_score=row.evil_twin_score,baseline_available=registered,temporal_valid=temporal_valid,
                temporal_status=status,decision=fuse(row.evil_twin_score,cfg['fusion_low'],cfg['fusion_high'],
                    status,registered,True,temporal_valid),scope='engineering replay; candidate baseline'))
    pd.DataFrame(fusion).to_csv(out/'fusion_engineering_replay.csv',index=False)
    overhead=measure(lambda:replay_sequence(candidate[candidate.split.eq('development_test')],primary,
        primary_threshold,cfg['beta'],cfg['K'],cfg['primary_method']),30,5)
    overhead['batch_windows']=len(candidate[candidate.split.eq('development_test')])
    overhead['amortized_median_ms']=overhead['median_ms']/overhead['batch_windows']
    overhead['scope']='candidate-legitimate n20 temporal scoring including distance, EWMA and persistence; excludes extraction'
    write_json(out/'runtime.json',overhead)
    # Diagnostic figures use only exploratory candidate observations.
    fig,axes=plt.subplots(1,2,figsize=(11,4.2))
    for split,trace in traces.items():
        axes[0].hist(trace.distance.dropna(),bins=25,alpha=.55,label=split)
        axes[1].hist(trace.smoothed_distance.dropna(),bins=25,alpha=.55,label=split)
    axes[0].set(title='Raw Mahalanobis distance',xlabel='distance',ylabel='windows')
    axes[1].axvline(primary_threshold,color='black',linestyle='--',label=f'p99 threshold={primary_threshold:.3f}')
    axes[1].set(title='EWMA-smoothed distance',xlabel='score',ylabel='windows')
    for axis in axes:axis.legend(fontsize=8)
    fig.suptitle('Candidate-legitimate exploratory monitoring (same capture)');fig.tight_layout()
    fig.savefig(out/'mahalanobis_distributions.png',dpi=180);plt.close(fig)
    sens=pd.DataFrame(sensitivity);fig,axis=plt.subplots(figsize=(8,4.5))
    for (method,split),group in sens.groupby(['method','split']):
        axis.plot(group.shrinkage,group.DRIFT/group.windows,marker='o',label=f'{method} / {split}')
    axis.set(xlabel='shrinkage',ylabel='DRIFT fraction',title='Exploratory regularization sensitivity')
    axis.legend(fontsize=8);fig.tight_layout();fig.savefig(out/'regularization_sensitivity.png',dpi=180);plt.close(fig)
    changed=[name for name,digest in protected.items() if not (project/name).is_file() or sha256(project/name)!=digest]
    if changed:raise AssertionError(f'Historical artifacts changed: {changed}')
    write_json(out/'integrity.json',dict(protected_files=len(protected),changed=changed))
    outputs={f.name:sha256(f) for f in out.iterdir() if f.is_file()}
    write_json(out/'manifest.json',dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),python=platform.python_version(),
        protocol=cfg,protocol_sha256=sha256(a.protocol),source=str(source.relative_to(project)),source_sha256=sha256(source),
        verified_legitimate_windows=0,verified_enrollment_enabled=False,candidate_enrollment_windows=len(enrollment),
        candidate_calibration_windows=len(calibration),historical_artifacts_changed=False,
        outputs_sha256=outputs,claims_scope='exploratory same-capture temporal behavior; no verified detection metrics'))
    print(pd.DataFrame(state_rows).to_string(index=False));print('primary threshold',primary_threshold)


if __name__=='__main__':main()
