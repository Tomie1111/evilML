#!/usr/bin/env python3
"""Run temporal/fusion only after the ML-validation checkpoint exists."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import joblib
import numpy as np
import pandas as pd
from src.common import epoch_ns, load_config, read_csv, sha256, write_json
from src.ml_io import load_windows
from src.evaluate_models import evaluate
from src.temporal_drift import replay, smoothed_values, TEMPORAL_FEATURES
from src.decision_fusion import fuse
from src.resource_benchmark import measure


def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,default=project/'configs/ml_experiment.yaml')
    p.add_argument('--project-root',type=Path,default=project)
    p.add_argument('--dataset-root',type=Path)
    a=p.parse_args();project=a.project_root.resolve();cfg=json.loads(a.config.read_text())
    _,root=load_config(a.config.parent/cfg['audit_config'],a.dataset_root)
    output=project/'results/temporal_fusion'
    if output.exists():raise FileExistsError(output)
    checkpoint=json.loads((project/'results/ml_validation.json').read_text())
    if not checkpoint['passed']:raise ValueError('ML pipeline validation is required first')
    selection=json.loads((project/'models/selection_manifest.json').read_text())
    if sha256(project/'models/selection_manifest.json')!=checkpoint['selection_manifest_sha256']:raise ValueError('ML selection changed')
    if sha256(a.config)!=selection['config_sha256']:raise ValueError('Experiment config changed')
    identifier=f'n{cfg["primary_window_size"]}_{cfg["primary_model"]}_all'
    meta=selection['selected'][identifier]
    if sha256(project/meta['artifact'])!=meta['artifact_sha256']:raise ValueError('Model artifact changed')
    model=joblib.load(project/meta['artifact'])
    w=load_windows(project/f'data/processed/window_features_{cfg["primary_window_size"]}.csv')
    w=w[w.split.isin(['validation','development_test'])].copy()
    settings=cfg['temporal']; baseline_path=root/settings['baseline_path_relative_to_dataset']
    baseline=json.loads(baseline_path.read_text());registry={(cfg['canonical_pcap'],settings['trusted_bssid'])}
    enrollment=pd.read_csv(root/settings['enrollment_path_relative_to_dataset'],dtype={'end_epoch':str})
    enrollment=enrollment[enrollment.split.eq('enrollment')]
    split_manifest=json.loads((project/'data/splits/split_manifest.json').read_text())
    if max(epoch_ns(x) for x in enrollment.end_epoch)>split_manifest['train_end_ns']:raise ValueError('Enrollment extends outside training time')
    if baseline['features']!=TEMPORAL_FEATURES:raise ValueError('Temporal baseline feature mismatch')
    if not np.allclose(enrollment[TEMPORAL_FEATURES].mean().to_numpy(),baseline['mean'],rtol=1e-10,atol=1e-12):raise ValueError('Baseline enrollment mismatch')
    validation=w[w.eligible & w.split.eq('validation')]
    vscore=model['pipeline'].predict_proba(validation[model['features']])[:,1]
    searches=[]
    for high in cfg['fusion']['high_threshold_candidates']:
        metrics,_=evaluate(validation.target,vscore,high);searches.append(dict(high=high,f1=metrics['f1']))
    high=max(searches,key=lambda r:r['f1'])['high']
    low_choices=[low for low in cfg['fusion']['low_threshold_candidates'] if low<high and not np.any((validation.target.to_numpy()==1)&(vscore<=low))]
    low=max(low_choices) if low_choices else None
    trusted_val=w[w.split.eq('validation') & w.bssid.eq(settings['trusted_bssid']) & w.pcap.eq(cfg['canonical_pcap'])]
    thresholds={}
    for method in settings['methods']:
        vals=smoothed_values(trusted_val,baseline,settings['beta'],method)
        if not len(vals):raise ValueError('No valid trusted validation windows')
        thresholds[method]=dict(threshold=float(np.quantile(vals,settings['percentile']/100,method='linear')),calibration_n=len(vals))
    output.mkdir(parents=True)
    calibration=dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),thresholds=thresholds,beta=settings['beta'],K=settings['K'],
        percentile=settings['percentile'],high_ml=high,low_ml=low,high_threshold_search=searches,
        source_split='validation only',baseline_sha256=sha256(baseline_path),baseline_fit_n=baseline['fit_n'],
        baseline_registry=[dict(pcap=c,bssid=b) for c,b in registry],
        baseline_trust_scope='Accepted author-documented legitimate role in this capture only',
        baseline_updated=False,primary_model=identifier,
        no_drift_is_not_automatically_stable=True,stable_policy='K consecutive valid smoothed scores <= threshold; intermediate evidence is UNAVAILABLE')
    write_json(output/'calibration.json',calibration)
    test=w[w.split.eq('development_test')].copy()
    scores=np.full(len(test),np.nan);valid=test.quality_valid.to_numpy()
    scores[valid]=model['pipeline'].predict_proba(test.loc[valid,model['features']])[:,1]
    test['ml_score']=scores
    temporal_summary=[];final=None
    for method in settings['methods']:
        temporal=pd.DataFrame(replay(test,baseline,registry,thresholds[method]['threshold'],settings['beta'],settings['K'],method))
        joined=test.merge(temporal,on='window_id',validate='one_to_one')
        joined.to_csv(output/f'{method}_trace.csv',index=False,float_format='%.17g')
        temporal_summary.append(dict(method=method,total_windows=len(joined),
            baseline_available=int(joined.baseline_available.sum()),stable=int(joined.status.eq('STABLE').sum()),
            drift=int(joined.status.eq('DRIFT').sum()),unavailable=int(joined.status.eq('UNAVAILABLE').sum()),
            attack_precision=None,attack_recall=None,reason='Drift is not an attack label; rogue stream has no trusted baseline'))
        if method==cfg['fusion']['temporal_method']:final=joined
    final['fusion_state']=[fuse(r.ml_score,low,high,r.status,r.baseline_available,r.quality_valid) for r in final.itertuples()]
    final['ml_only_state']=['Evil Twin Suspected' if r.quality_valid and r.ml_score>=.5 else 'Candidate Legitimate' if r.quality_valid else 'Pending' for r in final.itertuples()]
    final.to_csv(output/'fusion_predictions.csv',index=False,float_format='%.17g')
    summaries=[]
    for system,column in [('ML only','ml_only_state'),('ML + Time-Shield','fusion_state')]:
        gt=final.target.notna();positive=gt & final.target.eq(1);negative=gt & final.target.eq(0)
        alert=final[column].eq('Evil Twin Suspected');pending=final[column].eq('Pending')
        true=int((alert&positive).sum());false=int((alert&negative).sum())
        summaries.append(dict(system=system,candidate_windows=len(final),candidate_evil_windows=int(positive.sum()),
            candidate_legitimate_windows=int(negative.sum()),evil_alerts=true,legitimate_alerts=false,
            candidate_evil_alert_recall=true/int(positive.sum()) if positive.any() else None,
            candidate_alert_precision=true/(true+false) if true+false else None,
            pending_windows=int(pending.sum()),pending_rate=float(pending.mean()),
            suspicious_trusted_windows=int(final[column].eq('Suspicious Trusted AP').sum()),
            consistent_trusted_windows=int(final[column].eq('Consistent with Trusted Baseline').sum()),
            independently_verified_fpr=None,false_alerts_per_verified_ap_hour=None,
            note='Candidate-role triage metrics include invalid/pending windows in recall denominator; no drift ground truth'))
    pd.DataFrame(summaries).to_csv(output/'fusion_comparison.csv',index=False)
    pd.DataFrame(temporal_summary).to_csv(output/'temporal_comparison.csv',index=False)
    # Latency uses observed packet evidence within the deployed test segment only.
    raw=read_csv(project/cfg['source_beacons'])
    ids={r['bssid'] for r in read_csv(project/cfg['audited_identities']) if r['identity_status']=='candidate_evil_twin'}
    observed=[epoch_ns(r['frame.time_epoch']) for r in raw if r['wlan.bssid'] in ids and epoch_ns(r['frame.time_epoch'])>split_manifest['validation_end_ns']]
    latency=[]
    for system,column in [('ML only','ml_only_state'),('ML + Time-Shield','fusion_state')]:
        alerts=final[final.target.eq(1)&final[column].eq('Evil Twin Suspected')]
        first_alert=min((epoch_ns(x) for x in alerts.end_epoch),default=None)
        latency.append(dict(system=system,first_observed_rogue_ns=min(observed) if observed else None,
            first_alert_window_end_ns=first_alert,first_alert_after_test_first_observed_rogue_s=(first_alert-min(observed))/1e9 if first_alert is not None and observed else None,
            physical_attack_onset_detection_delay_s=None,scope='Start of development-test observation, not true attack onset; includes waiting through invalid windows'))
    write_json(output/'latency.json',latency)
    # Additional module costs, independent of classifier inference measurement.
    temporal_cost=measure(lambda:replay(test,baseline,registry,thresholds['mahalanobis']['threshold'],settings['beta'],settings['K']),30,5)
    fusion_cost=measure(lambda:[fuse(r.ml_score,low,high,r.status,r.baseline_available,r.quality_valid) for r in final.itertuples()],30,5)
    write_json(output/'overhead.json',dict(batch_windows=len(test),temporal_batch=temporal_cost,fusion_rules_batch=fusion_cost,
        temporal_amortized_median_ms=temporal_cost['median_ms']/len(test),fusion_rules_amortized_median_ms=fusion_cost['median_ms']/len(test),
        classifier_cost_source='results/metrics/resource_benchmarks.csv',note='Separate module timings; not an end-to-end PCAP-to-alert benchmark'))
    write_json(output/'verification.json',dict(ml_checkpoint_verified=True,thresholds_validation_only=True,
        baseline_enrollment_precedes_validation=True,baseline_unchanged=sha256(baseline_path)==calibration['baseline_sha256'],
        invalid_always_pending=bool(final.loc[~final.quality_valid,'fusion_state'].eq('Pending').all()),
        rogue_has_no_assumed_trusted_baseline=bool((~final.loc[final.target.eq(1),'baseline_available']).all()),
        no_independent_session_results_invented=True))
    print(pd.DataFrame(summaries).to_string(index=False));print(pd.DataFrame(temporal_summary).to_string(index=False))


if __name__=='__main__':main()
