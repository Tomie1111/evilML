#!/usr/bin/env python3
"""Engineering validation and evidence-gated operational audit; never train models."""
import argparse
import itertools
import json
import platform
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from src.common import sha256, write_json
from src.decision_fusion import fuse
from src.external_inference import predict_frozen
from src.ml_io import load_windows
from src.resource_benchmark import measure
from src.trusted_temporal import monitor
from src.pcap_tools import find_tool, field_registry, BASE_FIELDS, EXTRA_FIELDS


def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,default=project/'results/operational_validation_v1')
    a=p.parse_args(); out=a.out.resolve()
    if out.exists(): raise FileExistsError(out)
    config_path=project/'configs/operational_validation_v1.json'
    config=json.loads(config_path.read_text())
    # Protect every existing research artifact, not only the strict checkpoint.
    protected={str(f.relative_to(project)):sha256(f) for directory in ['models','data','results']
               for f in (project/directory).rglob('*') if f.is_file()}
    out.mkdir(parents=True)
    labels=pd.read_csv(project/'results/audit/identity_label_audit.csv')
    roles=labels.groupby(['pcap','identity_status']).size().reset_index(name='frames')
    roles.to_csv(out/'identity_evidence_counts.csv',index=False)
    verified=int(labels.identity_status.eq('verified_legitimate').sum())
    if verified:
        raise ValueError('New verified observations found: review evidence and declare chronological enrollment/calibration/monitoring before scoring')
    trace=pd.read_csv(project/'results/audit/window_attrition_v2/window_attrition.csv')
    selected=trace[trace.policy.isin(['strict_fixed_1p5','fixed_2p0','fixed_3p0'])]
    coverage=selected.groupby(['policy','window_size','capture_session','identity_status','split']).agg(
        windows=('window_id','size'), temporal_valid=('time_shield_temporal_eligible','sum')).reset_index()
    coverage['coverage_fraction']=coverage.temporal_valid/coverage.windows
    coverage['verified_enrollment_windows']=0
    coverage.to_csv(out/'quality_coverage.csv',index=False)
    reasons=selected.assign(reason=selected.temporal_quality_reasons.fillna('').str.split(';')).explode('reason')
    reasons=reasons[reasons.reason.ne('')].groupby(['policy','window_size','identity_status','reason']).size().reset_index(name='windows')
    reasons.to_csv(out/'quality_reasons.csv',index=False)
    # Real temporal vectors, no baseline fit and no relabeling.
    vectors=[]; states=[]; monitoring_tables=[]
    for size in config['window_sizes']:
        table=load_windows(project/f'data/processed/ml_non_temporal_v1/window_features_{size}.csv')
        candidate=table[table.identity_status.eq('candidate_legitimate')].copy()
        usable=candidate[candidate.time_shield_temporal_eligible]
        for feature in ['median_interarrival_ms','mad_interarrival_ms','tsf_slope_s_per_s']:
            values=usable[feature].dropna()
            vectors.append(dict(window_size=size,feature=feature,n=len(values),
                median=float(values.median()) if len(values) else None,
                p05=float(values.quantile(.05)) if len(values) else None,
                p95=float(values.quantile(.95)) if len(values) else None,
                scope='candidate legitimate feature distribution; not trusted drift scores'))
        # Threshold 0 is an unreachable engineering sentinel: baseline=None prevents scoring.
        missing_baseline=monitor(candidate,None,0,config['beta'],config['K'])
        pd.DataFrame(missing_baseline).to_csv(out/f'n{size}_availability_trace.csv',index=False)
        states.append(dict(window_size=size,scope='candidate legitimate availability replay',
            windows=len(candidate),STABLE=0,DRIFT=0,UNAVAILABLE=len(candidate),
            verified_enrollment_windows=0,baseline_status='blocked_no_verified_legitimate'))
        if size==20: monitoring_tables.append(candidate)
    pd.DataFrame(vectors).to_csv(out/'temporal_feature_distributions.csv',index=False)
    pd.DataFrame(states).to_csv(out/'state_counts.csv',index=False)
    write_json(out/'enrollment_feasibility.json',dict(verified_legitimate_frames=0,
        verified_enrollment_windows=0,baseline_created=False,chronological_enrollment_monitoring_performed=False,
        blocker='Only candidate/unknown identities exist; independent_identity_verification=false',
        previous_baseline_status='Historical candidate-role baseline, not admitted as verified enrollment',
        threshold=None,drift_score_distribution=None,covariance_sensitivity_results=None,
        planned_shrinkage_values=config['covariance_shrinkage_sensitivity']))
    # Full decision-rule table contains only declared engineering inputs.
    rules=[]
    for score,status,baseline,ml,temporal in itertools.product(
            [.1,.2,.5,.8,.9],['STABLE','DRIFT','UNAVAILABLE'],[False,True],[False,True],[False,True]):
        rules.append(dict(score=score,temporal_status=status,baseline_available=baseline,
            ml_valid=ml,temporal_valid=temporal,
            decision=fuse(score,.2,.8,status,baseline,ml,temporal),scope='engineering truth table'))
    pd.DataFrame(rules).to_csv(out/'fusion_rule_table.csv',index=False)
    engineering=[]; inference_checks=[]
    selection=json.loads((project/'models/preliminary_non_temporal_v1/selection_manifest.json').read_text())
    for identifier,meta in selection['selected'].items():
        if meta['ablation']!='configuration_radio_frame': continue
        predictions=pd.read_csv(project/f'results/preliminary_non_temporal_v1/{identifier}_predictions.csv')
        table=load_windows(project/f'data/processed/ml_non_temporal_v1/window_features_{meta["window_size"]}.csv')
        aligned=table.set_index('window_id').loc[predictions.window_id].reset_index()
        scores=predict_frozen(project/meta['artifact'],meta['artifact_sha256'],aligned)
        matches=bool(np.allclose(scores,predictions.evil_twin_score,rtol=1e-12,atol=1e-12))
        if not matches: raise AssertionError('Frozen preprocessing replay changed predictions')
        inference_checks.append(dict(experiment_id=identifier,windows=len(aligned),
            ordered_features=meta['features'],frozen_scores_match=matches,retrained=False))
        for row,window in zip(predictions.itertuples(),aligned.itertuples()):
            engineering.append(dict(experiment_id=identifier,window_id=row.window_id,
                ml_score=row.evil_twin_score,temporal_valid=window.time_shield_temporal_eligible,
                baseline_available=False,temporal_status='UNAVAILABLE',
                decision=fuse(row.evil_twin_score,.2,.8,'UNAVAILABLE',False,
                              window.ml_feature_eligible,window.time_shield_temporal_eligible)))
    pd.DataFrame(engineering).to_csv(out/'frozen_prediction_fusion_replay.csv',index=False)
    write_json(out/'frozen_inference_checks.json',inference_checks)
    candidate=monitoring_tables[0]
    overhead=measure(lambda:monitor(candidate,None,0,config['beta'],config['K']),30,5)
    overhead['scope']='UNAVAILABLE path on real candidate windows; excludes covariance scoring and PCAP extraction'
    write_json(out/'runtime_unavailable_path.json',overhead)
    # Reuse the existing intake validator; keep the prior readiness result immutable.
    subprocess.run([sys.executable,str(project/'scripts/check_independent_evaluation_readiness.py'),
                    '--out',str(out/'independent_readiness.json')],cwd=project,check=True,stdout=subprocess.DEVNULL)
    tshark=find_tool('tshark'); registry=field_registry(tshark)
    write_json(out/'external_readiness.json',dict(tshark=tshark,
        missing_dissector_fields=sorted(set(BASE_FIELDS|EXTRA_FIELDS)-set(registry)-{'_ws.malformed'}),
        independent_pcaps_registered=0,external_import_executed=False,
        importer='scripts/import_external_pcap.py',frozen_inference_replay_passed=True,
        pending='Actual independent PCAP extraction, field-value quality, frame attribution, lineage/device review',
        note='Distinct file hashes do not prove independent sessions or unseen physical APs'))
    # No drift histogram can be populated without a verified baseline.
    fig,axes=plt.subplots(1,2,figsize=(11,4))
    c=coverage[(coverage.identity_status=='candidate_legitimate') & (coverage['split']!='boundary_excluded')]
    for policy,group in c.groupby('policy'):
        g=group.groupby('window_size')[['windows','temporal_valid']].sum()
        axes[0].plot(g.index,g.temporal_valid/g.windows,marker='o',label=policy)
    axes[0].set(xlabel='Beacon window size',ylabel='Temporal-valid fraction',ylim=(0,1.05),
                title='Candidate legitimate quality coverage')
    axes[0].legend(fontsize=8)
    axes[1].axis('off');axes[1].text(.5,.5,'Trusted drift-score distribution unavailable\n\n0 verified legitimate enrollment windows\nNo baseline fitted; no distances computed',ha='center',va='center')
    fig.tight_layout();fig.savefig(out/'coverage_and_enrollment_gate.png',dpi=160);plt.close(fig)
    fig,axes=plt.subplots(1,3,figsize=(12,3.8))
    for axis,feature in zip(axes,['median_interarrival_ms','mad_interarrival_ms','tsf_slope_s_per_s']):
        axis.hist(candidate.loc[candidate.time_shield_temporal_eligible,feature].dropna(),bins=25)
        axis.set_title(feature,fontsize=9);axis.set_ylabel('Windows')
    fig.suptitle('n20 candidate legitimate temporal features (not trusted drift scores)')
    fig.tight_layout();fig.savefig(out/'temporal_features_candidate_only.png',dpi=160);plt.close(fig)
    tests=subprocess.run([sys.executable,'-m','pytest','tests','-q'],cwd=project,capture_output=True,text=True)
    (out/'test_results.txt').write_text(tests.stdout+tests.stderr)
    if tests.returncode: raise RuntimeError('Tests failed')
    changed=[name for name,digest in protected.items() if sha256(project/name)!=digest]
    write_json(out/'integrity.json',dict(protected_artifact_count=len(protected),changed=changed,
                                       original_artifact_sha256=protected))
    if changed: raise AssertionError('Historical research artifacts changed')
    write_json(out/'manifest.json',dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
        python=platform.python_version(),protocol_sha256=sha256(config_path),
        source_sha256={name:sha256(project/name) for name in [
            'results/audit/identity_label_audit.csv','results/audit/window_attrition_v2/window_attrition.csv',
            'configs/identity_evidence.json','configs/label_protocol_acceptance.json']},
        code_sha256={str(f.relative_to(project)):sha256(f) for folder in ['src','scripts','tests']
                     for f in (project/folder).glob('*.py')},
        outputs_sha256={f.name:sha256(f) for f in out.iterdir() if f.is_file()},
        no_training=True,no_final_classifier_selected=True,verified_operational_validation='blocked'))
    print(tests.stdout.strip());print('Saved:',out)


if __name__=='__main__': main()
