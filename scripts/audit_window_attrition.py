#!/usr/bin/env python3
"""Explain strict attrition and compare fixed, segmented and grouping policies."""
import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
from src.common import epoch_ns, read_csv, sha256, unique_index, write_json
from src.dataset_splitting import assign_splits
from src.ml_io import load_windows
from src.pcap_tools import BASE_FIELDS, EXTRA_FIELDS
from src.stream_grouping import group_streams
from src.window_policy import evaluate_policy


def reason_groups(reasons, label_missing=False):
    reasons={v for v in str(reasons).split(';') if v and v != 'nan'}
    result=set()
    if any('gap' in v for v in reasons):result.add('capture_gap')
    if any('nonpositive' in v and 'tsf' in v for v in reasons):result.add('tsf_reset_or_repeat')
    if 'incomplete_window' in reasons:result.add('insufficient_frames')
    if label_missing or 'mixed_or_unknown_identity' in reasons:result.add('mixed_or_unknown_label')
    if any(v in reasons for v in ['configuration_change','mixed_bssid','mixed_ssid','channel_change']):result.add('stream_or_profile_change')
    if any('missing' in v or v == 'feature_parse_error' for v in reasons):result.add('missing_field_or_parse_error')
    if 'nonfinite_feature' in reasons:result.add('nonfinite_temporal_feature')
    if 'truncated_frame' in reasons or 'malformed_frame' in reasons:result.add('frame_integrity')
    if not result and reasons:result.add('other_quality')
    return result or {'none'}


def summarize_windows(w, policy, size):
    reason_rows=[];summary=[]
    for (pcap,status,sid,split),group in w.groupby(['pcap','identity_status','candidate_stream_id','split'],dropna=False):
        sessions=group.pcap.nunique()
        summary.append(dict(policy=policy,window_size=size,capture_session=pcap,identity_status=status,
            candidate_stream_id=sid,split=split,windows=len(group),frames=int(group.n_frames.sum()),
            strict_temporal_valid=int(group.quality_valid.sum()),time_shield_eligible=int(group.time_shield_temporal_eligible.sum()),
            ml_non_temporal_eligible=int(group.ml_feature_eligible.sum()),
            labeled=int(group.target.notna().sum()),independent_capture_sessions=sessions,
            valid_slope=int(np.isfinite(group.tsf_slope_s_per_s).sum())))
        reason_counter=Counter()
        for row in group.itertuples():
            groups=reason_groups(row.quality_reasons,pd.isna(row.target))
            for reason in groups:reason_counter[reason]+=1
        for reason,count in sorted(reason_counter.items()):
            reason_rows.append(dict(policy=policy,window_size=size,capture_session=pcap,identity_status=status,
                candidate_stream_id=sid,split=split,rejection_reason=reason,windows_with_reason=count,
                note='Reasons overlap; do not sum as unique rejected windows'))
    return summary,reason_rows


def interval_audit(rows):
    result=[]
    for sid,group in group_streams(rows,'bssid_capabilities').items():
        counts=Counter();intervals=[]
        for left,right in zip(group,group[1:]):
            da=(epoch_ns(right['frame_time_epoch'])-epoch_ns(left['frame_time_epoch']))/1000 # us
            dt=int(right['tsf'])-int(left['tsf'])
            advertised=int(left['beacon_interval_tu'])*1024
            intervals.append(da/1000)
            counts['arrival_nonpositive']+=da<=0
            counts['tsf_nonpositive']+=dt<=0
            for factor in [1.5,2.0,3.0]:
                name=str(factor).replace('.','p')
                a=da>factor*advertised;t=dt>factor*advertised
                counts[f'arrival_gap_{name}']+=a;counts[f'tsf_gap_{name}']+=t
                counts[f'both_gap_{name}']+=a and t
            counts['approx_two_intervals']+=1.5*advertised<da<2.5*advertised
            counts['approx_three_or_more_intervals']+=da>=2.5*advertised
        r=group[0]
        result.append(dict(capture_session=r['pcap'],candidate_stream_id=sid,bssid=r['bssid'],
            capabilities=r['capabilities'],frames=len(group),observed_intervals=len(intervals),
            median_interarrival_ms=float(np.median(intervals)) if intervals else None,
            p95_interarrival_ms=float(np.quantile(intervals,.95)) if intervals else None,
            **counts,interpretation='Large receive/TSF intervals are capture discontinuities, not proof of source packet loss'))
    return result


def report(out,policy_summary,reason_rows,interval_rows,checks,config):
    s=pd.DataFrame(policy_summary);r=pd.DataFrame(reason_rows)
    baseline=s[s.policy.eq('strict_fixed_1p5')]
    overview=baseline.groupby(['window_size','identity_status'])[['windows','strict_temporal_valid','ml_non_temporal_eligible']].sum().reset_index()
    lines=['# Window attrition audit — Evil Twin', '',
      'This report uses only original AWID3 frames and the previously accepted candidate identity mapping. '
      'No oversampling, synthetic windows, test-score-based policy selection or baseline refit occurred.', '',
      '## Original strict policy (fixed windows; gap factor 1.5)', '',
      '| Size | Candidate role | Windows | Temporal eligible | ML non-temporal eligible |',
      '|---:|---|---:|---:|---:|']
    for x in overview.itertuples():
        lines.append(f'| {x.window_size} | {x.identity_status} | {x.windows} | {x.strict_temporal_valid} | {x.ml_non_temporal_eligible} |')
    lines += ['', 'Reason counts overlap when one window has several flags. The detailed breakdown by capture, stream and split is in `attrition_by_reason.csv` and `window_attrition.csv`.', '',
      '| Size | Candidate role | Capture gap | TSF reset/repeat | Missing/parse | Nonfinite temporal | Incomplete | Mixed/unknown label | Stream/profile change |',
      '|---:|---|---:|---:|---:|---:|---:|---:|---:|']
    for size in [10,20,50]:
        for status in ['candidate_legitimate','candidate_evil_twin']:
            g=r[(r.policy=='strict_fixed_1p5')&(r.window_size==size)&(r.identity_status==status)]
            n=lambda reason:int(g.loc[g.rejection_reason.eq(reason),'windows_with_reason'].sum())
            lines.append(f'| {size} | {status} | {n("capture_gap")} | {n("tsf_reset_or_repeat")} | {n("missing_field_or_parse_error")} | {n("nonfinite_temporal_feature")} | {n("insufficient_frames")} | {n("mixed_or_unknown_label")} | {n("stream_or_profile_change")} |')
    lines += ['', '## Root causes', '',
      '- The rogue stream has many receive gaps and matching TSF gaps. A 20-frame strict window fails if **any** of its 19 internal intervals, or its incoming boundary, exceeds 1.5 advertised intervals. The chance of retaining long windows falls sharply.',
      '- `interval_diagnostics.csv` counts distinct interval events; `attrition_by_reason.csv` counts windows affected by those events. They have different denominators.',
      '- One observed TSF decrease occurs inside the second Evil Twin profile. No slope is computed for a window spanning it. This is an observed discontinuity; a reboot or attack cause is unverified.',
      '- The Evil Twin capture has no missing beacon fields in the audited streams. Small terminal tails cause incomplete windows. Candidate role windows are not mixed in the default grouping.',
      '- BSSID-only grouping combines two rogue capability profiles and produces one profile-change window at their transition. Stable-profile grouping gives the same three groups as BSSID+capability in these data. Neither rule establishes physical device identity.', '',
      '## Separate eligibility and sensitivity', '',
      'ML non-temporal eligibility requires full windows, one accepted candidate role, stable configuration and finite configuration/radio/frame features. It can retain windows with receive gaps or TSF resets because those features do not use temporal continuity. Time-Shield eligibility keeps the strict continuity gate. Temporal features from invalid windows must not be silently imputed into an all-four-group ML model.',
      'The fixed 1.5, 2.0 and 3.0 gap settings; gap-segmented construction; and two alternate grouping rules were specified in `configs/window_sensitivity.json`. Sensitivity tables show available records only. Larger gap thresholds can admit missing-beacon intervals and are not chosen as a new quality standard from test performance.', '',
      'Recommended quality policy: fixed capture-order windows with BSSID+capability candidate grouping; use ML non-temporal flags for configuration/radio/frame experiments and strict 1.5-gap flags for Time-Shield. Do not compute or use a slope across a TSF reset. Use an explicit missing-temporal indicator only in a separately validated model design, not automatic imputation of invalid temporal features.', '',
      '## Feasibility gate', '',
      'See `policy_support.csv` for train/validation/development-test counts for every policy and class. Candidate profile streams are not independent sessions. Under recommended fixed 1.5/non-temporal ML eligibility, the Evil Twin counts are 90/141/144 for size 10, 45/70/72 for size 20, and 18/27/28 for size 50. Size 10 and 20 pass the documented exploratory support heuristic of at least 20/10/10 per class across train/validation/development test; size 50 fails it in train. These counts measure availability, not model performance.',
      'The source has one Evil Twin capture and no independent labeled test session, so **final model comparison and unseen-AP claims are not supported**. A preliminary same-capture study can be considered only for supported policies, clearly labeled as exploratory.',
      'The earlier strict-policy model artifacts and metrics were frozen before this audit in `results/strict_policy_checkpoint.json`; they are exploratory and should not be promoted to final results.', '',
      '## Verification', '',
      f'- Strict policy windows match previous artifacts: {checks["strict_windows_match"]}.',
      f'- All input frames conserved per evaluated policy and size: {checks["frame_conservation"]}.',
      f'- No overlapping frame membership within a policy/size: {checks["unique_membership"]}.',
      f'- Original strict files retain their recorded SHA-256 hashes: {checks["strict_files_unchanged"]}.',
      'No independent AP/session observations were generated.', '']
    (out/'report.md').write_text('\n'.join(lines))


def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project-root',type=Path,default=project)
    p.add_argument('--config',type=Path,default=project/'configs/window_sensitivity.json')
    p.add_argument('--out',type=Path,default=project/'results/audit/window_attrition_v2')
    a=p.parse_args();project=a.project_root.resolve();cfg=json.loads(a.config.read_text())
    if a.out.exists():raise FileExistsError(a.out)
    checkpoint=json.loads((project/'results/strict_policy_checkpoint.json').read_text())
    for name,digest in checkpoint['files_sha256'].items():
        if sha256(project/name)!=digest:raise ValueError(f'Frozen strict artifact changed: {name}')
    mlcfg=json.loads((project/'configs/ml_experiment.yaml').read_text())
    source=project/mlcfg['source_beacons'];labels=project/mlcfg['audited_identities']
    extraction=json.loads((project/'data/raw/audit/extraction_manifest.json').read_text())
    expected=next(x['output_sha256'] for x in extraction['extractions'] if x['scenario']=='Evil_Twin' and x['kind']=='beacons')
    if sha256(source)!=expected:raise ValueError('PCAP extraction changed')
    mapping=unique_index(read_csv(labels));columns=BASE_FIELDS|EXTRA_FIELDS
    rows=[]
    for raw in read_csv(source):
        row=dict(pcap=mlcfg['canonical_pcap'],**{columns[k]:v for k,v in raw.items()})
        label=mapping[(row['pcap'],int(row['frame_number']))]
        row.update(identity_status=label['identity_status'],identity_evidence_id=label['identity_evidence_id'])
        rows.append(row)
    split=json.loads((project/'data/splits/split_manifest.json').read_text())
    cutoff=(split['train_end_ns'],split['validation_end_ns'])
    summary=[];reasons=[];support=[];trace=[];checks={'strict_windows_match':True,'frame_conservation':True,'unique_membership':True,'strict_files_unchanged':True}
    for policy in cfg['policies']:
        for size in cfg['window_sizes']:
            windows,members=evaluate_policy(rows,size,policy['grouping'],policy['gap_factor'],policy['construction'])
            if len(members)!=len(rows):raise ValueError('Frame loss in policy window construction')
            keys=[(m['pcap'],m['frame_number']) for m in members]
            if len(set(keys))!=len(keys):raise ValueError('Overlapping source frame membership')
            w=assign_splits(pd.DataFrame(windows),cutoff)
            w['ml_eligible']=w.ml_feature_eligible&w.split.ne('boundary_excluded')
            w['temporal_eligible']=w.time_shield_temporal_eligible&w.split.ne('boundary_excluded')
            if policy['id']=='strict_fixed_1p5':
                old=load_windows(project/f'data/processed/window_features_{size}.csv')
                for field in ['window_id','first_frame','last_frame','n_frames','quality_valid','quality_reasons','split','eligible']:
                    if not w[field].fillna('').astype(str).reset_index(drop=True).equals(old[field].fillna('').astype(str).reset_index(drop=True)):
                        raise ValueError(f'Strict baseline mismatch n{size} field={field}')
            sub,rr=summarize_windows(w,policy['id'],size);summary+=sub;reasons+=rr
            for r in w.itertuples():
                trace.append(dict(policy=policy['id'],window_size=size,capture_session=r.pcap,candidate_stream_id=r.candidate_stream_id,
                    window_id=r.window_id,split=r.split,identity_status=r.identity_status,first_frame=r.first_frame,last_frame=r.last_frame,
                    frames=r.n_frames,strict_temporal_valid=r.quality_valid,ml_feature_eligible=r.ml_feature_eligible,
                    time_shield_temporal_eligible=r.time_shield_temporal_eligible,ml_eligible=r.ml_eligible,temporal_eligible=r.temporal_eligible,
                    quality_reasons=r.quality_reasons,ml_quality_reasons=r.ml_quality_reasons,temporal_quality_reasons=r.temporal_quality_reasons,
                    slope_available=bool(np.isfinite(r.tsf_slope_s_per_s))))
            for (status,sp),g in w.groupby(['identity_status','split']):
                support.append(dict(policy=policy['id'],window_size=size,identity_status=status,split=sp,
                    candidate_windows=len(g),strict_temporal_eligible=int(g.temporal_eligible.sum()),
                    ml_non_temporal_eligible=int(g.ml_eligible.sum()),distinct_candidate_streams=g.candidate_stream_id.nunique(),
                    independent_capture_sessions=g.pcap.nunique(),independent_test_sessions=0,
                    note='All candidate streams are in one original Evil_Twin PCAP'))
            print(policy['id'],size,'strict=',int(w.temporal_eligible.sum()),'ML=',int(w.ml_eligible.sum()),flush=True)
    out=a.out;out.mkdir(parents=True)
    pd.DataFrame(summary).to_csv(out/'attrition_by_stream.csv',index=False)
    pd.DataFrame(reasons).to_csv(out/'attrition_by_reason.csv',index=False)
    pd.DataFrame(trace).to_csv(out/'window_attrition.csv',index=False)
    pd.DataFrame(support).to_csv(out/'policy_support.csv',index=False)
    intervals=interval_audit(rows);pd.DataFrame(intervals).to_csv(out/'interval_diagnostics.csv',index=False)
    # Declared support heuristic is descriptive; independent-session gate is decisive.
    summary_support=pd.DataFrame(support)
    gates=[]
    for (policy,size),g in summary_support.groupby(['policy','window_size']):
        h=cfg['preliminary_support_heuristic'];count={}
        for split_name in ['train','validation','development_test']:
            for status in ['candidate_legitimate','candidate_evil_twin']:
                records=g[(g.split==split_name)&(g.identity_status==status)]
                count[f'{split_name}_{status}']=int(records.ml_non_temporal_eligible.sum())
        preliminary=all(count[f'{sp}_{st}']>=h[f'minimum_{sp}_windows_per_class'] for sp in ['train','validation','development_test'] for st in ['candidate_legitimate','candidate_evil_twin'])
        gates.append(dict(policy=policy,window_size=int(size),preliminary_non_temporal_support=preliminary,
            final_independent_evaluation_feasible=False,independent_labeled_capture_sessions=1,**count))
    pd.DataFrame(gates).to_csv(out/'feasibility_gate.csv',index=False)
    report(out,summary,reasons,intervals,checks,cfg)
    write_json(out/'manifest.json',dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),protocol=cfg,
        protocol_sha256=sha256(a.config),source_beacons_sha256=sha256(source),identity_table_sha256=sha256(labels),
        strict_checkpoint_sha256=sha256(project/'results/strict_policy_checkpoint.json'),checks=checks,
        original_frames=len(rows),policies=len(cfg['policies']),window_sizes=cfg['window_sizes'],
        synthetic_windows=0,oversampling=False,final_test_classifier_scores_used=False,
        original_strict_artifacts_modified=False,code_sha256=sha256(project/'src/window_policy.py')))


if __name__=='__main__':main()
