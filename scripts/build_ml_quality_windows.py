#!/usr/bin/env python3
"""Prepare non-temporal ML tables under the documented, post-attrition policy."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import numpy as np
import pandas as pd
from src.common import read_csv, sha256, unique_index, write_json
from src.dataset_splitting import assign_splits
from src.pcap_tools import BASE_FIELDS, EXTRA_FIELDS
from src.window_policy import evaluate_policy
from src.preprocessing import FEATURE_GROUPS


def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project-root',type=Path,default=project)
    p.add_argument('--out',type=Path,default=project/'data/processed/ml_non_temporal_v1')
    a=p.parse_args();project=a.project_root.resolve()
    if a.out.exists():raise FileExistsError(a.out)
    sensitivity=project/'results/audit/window_attrition_v2'
    attrition=json.loads((sensitivity/'manifest.json').read_text())
    cfg=json.loads((project/'configs/ml_experiment.yaml').read_text())
    source=project/cfg['source_beacons'];labels=project/cfg['audited_identities']
    if sha256(source)!=attrition['source_beacons_sha256'] or sha256(labels)!=attrition['identity_table_sha256']:
        raise ValueError('Source data changed since attrition audit')
    acceptance=json.loads((project/'configs/label_protocol_acceptance.json').read_text())
    if acceptance['status']!='accepted_for_preliminary_dataset_role_training':raise ValueError('Protocol acceptance missing')
    mapping=unique_index(read_csv(labels));fields=BASE_FIELDS|EXTRA_FIELDS
    rows=[]
    for raw in read_csv(source):
        r=dict(pcap=cfg['canonical_pcap'],**{fields[k]:v for k,v in raw.items()})
        lab=mapping[(r['pcap'],int(r['frame_number']))]
        r.update(identity_status=lab['identity_status'],identity_evidence_id=lab['identity_evidence_id'])
        rows.append(r)
    split=json.loads((project/'data/splits/split_manifest.json').read_text())
    cutoffs=(split['train_end_ns'],split['validation_end_ns'])
    temporal=FEATURE_GROUPS['temporal']
    out=a.out;out.mkdir(parents=True)
    summary=[];hashes={}
    trace=pd.read_csv(sensitivity/'window_attrition.csv')
    for size in (10,20,50):
        windows,members=evaluate_policy(rows,size,'bssid_capabilities',1.5,'fixed')
        w=assign_splits(pd.DataFrame(windows),cutoffs)
        w['ml_eligible']=w.ml_feature_eligible&w.split.ne('boundary_excluded')
        w['temporal_eligible']=w.time_shield_temporal_eligible&w.split.ne('boundary_excluded')
        discarded=~w.time_shield_temporal_eligible
        w.loc[discarded,temporal]=np.nan
        frozen=trace[(trace.policy=='strict_fixed_1p5')&(trace.window_size==size)]
        check=w[['window_id','ml_eligible','temporal_eligible']].merge(
            frozen[['window_id','ml_eligible','temporal_eligible']],on='window_id',suffixes=('_new','_audit'),validate='one_to_one')
        if len(check)!=len(w) or not all(check[f'{c}_new'].equals(check[f'{c}_audit']) for c in ['ml_eligible','temporal_eligible']):
            raise ValueError('ML/temporal eligibility differs from attrition audit')
        path=out/f'window_features_{size}.csv';w.to_csv(path,index=False,float_format='%.17g')
        hashes[path.name]=sha256(path)
        for (sp,status),g in w.groupby(['split','identity_status']):
            summary.append(dict(window_size=size,split=sp,identity_status=status,candidate_windows=len(g),
                ml_non_temporal_eligible=int(g.ml_eligible.sum()),time_shield_temporal_eligible=int(g.temporal_eligible.sum()),
                independent_capture_sessions=g.pcap.nunique()))
    pd.DataFrame(summary).to_csv(out/'support.csv',index=False)
    write_json(out/'manifest.json',dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
        source_beacons_sha256=sha256(source),identity_table_sha256=sha256(labels),
        attrition_manifest_sha256=sha256(sensitivity/'manifest.json'),output_sha256=hashes,
        grouping='bssid_capabilities',construction='fixed',gap_factor_for_temporal=1.5,
        ml_feature_groups=['configuration','radio','frame'],
        temporal_feature_policy='Set temporal features to missing where Time-Shield eligibility fails; do not use them for non-temporal ML training',
        original_strict_files_unchanged=True,independent_test_sessions=0,oversampling=False,
        model_training_or_final_comparison_performed=False))
    print(pd.DataFrame(summary).to_string(index=False))


if __name__=='__main__':main()
