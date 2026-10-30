#!/usr/bin/env python3
"""One validation-only CART pilot after attrition review; no test predictions."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import joblib
import numpy as np
from src.common import sha256, write_json
from src.ml_io import load_windows
from src.feature_ablation import features_for
from src.train_models import select_model, explanation


def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project-root',type=Path,default=project)
    p.add_argument('--out',type=Path,default=project/'models/exploratory_non_temporal_v1')
    a=p.parse_args();project=a.project_root.resolve()
    if a.out.exists():raise FileExistsError(a.out)
    prepared=project/'data/processed/ml_non_temporal_v1'
    manifest=json.loads((prepared/'manifest.json').read_text())
    src=prepared/'window_features_20.csv'
    if sha256(src)!=manifest['output_sha256'][src.name]:raise ValueError('Prepared features changed')
    sensitivity=json.loads((project/'results/audit/window_attrition_v2/manifest.json').read_text())
    if sha256(project/'results/audit/window_attrition_v2/manifest.json')!=manifest['attrition_manifest_sha256']:
        raise ValueError('Attrition gate changed')
    config=json.loads((project/'configs/ml_experiment.yaml').read_text())
    support=json.loads((project/'configs/window_sensitivity.json').read_text())['preliminary_support_heuristic']
    table=load_windows(src);eligible=table[table.ml_eligible]
    train=eligible[eligible.split.eq('train')];validation=eligible[eligible.split.eq('validation')]
    counts={split:{int(k):int(v) for k,v in group.target.value_counts().items()} for split,group in [('train',train),('validation',validation)]}
    for label in (0,1):
        if counts['train'].get(label,0)<support['minimum_train_windows_per_class'] or counts['validation'].get(label,0)<support['minimum_validation_windows_per_class']:
            raise ValueError('Preliminary label support gate failed')
    features=features_for('configuration_radio_frame')
    if any(train[features].isna().any()) or any(validation[features].isna().any()):
        raise ValueError('Non-temporal pilot cannot impute missing features')
    best=select_model(train,validation,features,'decision_tree',config['hyperparameters']['decision_tree'],config['random_seed'],.5)
    a.out.mkdir(parents=True)
    model=a.out/'decision_tree.joblib'
    joblib.dump(dict(pipeline=best['pipeline'],features=features,model='decision_tree',
        window_size=20,policy='non_temporal_fixed_1p5',label_scope='accepted_author_documented_candidate_roles',
        training_window_ids=train.window_id.tolist(),validation_window_ids=validation.window_id.tolist(),
        prepared_manifest_sha256=sha256(prepared/'manifest.json')),model,compress=3)
    reloaded=joblib.load(model)
    scores=reloaded['pipeline'].predict_proba(validation[features])[:,1]
    if not np.allclose(scores,best['pipeline'].predict_proba(validation[features])[:,1],atol=1e-12):
        raise ValueError('Serialized pilot model differs')
    result=dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),status='preliminary_validation_only',
        selected_parameters=best['params'],validation_metrics=best['validation_metrics'],
        train_class_counts=counts['train'],validation_class_counts=counts['validation'],
        feature_groups=['configuration','radio','frame'],features=features,
        transformed_explanation=explanation(best['pipeline']),validation_search=best['search_log'],
        independent_training_sessions=1,independent_test_sessions=0,physical_identity_verified=False,
        development_test_scores_computed=False,final_model_comparison_performed=False,
        label_provenance='author-documented candidate AP roles, user-accepted preliminary protocol',
        source_features_sha256=sha256(src),model_sha256=sha256(model),
        caution='Validation windows share a capture and APs with training. Metrics are exploratory and may reflect device configuration shortcuts.')
    write_json(a.out/'validation_only.json',result)
    rows=validation[['window_id','split','pcap','candidate_stream_id','identity_status','label_provenance','target','quality_valid','ml_eligible','time_shield_temporal_eligible']].copy()
    rows['score']=scores;rows['prediction']=(scores>=.5).astype(int)
    rows.to_csv(a.out/'validation_predictions.csv',index=False,float_format='%.17g')
    print(json.dumps({k:result[k] for k in ['status','selected_parameters','validation_metrics','train_class_counts','validation_class_counts','development_test_scores_computed']},indent=2))


if __name__=='__main__':main()
