#!/usr/bin/env python3
"""Preliminary same-capture comparison after the attrition gate."""
import argparse
import importlib.metadata
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import joblib
import numpy as np
import pandas as pd
from src.common import sha256, write_json
from src.evaluate_models import evaluate, prediction_table
from src.ml_io import load_windows
from src.preprocessing import FEATURE_GROUPS
from src.train_models import explanation, select_model
from src.window_aggregation import CATEGORICAL

CONFIG_NO_IE=[f for f in FEATURE_GROUPS['configuration'] if f!='stable_ie_structure_encoded']
GROUPS={
    'configuration':FEATURE_GROUPS['configuration'],
    'configuration_without_ie':CONFIG_NO_IE,
    'radio':FEATURE_GROUPS['radio'],
    'frame':FEATURE_GROUPS['frame'],
}

def ablation_features(groups):
    result=[]
    for group in groups:
        result.extend(GROUPS[group])
    return result

def novelty(train,test,features):
    rows=[]
    for feature in [f for f in features if f in CATEGORICAL]:
        known=set(train[feature].astype(str)); values=test[feature].astype(str)
        unseen=~values.isin(known)
        for status,group in test.assign(_unseen=unseen).groupby('identity_status'):
            rows.append(dict(feature=feature,identity_status=status,windows=len(group),
                unseen_windows=int(group._unseen.sum()),unseen_fraction=float(group._unseen.mean()),
                train_categories=len(known),test_categories=group[feature].astype(str).nunique()))
    return rows

def main():
    project=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project-root',type=Path,default=project)
    p.add_argument('--protocol',type=Path,default=project/'configs/non_temporal_exploratory.json')
    p.add_argument('--out',type=Path,default=project/'results/preliminary_non_temporal_v1')
    p.add_argument('--models-out',type=Path,default=project/'models/preliminary_non_temporal_v1')
    a=p.parse_args();project=a.project_root.resolve()
    if a.out.exists() or a.models_out.exists():raise FileExistsError('Preliminary output exists')
    protocol=json.loads(a.protocol.read_text())
    if not protocol['declared_before_development_test_evaluation'] or not protocol['no_oversampling'] or not protocol['no_smote']:
        raise ValueError('Protocol gate failed')
    prepared=project/'data/processed/ml_non_temporal_v1'
    prepared_manifest=json.loads((prepared/'manifest.json').read_text())
    mlcfg=json.loads((project/'configs/ml_experiment.yaml').read_text())
    support_cfg=json.loads((project/'configs/window_sensitivity.json').read_text())['preliminary_support_heuristic']
    experiments=[]
    for size in protocol['window_sizes']:
        for model in protocol['models']:
            experiments.append((size,model,'configuration_radio_frame',ablation_features(protocol['ablations']['configuration_radio_frame'])))
    for name,groups in protocol['ablations'].items():
        if name!='configuration_radio_frame':
            experiments.append((20,protocol['ablation_model'],name,ablation_features(groups)))
    a.out.mkdir(parents=True);a.models_out.mkdir(parents=True)
    selected={};searches=[];novelty_rows=[];tables={}
    for size in protocol['window_sizes']:
        path=prepared/f'window_features_{size}.csv'
        if sha256(path)!=prepared_manifest['output_sha256'][path.name]:raise ValueError('Prepared feature hash changed')
        table=load_windows(path);tables[size]=table[table.ml_eligible].copy()
    for size,model,name,features in experiments:
        table=tables[size];train=table[table.split.eq('train')];validation=table[table.split.eq('validation')]
        for split_name,group,minimum in [('train',train,support_cfg['minimum_train_windows_per_class']),('validation',validation,support_cfg['minimum_validation_windows_per_class'])]:
            if min(int(group.target.eq(0).sum()),int(group.target.eq(1).sum()))<minimum:
                raise ValueError(f'{size} {split_name} class support failed')
        if train[features].isna().any().any() or validation[features].isna().any().any():
            raise ValueError('Non-temporal experiment cannot impute missing source features')
        identifier=f'n{size}_{model}_{name}'
        best=select_model(train,validation,features,model,mlcfg['hyperparameters'][model],mlcfg['random_seed'],protocol['threshold'])
        artifact=a.models_out/f'{identifier}.joblib'
        bundle=dict(pipeline=best['pipeline'],features=features,window_size=size,model=model,ablation=name,
            parameters=best['params'],training_window_ids=train.window_id.tolist(),validation_window_ids=validation.window_id.tolist(),
            source_features_sha256=prepared_manifest['output_sha256'][f'window_features_{size}.csv'],
            protocol_sha256=sha256(a.protocol),scope=protocol['scope'])
        joblib.dump(bundle,artifact,compress=3)
        restored=joblib.load(artifact)
        original=best['pipeline'].predict_proba(validation[features])[:,1]
        loaded=restored['pipeline'].predict_proba(validation[features])[:,1]
        if not np.allclose(original,loaded,rtol=1e-12,atol=1e-12):raise ValueError('Serialization mismatch')
        selected[identifier]=dict(window_size=size,model=model,ablation=name,features=features,
            parameters=best['params'],validation_metrics=best['validation_metrics'],validation_search_index=best['candidate_index'],
            train_counts={str(v):int(train.target.eq(v).sum()) for v in (0,1)},
            validation_counts={str(v):int(validation.target.eq(v).sum()) for v in (0,1)},
            artifact=str(artifact.relative_to(project)),artifact_sha256=sha256(artifact),model_size_bytes=artifact.stat().st_size,
            explanation=explanation(best['pipeline']),constant_train_features=best['train_only_constant_features'])
        for row in best['search_log']:searches.append(dict(experiment_id=identifier,**row))
        print('selected',identifier,best['validation_metrics']['f1'],flush=True)
    # Selection is frozen before any development-test score is computed.
    selection=dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),protocol=protocol,protocol_sha256=sha256(a.protocol),
        prepared_manifest_sha256=sha256(prepared/'manifest.json'),selected=selected,
        development_test_opened=False,final_model_comparison=False,independent_sessions=0)
    selection_path=a.models_out/'selection_manifest.json';write_json(selection_path,selection)
    rows=[];reports={}
    for identifier,meta in selected.items():
        table=tables[meta['window_size']];train=table[table.split.eq('train')];test=table[table.split.eq('development_test')]
        if min(int(test.target.eq(0).sum()),int(test.target.eq(1).sum()))<support_cfg['minimum_development_test_windows_per_class']:
            raise ValueError('Development-test support gate failed')
        bundle=joblib.load(project/meta['artifact']);score=bundle['pipeline'].predict_proba(test[bundle['features']])[:,1]
        metrics,report=evaluate(test.target,score,protocol['threshold'])
        rows.append(dict(experiment_id=identifier,window_size=meta['window_size'],model=meta['model'],ablation=meta['ablation'],
            feature_count=len(meta['features']),model_size_bytes=meta['model_size_bytes'],evaluation_scope=protocol['scope'],**metrics))
        reports[identifier]=dict(validation=meta['validation_metrics'],development_test=report,
            train_counts=meta['train_counts'],validation_counts=meta['validation_counts'],
            development_test_counts={str(v):int(test.target.eq(v).sum()) for v in (0,1)},
            independent_test=False,physical_identity_verified=False)
        prediction_table(test,score,protocol['threshold']).to_csv(a.out/f'{identifier}_predictions.csv',index=False,float_format='%.17g')
        novelty_rows.extend(dict(experiment_id=identifier,window_size=meta['window_size'],**r) for r in novelty(train,test,meta['features']))
        print('tested',identifier,metrics['f1'],flush=True)
    result=pd.DataFrame(rows)
    result[result.ablation.eq('configuration_radio_frame')].to_csv(a.out/'model_comparison.csv',index=False)
    result[(result.window_size.eq(20))&(result.model.eq(protocol['ablation_model']))].to_csv(a.out/'feature_ablation.csv',index=False)
    pd.DataFrame(novelty_rows).to_csv(a.out/'categorical_novelty.csv',index=False)
    write_json(a.out/'classification_reports.json',reports);write_json(a.out/'validation_search.json',searches)
    write_json(a.out/'manifest.json',dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),protocol=protocol,
        protocol_sha256=sha256(a.protocol),selection_manifest_sha256=sha256(selection_path),
        random_seed=mlcfg['random_seed'],
        runtime=dict(python=sys.version,platform=platform.platform(),packages={name:importlib.metadata.version(name)
            for name in ['numpy','pandas','scikit-learn','scipy','joblib']}),
        inputs=dict(prepared_manifest=str((prepared/'manifest.json').relative_to(project)),
            prepared_manifest_sha256=sha256(prepared/'manifest.json'),
            window_features={f'window_features_{size}.csv':prepared_manifest['output_sha256'][f'window_features_{size}.csv']
                for size in protocol['window_sizes']}),
        selection_frozen_before_test=True,development_test_opened_once_by_this_run=True,
        results_sha256={'model_comparison.csv':sha256(a.out/'model_comparison.csv'),'feature_ablation.csv':sha256(a.out/'feature_ablation.csv'),
            'categorical_novelty.csv':sha256(a.out/'categorical_novelty.csv')},
        no_oversampling=True,no_smote=True,independent_test_sessions=0,final_model_comparison=False,
        limitation='Same original capture; AP identity candidate roles; configuration shortcut risk'))
    print(result[['experiment_id','precision','recall','f1','support_legitimate','support_evil_twin']].to_string(index=False))

if __name__=='__main__':main()
