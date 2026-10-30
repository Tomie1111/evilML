"""Train-only pipelines; one held-out chronological validation split for selection."""
import time
import warnings
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import ParameterGrid
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from .evaluate_models import evaluate
from .preprocessing import validate_feature_names
from .window_aggregation import CATEGORICAL


def make_pipeline(model_name, features, parameters, seed):
    features = validate_feature_names(features)
    categorical = [c for c in features if c in CATEGORICAL]
    numeric = [c for c in features if c not in CATEGORICAL]
    transformers = []
    if numeric:
        numeric_steps = [('impute', SimpleImputer(strategy='median', keep_empty_features=True))]
        if model_name == 'logistic_regression': numeric_steps.append(('scale', StandardScaler()))
        transformers.append(('numeric', Pipeline(numeric_steps), numeric))
    if categorical:
        transformers.append(('categorical', Pipeline([
            ('impute', SimpleImputer(strategy='constant', fill_value='MISSING', keep_empty_features=True)),
            ('encode', OneHotEncoder(handle_unknown='ignore', sparse_output=False))]), categorical))
    if model_name == 'decision_tree': model = DecisionTreeClassifier(random_state=seed, **parameters)
    elif model_name == 'random_forest': model = RandomForestClassifier(random_state=seed, n_jobs=-1, **parameters)
    elif model_name == 'logistic_regression': model = LogisticRegression(max_iter=2000, random_state=seed, **parameters)
    else: raise ValueError(model_name)
    return Pipeline([('preprocess', ColumnTransformer(transformers, remainder='drop')), ('model', model)])


def select_model(train, validation, features, model_name, grid, seed=42, threshold=0.5):
    if set(train.target.astype(int)) != {0, 1} or set(validation.target.astype(int)) != {0, 1}:
        raise ValueError('Both classes required in train and validation')
    best = None; best_f1 = -1; log = []
    for i, params in enumerate(ParameterGrid(grid)):
        pipeline = make_pipeline(model_name, features, params, seed)
        start = time.perf_counter()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            pipeline.fit(train[features], train.target.astype(int))
        elapsed = time.perf_counter() - start
        score = pipeline.predict_proba(validation[features])[:, 1]
        metrics, _ = evaluate(validation.target, score, threshold)
        log.append(dict(candidate_index=i, parameters=params, fit_seconds=elapsed,
            validation_precision=metrics['precision'], validation_recall=metrics['recall'], validation_f1=metrics['f1'],
            warnings=[str(w.message) for w in caught]))
        if metrics['f1'] > best_f1:
            best_f1 = metrics['f1']
            best = dict(pipeline=pipeline, params=params, fit_seconds=elapsed, validation_metrics=metrics,
                        candidate_index=i, warnings=log[-1]['warnings'])
    best['search_log'] = log
    best['train_only_constant_features'] = [c for c in features if train[c].nunique(dropna=False) == 1]
    return best


def explanation(pipeline):
    names = pipeline.named_steps['preprocess'].get_feature_names_out().tolist()
    model = pipeline.named_steps['model']
    if hasattr(model, 'feature_importances_'):
        weights = model.feature_importances_.tolist(); kind = 'impurity_feature_importance'
    else:
        weights = model.coef_[0].tolist(); kind = 'logistic_coefficient_after_train_only_preprocessing'
    return dict(kind=kind, transformed_features=names, weights=weights,
        tree_depth=int(model.get_depth()) if hasattr(model, 'get_depth') else None,
        leaf_count=int(model.get_n_leaves()) if hasattr(model, 'get_n_leaves') else None,
        note='Configuration importance may reflect same-device shortcuts; not causal attack evidence')
