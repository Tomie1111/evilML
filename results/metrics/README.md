# Status of existing model outputs

`model_comparison.csv`, `feature_ablation.csv`, saved models and predictions
were generated under the original combined strict temporal quality gate before
the user's window-attrition instruction. They are frozen exploratory,
same-capture development results. Their hashes are recorded in
`../strict_policy_checkpoint.json`; no additional final model comparison was
run after the attrition review.

The subsequent quality review is in `../audit/window_attrition_v2/`. It shows
that strict filtering leaves only 2 Evil Twin training windows at size 20 and
none at size 50. Do not use these model scores to choose a new quality policy
or claim independent-AP performance. The recommended non-temporal ML dataset
has separate eligibility flags under `../../data/processed/ml_non_temporal_v1/`.
It has not been used for a final model comparison. An independent labeled
session is required for that evaluation.

A separate validation-only CART pilot using the new non-temporal eligibility
is under `../../models/exploratory_non_temporal_v1/`. It has no development-test
predictions and does not change the frozen strict comparison files.
