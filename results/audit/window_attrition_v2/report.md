# Window attrition audit — Evil Twin

This report uses only original AWID3 frames and the previously accepted candidate identity mapping. No oversampling, synthetic windows, test-score-based policy selection or baseline refit occurred.

## Original strict policy (fixed windows; gap factor 1.5)

| Size | Candidate role | Windows | Temporal eligible | ML non-temporal eligible |
|---:|---|---:|---:|---:|
| 10 | candidate_evil_twin | 378 | 89 | 376 |
| 10 | candidate_legitimate | 869 | 752 | 868 |
| 20 | candidate_evil_twin | 190 | 13 | 188 |
| 20 | candidate_legitimate | 435 | 325 | 434 |
| 50 | candidate_evil_twin | 76 | 0 | 74 |
| 50 | candidate_legitimate | 174 | 89 | 173 |

Reason counts overlap when one window has several flags. The detailed breakdown by capture, stream and split is in `attrition_by_reason.csv` and `window_attrition.csv`.

| Size | Candidate role | Capture gap | TSF reset/repeat | Missing/parse | Nonfinite temporal | Incomplete | Mixed/unknown label | Stream/profile change |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 10 | candidate_legitimate | 116 | 0 | 0 | 0 | 1 | 0 | 0 |
| 10 | candidate_evil_twin | 289 | 1 | 0 | 1 | 2 | 0 | 0 |
| 20 | candidate_legitimate | 109 | 0 | 0 | 0 | 1 | 0 | 0 |
| 20 | candidate_evil_twin | 177 | 1 | 0 | 1 | 2 | 0 | 0 |
| 50 | candidate_legitimate | 85 | 0 | 0 | 0 | 1 | 0 | 0 |
| 50 | candidate_evil_twin | 76 | 1 | 0 | 1 | 2 | 0 | 0 |

## Root causes

- The rogue stream has many receive gaps and matching TSF gaps. A 20-frame strict window fails if **any** of its 19 internal intervals, or its incoming boundary, exceeds 1.5 advertised intervals. The chance of retaining long windows falls sharply.
- `interval_diagnostics.csv` counts distinct interval events; `attrition_by_reason.csv` counts windows affected by those events. They have different denominators.
- One observed TSF decrease occurs inside the second Evil Twin profile. No slope is computed for a window spanning it. This is an observed discontinuity; a reboot or attack cause is unverified.
- The Evil Twin capture has no missing beacon fields in the audited streams. Small terminal tails cause incomplete windows. Candidate role windows are not mixed in the default grouping.
- BSSID-only grouping combines two rogue capability profiles and produces one profile-change window at their transition. Stable-profile grouping gives the same three groups as BSSID+capability in these data. Neither rule establishes physical device identity.

## Separate eligibility and sensitivity

ML non-temporal eligibility requires full windows, one accepted candidate role, stable configuration and finite configuration/radio/frame features. It can retain windows with receive gaps or TSF resets because those features do not use temporal continuity. Time-Shield eligibility keeps the strict continuity gate. Temporal features from invalid windows must not be silently imputed into an all-four-group ML model.
The fixed 1.5, 2.0 and 3.0 gap settings; gap-segmented construction; and two alternate grouping rules were specified in `configs/window_sensitivity.json`. Sensitivity tables show available records only. Larger gap thresholds can admit missing-beacon intervals and are not chosen as a new quality standard from test performance.

Recommended quality policy: fixed capture-order windows with BSSID+capability candidate grouping; use ML non-temporal flags for configuration/radio/frame experiments and strict 1.5-gap flags for Time-Shield. Do not compute or use a slope across a TSF reset. Use an explicit missing-temporal indicator only in a separately validated model design, not automatic imputation of invalid temporal features.

## Feasibility gate

See `policy_support.csv` for train/validation/development-test counts for every policy and class. Candidate profile streams are not independent sessions. Under recommended fixed 1.5/non-temporal ML eligibility, the Evil Twin counts are 90/141/144 for size 10, 45/70/72 for size 20, and 18/27/28 for size 50. Size 10 and 20 pass the documented exploratory support heuristic of at least 20/10/10 per class across train/validation/development test; size 50 fails it in train. These counts measure availability, not model performance.
The source has one Evil Twin capture and no independent labeled test session, so **final model comparison and unseen-AP claims are not supported**. A preliminary same-capture study can be considered only for supported policies, clearly labeled as exploratory.
The earlier strict-policy model artifacts and metrics were frozen before this audit in `results/strict_policy_checkpoint.json`; they are exploratory and should not be promoted to final results.

## Verification

- Strict policy windows match previous artifacts: True.
- All input frames conserved per evaluated policy and size: True.
- No overlapping frame membership within a policy/size: True.
- Original strict files retain their recorded SHA-256 hashes: True.
No independent AP/session observations were generated.
