# Evil Twin Detection Research

Current milestone: **Time-Shield/fusion engineering validation; verified operational evaluation awaiting evidence**.
The user accepted [the preliminary labeling protocol](labeling_protocol_accepted.md)
provided no results are fabricated. The original audit remains immutable. An
earlier strict-policy exploratory model run exists; it was frozen in
`results/strict_policy_checkpoint.json` before the attrition work and must not
be reported as a final comparison. The author documentation supports candidate
dataset roles, without independent device identification.

## Environment

Python 3.11+; the initial dataset audit uses the standard library. Window
analysis uses pinned NumPy, pandas and pytest in `requirements-ml.txt`.
TShark and capinfos are required for PCAP verification. Their paths are resolved from PATH, then from
the macOS Wireshark app, or can be configured explicitly. No decryption keys are
read by our Python code, and WLAN decryption is explicitly disabled in TShark.

```bash
cd evilML/evil-twin-detection
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

The configuration is JSON-form YAML 1.2, readable with the standard library.
`dataset_root` is relative to `configs/experiment.yaml`. Override with
`--dataset-root /your/dataset` for relocated data. No username or dataset absolute
path is embedded in source/config. Recorded commands include resolved input paths
for provenance, which are naturally machine-specific.

## Exact commands

The initial commands used for the checked-in local results:

```bash
python3 scripts/extract_audit_inputs.py
python3 -m src.dataset_audit
python3 -m unittest discover -s tests -v
python3 scripts/verify_audit.py
```

Extraction inventories all `.pcap`/`.pcapng` files in `pcaps`, including full
SHA256 and packet counts. It re-extracts complete Beacon tables and replays the
literal `Read_me.txt` attack filters for the two configured captures. PCAP bytes
are streamed by Wireshark; only the much smaller CSV evidence is loaded in Python.
Packet-level subtype/fields of other captures remain uninspected and their beacon
counts are explicitly unknown.

Outputs refuse to overwrite nonempty directories. To repeat, choose new paths:

```bash
python3 scripts/extract_audit_inputs.py --out data/raw/repeat-01
python3 -m src.dataset_audit --extractions data/raw/repeat-01 --out results/audit-repeat-01
```

To recompute reports from the saved, hash-checked extraction (without another PCAP
scan):

```bash
python3 -m src.dataset_audit --extractions data/raw/audit --out results/audit-repeat-02
```

Config and input checksums are retained. Changing config requires a fresh
extraction manifest, even for a policy-only edit. Full PCAP hashes refer to the
extraction run; immutable original files are assumed thereafter. A full repeat
recomputes them. Runtime timestamps differ between report runs by design.

## Code and output map

| File | Responsibility |
|---|---|
| `scripts/extract_audit_inputs.py` | Original PCAP inventory, hashes, subtype-confirmed Beacon and filter extraction |
| `src/pcap_tools.py` | Configurable Wireshark subprocess tools and field registry |
| `src/dataset_audit.py` | Schemas, missingness, CSV/PCAP joins, audit reports |
| `src/label_validation.py` | Unique capture/frame joins; candidate/verified/unknown distinction; training gate |
| `src/feature_extraction.py` | Feature availability and stream diagnostics; sequence wrap, RSSI, stable IE helpers |
| `src/preprocessing.py` | Predictive feature allowlist; exploratory model pipelines fit encoders/scalers on train only |
| `configs/identity_evidence.json` | Primary author-documentation evidence and its limits |

Required outputs under `results/audit/`:

- `dataset_audit.json`: file schemas/types, counts, hashes, versions, field coverage,
  source evidence, integrity checks and gate result.
- `label_distribution.csv`, `label_provenance.csv`: original label families,
  candidate identity interpretation and provenance kept separate.
- `feature_availability.csv`: actual source-field availability/missingness,
  proposed extraction methods, independent-capture limitations and eligibility.
- `data_quality_report.md`: verified observations, assumptions and unresolved issues.

Additional evidence includes complete per-frame join audits, filter replay audits,
`full_capture_inventory.csv`, `identity_label_audit.csv`, `flagged_beacons.csv`,
`stream_quality.csv`, `configuration_shortcut_audit.csv`,
`previous_time_shield_overlap.csv`, `forbidden_features.csv`, and `training_gate.json`.

## Tests and next milestones

Window attrition workflow (the original strict window files must already exist):

```bash
python3 scripts/audit_window_attrition.py
python3 scripts/build_ml_quality_windows.py
python3 -m pytest tests -q
```

The checked result is `results/audit/window_attrition_v2/report.md`; the
earlier v1 report is retained as a development trace. `data/processed/ml_non_temporal_v1/`
contains separate ML and Time-Shield eligibility flags plus masked temporal
values for windows that fail the temporal gate. It does not contain newly fitted
models. The fixed 1.5 strict windows and the exploratory model outputs remain
under their original paths. The recommended ML-only policy uses configuration,
radio and frame features; Time-Shield keeps the original temporal gate.

A CART pilot on the new size-20 non-temporal features is stored at
`models/exploratory_non_temporal_v1/validation_only.json`. It was fitted on
train and selected on validation only. Its validation F1 is 1.0 on the accepted
candidate labels, but its tree relies almost entirely on one IE-structure
indicator. This is a same-capture configuration shortcut, not proof of
independent-device detection. No development-test scores were computed.

An independent labeled capture is still required for a final model comparison
or unseen-AP claim. The existing strict exploratory outputs show why this gate
matters: only 2 Evil Twin size-20 windows were eligible in train. The new
non-temporal table has 45/70/72 across train/validation/development-test for
size 20, all from one original capture. Size 50 has 18/27/28 and fails the
documented exploratory train-count heuristic of 20 positive windows.

The predeclared same-capture follow-up for sizes 10 and 20 is stored under
`results/preliminary_non_temporal_v1/`, with frozen artifacts under
`models/preliminary_non_temporal_v1/`. Run it on a clean output path with:

```bash
.venv/bin/python scripts/run_non_temporal_exploratory.py
.venv/bin/python scripts/benchmark_non_temporal.py
.venv/bin/python scripts/plot_non_temporal_results.py
```

The checked run exposes a material configuration shift: all Evil Twin
development-test windows contain several categorical values unseen in train.
Size-10 CART and Random Forest and size-20 Random Forest therefore have
development-test Evil Twin recall 0, while Logistic Regression and some
size-20 ablations score 1.0 using highly separable RSSI/frame-length conditions.
These are useful shortcut diagnostics, not final performance claims. See
`results/preliminary_non_temporal_v1/report_th.md` for the full interpretation.

`scripts/verify_audit.py` writes `results/verification.json` and its test log.
It repeats the audit in a temporary directory, checks deterministic outputs,
verifies overwrite protection and checks the original Time-Shield against its
packaged reference. Use a new `--out` path to repeat verification. The early
diagnostic report is retained in `results/audit_initial/`; `results/audit/` is the
current report and explicitly separates canonical integrity from supplemental
raw CSV omissions.

Unit tests cover composite-key uniqueness, unknown handling, exact timestamps,
PCAP comparison, label gating, feature allowlisting, sequence wraparound, antenna
RSSI, IE normalization and reset/gap detection. Small unit fixtures are isolated
from research outputs; no synthetic experiment data or metrics are produced.
Tests also cover window construction, split/preprocessing, temporal states,
fusion rules and the separate ML/Time-Shield quality policy.

Next: obtain a separate, independently labeled AP/session capture to assess
generalization. The new non-temporal windows permit an explicitly exploratory
same-capture ML study for sizes 10 and 20, but final model comparison remains
blocked by the lack of independent sessions. Do not use the existing strict
exploratory model scores to select the quality policy. Independent evaluation
requires frozen model artifacts and evidence bound to the new capture; it cannot
be manufactured from the existing Evil_Twin PCAP.

## Independent evaluation intake

The next-stage interface is implemented without inventing observations. Its empty registry,
manifest template and evidence requirements are under `data/independent/`. Check readiness with:

```bash
.venv/bin/python scripts/check_independent_evaluation_readiness.py \
  --out results/independent_evaluation_readiness-repeat.json
```

The checked status is `results/independent_evaluation_readiness.json`: zero independent sessions,
so scoring is blocked and no models were loaded. The validator binds capture and external evidence
files to hashes, checks frozen artifact integrity, rejects development-capture reuse, and does not
count cloned-BSSID intervals without external frame attribution. See
`results/independent_evaluation_readiness_th.md` for the current Thai summary.

Repeat the attrition analysis with a new output path, for example:
`python3 scripts/audit_window_attrition.py --out results/audit/window_attrition_repeat`.
The original v2 report and strict artifacts are protected against overwrite.
`scripts/train_non_temporal_pilot.py` is validation-only and also refuses to
overwrite its existing output directory.

The earlier `time_shield`, `time_shield_calibration` and `awid3_attack_audit_complete`
directories are external research inputs; this milestone does not rewrite them.

## Operational validation v1

See `results/operational_validation_v1/report_th.md` for the Thai operational audit,
D3 methodology text and exact data blockers. `completion_matrix.csv` distinguishes
implemented mechanics from completed experiments. The audit found no verified
legitimate enrollment windows; historical candidate-role baselines are not promoted
to verified trusted enrollment. Consequently actual drift-score distributions and
covariance sensitivity remain blocked. Candidate feature distributions and quality
coverage are provided with their provenance, and all no-baseline states are UNAVAILABLE.

New engineering entry points:

- `src/trusted_temporal.py`: reviewed device/window evidence, chronological enrollment,
  frozen baseline monitoring, invalid-window persistence reset.
- `src/decision_fusion.py`: separate ML and temporal eligibility; 120 tested rule combinations.
- `src/external_inference.py`: checksum-verified frozen preprocessing/inference and
  null attack metrics for legitimate-only observations.
- `scripts/import_external_pcap.py`: unlabeled streaming Beacon extraction and field audit.

Commands (each output directory must be new):

```bash
.venv/bin/python scripts/validate_operations_v1.py --out results/operational_validation_v2
.venv/bin/python scripts/import_external_pcap.py --pcap /path/to/new-session.pcapng --out data/independent/import_session_01
```

The importer does not verify physical identity or assign labels. An external PCAP
has not yet been registered or imported; actual field compatibility, lineage and
frame attribution remain to be checked. Capture hashes reject byte-identical reuse
but cannot prove independence of cropped or re-exported captures. Independent
session/device evidence requires researcher review before scoring experimental metrics.
