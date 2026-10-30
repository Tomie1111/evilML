# Independent evaluation intake

This directory is intentionally empty of observations. Copy
`session_manifest.template.json` once per real capture and list its relative path in
`session_registry.json`. Do not fill placeholders from model predictions, BSSID assumptions,
or AWID3 attack filters.

Each session manifest must bind the capture and every external evidence file to SHA256 hashes.
Device roles must be `verified_legitimate` or `verified_evil_twin` and must cite evidence IDs.
Intervals must use one of the predeclared scenarios and cite both device and evidence IDs.

For `ssid_bssid_clone`, a passive BSSID match cannot attribute a frame to a physical transmitter.
Such an interval counts toward supervised evaluation only when it uses
`ground_truth_scope: transmitter_identity` and supplies `frame_attribution_evidence_id`, backed
by an external synchronized testbed or packet-injection log. Otherwise retain it as
`ground_truth_scope: event_presence`; it may support operational analysis but not verified
per-window classifier metrics.

Run readiness validation without scoring:

```bash
.venv/bin/python scripts/check_independent_evaluation_readiness.py \
  --out results/independent_evaluation_readiness.json
```

The final gate requires at least two independent sessions containing countable verified
legitimate intervals and two containing countable verified Evil Twin intervals. This is a
session count, not a window count.
