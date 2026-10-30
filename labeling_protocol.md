# Proposed labeling protocol: awid3-author-role-v1

Status: **proposed; not approved; not used to train a model**.

This protocol is the concrete review item required by the user's master prompt §4.3.
It does not alter the labels or assumptions of the earlier Time-Shield work.

## Evidence and scope

The AWID3 author paper, DOI `10.1109/ACCESS.2021.3061609`, section III-B
“Evil_Twin”, describes distinct legitimate/rogue MAC suffixes and the same AP
configuration for the second implementation. The local `Read_me.txt` supplies
the full rogue address in its filter. The existing builder combines this evidence
into capture-specific AP role annotations. Direct PCAP replay can verify the
observations and filter matches, but cannot independently authenticate transmitters.

Source and access details are in `configs/identity_evidence.json` and the audit
manifest. The proposed interpretation is **author-documented dataset identity**,
not independently observed physical identity or proof of attack success.

## Proposed training labels if accepted

Only original capture `pcaps/7. Evil_Twin.pcap` is eligible:

| Existing annotation + documented BSSID | Audit identity status | Proposed target |
|---|---|---|
| NORMAL + `0c:9d:92:54:fe:34` | candidate_legitimate | 0, legitimate dataset role |
| EVIL_TWIN + `0c:9d:92:54:fe:35` | candidate_evil_twin | 1, Evil Twin dataset role |
| Missing/conflicting evidence, unknown role, or other capture | unknown | excluded |

Both observed rogue profiles remain the same positive role; profile IDs are
reporting/grouping metadata, never class features or tool identity labels.
The 65 candidate rogue beacons preceding the first matched attack-filter beacon
would retain the proposed positive identity target, rather than being relabeled
normal. This is an explicit identity-vs-filter assumption to accept or revise.

Retain all original attack labels and their filter status independently. Exclude
the entire `Rogue_AP` capture from supervised identity training in this protocol:
same-BSSID observations do not identify the physical emitter. Exclude malformed,
truncated or otherwise quality-invalid observations according to a fixed policy.

## Window policy and evaluation scope

Use capture-specific candidate streams and non-overlapping windows of 10/20/50
beacons. All frames in a labeled window must share the accepted role and evidence
scope. Any unknown or mixed identity produces an unlabeled window. Reject incomplete
windows, nonpositive time deltas, TSF resets and configured large gaps; retain them
in quality/coverage reports. Do not silently repair or interpolate them.

Validate chronological split membership and both-class support **before training**.
Use the same split for all models and ablations. Never choose boundaries based on
model scores. A split by physical AP cannot be claimed here: only one candidate
legitimate AP and one candidate rogue address in one session are available.
Never use frame-random splitting or treat derived CSV/pcapng copies as new sessions.

Fit encoders/scalers/imputers on train only. Lock model selection using validation
only; a final independent session must remain separate. Existing Time-Shield
holdout has already been examined and is not an untouched research test.

Metrics under this protocol must say **agreement with author-documented dataset
roles on a preliminary same-capture split**. They do not establish unseen-AP
generalization, physical transmitter identification, or detection of successful
credential theft. Do not report independently verified normal-class FPR until
suitable labels exist. A candidate-role false-alarm fraction, if later measured,
must be explicitly named and include its denominator and provenance.

## How to resolve the gate

1. Accept this capture-specific, author-documented protocol for preliminary
   development. Record the explicit acceptance and protocol hash in a new version
   of the experiment configuration; keep candidate status/provenance visible.
2. Alternatively, provide device/event logs or a controlled independently labeled
   session to establish verified classes. Bind evidence to capture/session and
   original frame/time ranges; do not generate labels from model predictions.

Neither choice authorizes automatic relabeling of other captures or claiming an
independent test. Until one is resolved, this implementation performs audit only.
