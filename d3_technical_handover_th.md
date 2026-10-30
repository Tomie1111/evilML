# D3 Technical and Experimental Handover — Evil Twin Detection

เอกสารนี้เป็น technical handover สำหรับนำไปเขียน D3 ภายหลัง ไม่ใช่ manuscript และไม่ใช่ผลประเมินขั้นสุดท้าย ทุกข้อความสำคัญระบุสถานะเป็น **MEASURED RESULT**, **IMPLEMENTED DESIGN**, **PROPOSED METHOD** หรือ **LIMITATION / NOT YET VALIDATED** แหล่งหลักฐานแบบค้นหาได้อยู่ใน `d3_evidence_index.csv` และสถานะองค์ประกอบอยู่ใน `d3_completion_matrix.csv`

## 1. Executive Summary

**MEASURED RESULT.** โครงการตรวจสอบ AWID3 PCAP 14 ไฟล์และสกัด Beacon เต็มจาก `7. Evil_Twin.pcap` 12,461 เฟรมกับ `4. Rogue_AP.pcap` 6,946 เฟรม งาน supervised preliminary ใช้ Evil Twin capture เพียง session เดียว โดยมี `candidate_legitimate` 8,685 เฟรมและ `candidate_evil_twin` 3,776 เฟรม ไม่มี `verified_legitimate` หรือ independent test session

**IMPLEMENTED DESIGN.** ระบบประกอบด้วย streaming PCAP extraction, evidence-aware labels, candidate AP stream grouping, non-overlapping windows 10/20/50 Beacons, fingerprint สี่กลุ่ม, ML สามแบบ, Time-Shield และ four-state decision fusion ระบบแยก `ml_eligible` ออกจาก `time_shield_temporal_eligible` เพื่อรักษา configuration/radio/frame features เมื่อ temporal continuity ใช้ไม่ได้

**MEASURED RESULT.** Preliminary non-temporal ML แสดงผลต่างกันรุนแรงระหว่างโมเดล: n10 CART/RF/LR มี development F1 เท่ากับ 0/0/1 และ n20 เท่ากับ 1/0/1 Configuration-only n20 CART ได้ F1=0 ขณะที่ radio-only และ frame-only ได้ F1=1 ผลนี้สัมพันธ์กับ configuration novelty, RSSI และ frame-length shortcuts และไม่รองรับการเลือก final classifier

**MEASURED RESULT.** Time-Shield exploratory v2.1 ใช้ candidate legitimate n20 จำนวน 120 valid windows สำหรับ enrollment และ 104 windows ช่วงถัดไปสำหรับ calibration โดยมี 72 valid smoothed calibration scores ค่า primary Mahalanobis threshold p99=7.334245, `beta=0.3`, `K=3`, shrinkage=0.1 Validation ให้ STABLE/DRIFT/UNAVAILABLE=37/0/49 และ development-test=32/0/55 ผลนี้วัด temporal consistency ของ candidate AP ภายใน capture เดียว ไม่ใช่ Evil Twin detection performance

**LIMITATION / NOT YET VALIDATED.** Final FPR, false alerts/AP-hour, verified Time-Shield baseline, fusion accuracy, cross-dataset performance และ unseen-AP generalization ยังวัดไม่ได้จนกว่าจะมี independently captured PCAP พร้อม device/event evidence และ exposure duration

## 2. Project Objectives and Architecture

วัตถุประสงค์คือประเมินว่าการตรวจแบบ passive โดยใช้ multi-factor AP fingerprint ร่วมกับ temporal drift ช่วยคัดกรอง Evil Twin ได้หรือไม่ ภายใต้ข้อจำกัดว่าต้องไม่ใช้ BSSID, SSID หรือ attack filter เป็นหลักฐาน physical identity โดยอัตโนมัติ

**IMPLEMENTED DESIGN.** Data flow ที่ใช้งานจริงคือ:

`PCAP -> TShark Beacon table -> label/evidence audit -> candidate stream -> non-overlapping window -> separate quality gates -> frozen ML score + Time-Shield state -> four-state decision`

ML ใช้ configuration+radio+frame features ส่วน Time-Shield ใช้ temporal vector สามมิติ Decision fusion ให้ผล `Consistent with Trusted Baseline`, `Evil Twin Suspected`, `Suspicious Trusted AP` หรือ `Pending` ซึ่งเป็น operational decisions แยกจาก ground truth

## 3. Implementation Status Matrix

รายละเอียดครบ 20 องค์ประกอบอยู่ใน `d3_completion_matrix.csv` ภาพรวมคือ dataset audit, feature/window pipeline, preliminary ML, ablation, frozen artifacts, intake validator และ tests เสร็จและทดสอบแล้ว Time-Shield, trusted enrollment, resource measurement และ fusion implemented แต่ validation ยังจำกัดอยู่ที่ candidate-role/same-capture Cross-dataset evaluation ถูก block ด้วยข้อมูลที่ขาด

สถานะ `COMPLETED AND TESTED` หมายถึง implementation และการตรวจใน scope ที่ประกาศเสร็จ ไม่ได้ขยายความหมายเป็น independent scientific validation

## 4. Dataset and Ground-Truth Audit

### 4.1 ไฟล์และ capture ที่ใช้

**MEASURED RESULT.** `results/audit/dataset_audit.json` inventory PCAP/PCAPNG 14 ไฟล์ รวม Deauth, Malware, SSDP, Botnet, Website spoofing, Disassociation, (Re)Association, Rogue AP, KRACK, Kr00k, Evil Twin, SQL Injection, SSH และ derived `AWID3_EvilTwin_Normal_Beacons.pcapng` Audit สแกน metadata/hash ของทั้งหมด แต่ Beacon/official-filter extraction เต็มที่ใช้ในงานนี้มาจาก:

| Capture | Total packets | Extracted Beacons | การใช้งาน |
|---|---:|---:|---|
| `pcaps/7. Evil_Twin.pcap` | 3,778,728 | 12,461 | supervised candidate-role experiments |
| `pcaps/4. Rogue_AP.pcap` | 1,973,193 | 6,946 | audit only; identity unknown |
| `pcaps/AWID3_EvilTwin_Normal_Beacons.pcapng` | 8,685 | derived subset | integrity/provenance check; ไม่ใช่ independent session |

### 4.2 Label definitions

| Label | จำนวน Beacon | ความหมาย |
|---|---:|---|
| `candidate_legitimate` | 8,685 | BSSID `.fe:34`; author-described dataset role within Evil Twin capture |
| `candidate_evil_twin` | 3,776 | BSSID `.fe:35`; author description + local filter anchor; 3,711 matched filter, 65 outside filter |
| `unknown` | 6,946 | Rogue_AP capture; ไม่แปลง filter/non-filter เป็น AP identity |
| `verified_legitimate` | 0 | ไม่มี independent device/event log |
| `verified_evil_twin` | 0 | ไม่มี independent transmitter authentication |

**IMPLEMENTED DESIGN.** Attack-related frame label และ AP identity label ถูกเก็บแยกกัน การอยู่นอก attack filter ไม่ถูกแปลงเป็น normal Join key ของ frame-specific evidence คือ `(pcap, original frame number)` และตรวจ uniqueness ก่อน merge

**LIMITATION / NOT YET VALIDATED.** `.fe:34/.fe:35` เป็น capture-specific dataset-role mapping ไม่ใช่การพิสูจน์ physical transmitter, attack success หรือ credential theft Rogue AP capture ไม่ได้เพิ่ม independent legitimate/Evil Twin session และ derived pcapng ไม่เป็น session ใหม่

## 5. Feature Definitions and Fingerprint Construction

ทุก feature คำนวณต่อ window โดย encoder/scaler/imputer อยู่ใน scikit-learn Pipeline และ fit บน train เท่านั้น Categorical unknown ใน validation/test ใช้ `OneHotEncoder(handle_unknown="ignore")`; numeric pipeline ใช้ median imputation แต่ experiment ใหม่ปฏิเสธ source feature ที่ missing ก่อน fit เพื่อไม่อาศัย imputation ซ่อนปัญหา

| Group | Feature | Definition / unit / type | Eligibility and use |
|---|---|---|---|
| Configuration | `capabilities_encoded` | capability word normalized เป็น hex string; categorical | ML; profile ต้องคงที่ |
| Configuration | `rsn_present` | IE tag 48 present; binary int | ML |
| Configuration | `rsn_capabilities_encoded` | normalized categorical RSN capabilities; `ABSENT_RSN` แยกจาก missing | ML |
| Configuration | `group_cipher_encoded` | sorted categorical group cipher set | ML |
| Configuration | `pairwise_ciphers_encoded` | sorted categorical pairwise cipher set | ML |
| Configuration | `akm_suites_encoded` | sorted categorical AKM set | ML |
| Configuration | `supported_rates_encoded` | normalized Mbps/basic-bit set จาก supported+extended rates | ML |
| Configuration | `stable_ie_structure_encoded` | sorted unique IE IDs ตัด SSID(0), TIM(5), BSS Load(11), vendor(221) | ML; shortcut risk |
| Configuration | `beacon_interval_tu` | advertised interval; float TU, 1 TU=1024 us | ML และ quality reference |
| Radio | `rssi_median_dbm` | median antenna RSSI ต่อ frame แล้ว median ต่อ window; float dBm | ML; receiver-location confound |
| Radio | `rssi_std_dbm` | sample SD ของ per-frame antenna median; float dB | ML; >=2 frames |
| Radio | `channel_frequency_mhz` | consistent radiotap frequency; integer MHz | ML; channel change invalid |
| Frame | `frame_len_mean` | mean `frame.len`; float bytes | ML; capture/filter/device shortcut risk |
| Frame | `frame_len_std` | sample SD `frame.len`; float bytes | ML |
| Frame | `sequence_increment_median` | median adjacent `(next-prev) mod 4096`; float | ML; ไม่ใช่ packet-loss proof |
| Frame | `sequence_discontinuity_rate` | fraction modulo increments !=1; float [0,1] | ML |
| Frame | `retry_fraction` | fraction retry flag true; float [0,1] | ML |
| Temporal | `median_interarrival_ms` | median exact receive-time deltas; float ms | Time-Shield; valid chronology required |
| Temporal | `mad_interarrival_ms` | raw median absolute deviation; float ms, ไม่มี 1.4826 factor | Time-Shield |
| Temporal | `tsf_slope_s_per_s` | centered OLS TSF seconds vs receive seconds; float s/s | Time-Shield; positive deltas only |
| Temporal | `tsf_nonpositive_fraction` | fraction TSF deltas <=0; float [0,1] | quality indicator; ไม่อยู่ใน 3-D Time-Shield vector |

**IMPLEMENTED DESIGN.** Predictive leakage denylist ประกอบด้วย SSID/BSSID/MAC, capture filename, frame number, absolute timestamps, raw TSF, attack/capture labels, candidate stream ID, identity status และ split ฟิลด์เหล่านี้ใช้ grouping/provenance/audit เท่านั้น

## 6. Window Construction and Quality Policies

**IMPLEMENTED DESIGN.** Primary stream key คือ `(capture, BSSID, capabilities)` แล้ว hash เป็น 16-character `candidate_stream_id`; BSSID ไม่ถือเป็น physical identity Frames เรียงด้วย original frame number Windows ขนาด 10/20/50 ไม่ซ้อนกันและ frame หนึ่งไม่อยู่หลาย window ต่อขนาด Tail ที่ไม่ครบถูก flag ไม่เติม frame

Conservative window label ต้องมี identity status เดียวและ provenance เดียว Unknown/mixed windows ไม่มี target Global chronological split ใช้ 60% train, 20% validation, 20% development-test ตามเวลา capture; windows คร่อม boundary ถูก exclude ไม่มี frame-random split

**IMPLEMENTED DESIGN.** ML eligibility ต้องมี complete window, single label/profile, finite configuration/radio/frame features, ไม่มี malformed/truncation/channel/configuration inconsistency Capture gap หรือ TSF reset ไม่ตัด non-temporal ML โดยอัตโนมัติ Temporal features ของ window ที่ไม่ผ่านถูก mask

Time-Shield eligibility ใช้ gap factor 1.5, incoming-boundary check, positive receive/TSF deltas, finite temporal vector และ reject TSF reset TSF slope คำนวณเฉพาะเมื่อ receive timestamps และ TSF เพิ่มขึ้นตลอด window จึงไม่ regress ข้าม reset Missing timestamp/gap/reset ทำให้ EWMA และ persistence reset และ state เป็น UNAVAILABLE

## 7. Window Attrition Results

**MEASURED RESULT.** Primary strict fixed 1.5 policy:

| Size | Role | Candidate windows | ML eligible | Time-Shield eligible |
|---:|---|---:|---:|---:|
| 10 | candidate legitimate | 869 | 866 | 750 |
| 10 | candidate Evil Twin | 378 | 375 | 89 |
| 20 | candidate legitimate | 435 | 432 | 323 |
| 20 | candidate Evil Twin | 190 | 187 | 13 |
| 50 | candidate legitimate | 174 | 171 | 88 |
| 50 | candidate Evil Twin | 76 | 73 | 0 |

เหตุผลซ้ำกันได้ใน window เดียว สำหรับ n20 Evil Twin มี `arrival_gap` 176 windows, `tsf_gap` 176, incoming arrival/TSF gap อย่างละ 21, `tsf_nonpositive` 1, `nonfinite_feature` 1 และ structural-quality 2 จุด รายงาน attrition ตรวจละเอียดพบ 177 windows ที่มี capture gap อย่างน้อยหนึ่งประเภท, TSF decrease/repeat 1 และ incomplete tails 2 ขนาด 50 Evil Twin ทั้ง 76 windows มี capture gap

**MEASURED RESULT.** Sensitivity ใช้ gap factors 1.5/2/3, gap-segmented construction, BSSID-only และ stable-profile grouping โดยเปรียบเทียบ availability ไม่ใช้ model score เกณฑ์ 3.0 เพิ่ม temporal coverage มาก แต่ไม่ได้เลือกเป็น primary เพราะอาจยอมรับช่วงที่ข้าม Beacons ที่สังเกตไม่ครบ Final policy จึงคง fixed windows, BSSID+capabilities และ strict temporal 1.5

การแยก quality gates ทำให้ n20 Evil Twin non-temporal ML usable train/validation/dev=45/70/72 แทน temporal usable=2/5/6 ส่วน n50 ML train positive=18 ต่ำกว่า heuristic 20 จึงไม่ทำ preliminary comparison

## 8. Preliminary ML Experiments

**IMPLEMENTED DESIGN.** Positive class คือ candidate Evil Twin Random seed=42 Preprocessing อยู่ใน Pipeline Hyperparameters เลือกด้วย validation positive-class F1, tie ใช้ลำดับ grid แรก, threshold=0.5 และไม่ refit ด้วย validation ก่อน development test

| Window | Split | Legitimate | Evil Twin |
|---:|---|---:|---:|
| 10 | train / validation / dev | 521 / 172 / 173 | 90 / 141 / 144 |
| 20 | train / validation / dev | 260 / 86 / 86 | 45 / 70 / 72 |

Search spaces: CART `max_depth=[3,4,5,6]`, `min_samples_leaf=[5,10,20]`; RF `n_estimators=[50,100]`, `max_depth=[5,8,10]`, `min_samples_leaf=[2,5]`; LR `C=[0.1,1,10]`; ทุกแบบค้น `class_weight=[None, balanced]`

Selected primary non-temporal configurations:

| Window | Model | Selected parameters | Validation F1 |
|---:|---|---|---:|
| 10 | CART | depth=3, leaf>=5, no class weight | 0.800 |
| 10 | RF | trees=50, depth=5, leaf>=2, no class weight | 0.800 |
| 10 | LR | C=0.1, no class weight | 1.000 |
| 20 | CART | depth=3, leaf>=5, balanced | 1.000 |
| 20 | RF | trees=50, depth=5, leaf>=2, no class weight | 0.8034 |
| 20 | LR | C=0.1, no class weight | 1.000 |

**LIMITATION / NOT YET VALIDATED.** ทั้งสาม split อยู่ใน capture เดียว Development-test เคยถูก inspect ในงานก่อนหน้า จึงเป็น frozen development result ไม่ใช่ untouched independent test ไม่มี n50 non-temporal model comparison เพราะ train positive support ไม่ผ่าน heuristic

## 9. Model Comparison Results

**MEASURED RESULT.** Configuration+radio+frame development-test:

| Window | Model | Precision | Recall | F1 | TN/FP/FN/TP |
|---:|---|---:|---:|---:|---|
| 10 | CART | 0 | 0 | 0 | 173/0/144/0 |
| 10 | RF | 0 | 0 | 0 | 173/0/144/0 |
| 10 | LR | 1 | 1 | 1 | 173/0/0/144 |
| 20 | CART | 1 | 1 | 1 | 86/0/0/72 |
| 20 | RF | 0 | 0 | 0 | 86/0/72/0 |
| 20 | LR | 1 | 1 | 1 | 86/0/0/72 |

คะแนนสมบูรณ์ไม่ได้พิสูจน์ generalization และคะแนนศูนย์ของ tree models แสดง distribution shift ที่ค่า validation อย่างเดียวไม่เปิดเผย Historical strict temporal experiment ยังอยู่ใน `results/metrics/`; n10 eligible Evil Twin เพียง 39 และ n20 เพียง 6 จึงไม่ใช้เลือก quality policy หรือ final model

## 10. Feature Ablation and Shortcut Findings

**MEASURED RESULT.** n20 CART development ablation:

| Feature group | Features | F1 |
|---|---:|---:|
| Configuration only | 9 | 0 |
| Radio only | 3 | 1 |
| Frame only | 5 | 1 |
| Configuration+Radio | 12 | 1 |
| Configuration+Frame | 14 | 1 |
| Radio+Frame | 8 | 1 |
| Configuration+Radio+Frame | 17 | 1 |
| Configuration without IE+Radio+Frame | 16 | 1 |

Configuration-only validation F1=0.8034 แต่ development F1=0 โดย miss Evil Twin 72/72 Candidate Evil development windows มี unseen category fraction=1 สำหรับ capabilities, RSN capabilities, group cipher, pairwise cipher และ stable IE structure n10 CART/RF จึงทำนาย Evil Twin development ทั้งหมดเป็น legitimate

Tree diagnostics ระบุว่า configuration models พึ่ง IE/cipher categories ส่วน radio-only tree พึ่ง `rssi_median_dbm` และ frame-only tree พึ่ง `frame_len_mean` Candidate legitimate RSSI อยู่ประมาณ -34 ถึง -31 dBm ขณะที่ Evil Twinประมาณ -48 ถึง -40 dBm; frame lengths legitimateประมาณ 342 bytes แต่ Evil profiles 241/150 bytes

**MEASURED RESULT.** ผลเหล่านี้สาธิต shortcut/distribution shift ภายใน capture **LIMITATION / NOT YET VALIDATED.** ยังไม่พิสูจน์ว่าฟีเจอร์เหล่านี้เป็น causal attack indicators หรือคงผลกับ receiver position/AP ใหม่ Temporal-only มีเฉพาะ historical strict experiment และไม่ได้ทำ ablation ใหม่หลัง separate eligibility เพราะ temporal-invalid windows ถูก mask

## 11. Time-Shield and Trusted Enrollment Status

### 11.1 Algorithm

**IMPLEMENTED DESIGN.** Temporal vector คือ

`z_t = [median(Delta arrival_ms), MAD(Delta arrival_ms), TSF_slope_s_per_s]`

จาก enrollment คำนวณ mean `mu`, sample scale และ correlation แล้ว regularize:

`R_lambda = (1-lambda) R + lambda I`

Standardized vector `u=(z-mu)/scale` และ Mahalanobis distance:

`d_t = sqrt(u_t^T R_lambda^{-1} u_t)`

EWMA `D_t = beta D_(t-1) + (1-beta)d_t` State เป็น DRIFT หลัง `D_t > threshold` ติดต่อกัน K valid windows, STABLE หลัง `D_t <= threshold` ติดต่อกัน K valid windows และ UNAVAILABLE เมื่อข้อมูล/baseline ไม่พร้อมหรือ evidence ยังไม่ครบ Gap/reset/missing timestamp reset EWMA และ streak ดังนั้นการไม่ alert ไม่เท่ากับ STABLE อัตโนมัติ

### 11.2 Verified และ exploratory enrollment

`src/trusted_temporal.py` บังคับ verified legitimate, evidence binding, one attributed stream และ enrollment ก่อน monitoring แต่ **verified enrollment disabled** เพราะ verified legitimate=0

คำสั่งล่าสุดอนุญาต candidate legitimate สำหรับ exploratory enrollment เท่านั้น Protocol v2.1 ใช้ n20 train candidate windows เรียงเวลา: 60% แรก 156 candidate windows เป็น enrollment segment ซึ่งผ่าน temporal gate 120; 40% หลัง 104 เป็น calibration segmentและมี valid smoothed scores 72 Enrollment จบก่อน calibration และ validation/dev เป็น monitoring only Baseline ไม่ update

Primary parameters: shrinkage=0.1, Mahalanobis, p99 calibration threshold=7.334245, beta=0.3, K=3 Mean vector=[102.402475 ms, 0.131117 ms, 0.999983985 s/s], scales=[0.044937, 0.277417, 9.21698e-6]

**MEASURED RESULT.** Candidate-legitimate monitoring:

| Split | Windows | Temporal valid | STABLE | DRIFT | UNAVAILABLE | Invalid / persistence warmup |
|---|---:|---:|---:|---:|---:|---|
| validation | 86 | 65 | 37 | 0 | 49 | 21 / 28 |
| development-test | 87 | 66 | 32 | 0 | 55 | 21 / 34 |

Primary Mahalanobis smoothed distribution: validation median=1.2399, p95=3.7618, p99=4.8604; development median=1.1935, p95=5.1080, p99=9.0931 มี isolated values สูงกว่า threshold แต่ไม่ต่อเนื่องครบ K=3 จึง DRIFT=0

Sensitivity shrinkage 0.01/0.1/0.5/1.0 ให้ Mahalanobis thresholds 7.3393/7.3342/7.3157/7.3008 และ state counts เหมือนกัน Standardized Euclidean threshold=7.3008 และ state counts เหมือนกันทุกค่า นี่แสดง local numerical stability ใน candidate sequence นี้ ไม่ใช่ universal parameter validation

Historical `results/temporal_fusion/` ใช้ candidate baseline 130 windows และ threshold 4.0316 ภายใต้ protocol/split เดิม ผล Mahalanobis test STABLE=31, DRIFT=0, UNAVAILABLE=129 จาก 160 windows เก็บไว้เป็น historical exploratory artifact v2.1 ใช้ chronological enrollment/calibration protocol ใหม่ จึง threshold ต่างกันและไม่ควรรวมเป็นผลเดียว

**LIMITATION / NOT YET VALIDATED.** Drift ไม่ใช่ Evil Twin proof ไม่มี verified baseline, verified calibration, independent normal monitoring หรือ drift-event ground truth จึงไม่มี verified FPR/recall

## 12. Decision Fusion Status

**IMPLEMENTED DESIGN.** Inputs คือ ML score, low/high thresholds, Time-Shield status, baseline availability, ML validity และ temporal validity Priority:

| Rule | Output |
|---|---|
| ML invalid/nonfinite | Pending |
| valid ML score >= high | Evil Twin Suspected |
| score < high + baseline + temporal valid + DRIFT | Suspicious Trusted AP |
| score <= low + baseline + temporal valid + STABLE | Consistent with Trusted Baseline |
| other | Pending |

High ML มี priority เหนือ STABLE; temporal-invalid ทำให้ STABLE/DRIFT ใช้ไม่ได้แต่ไม่ลบ valid high ML; missing baseline ให้ temporal status UNAVAILABLE Engineering truth table 120 combinations ผ่าน tests

Exploratory v2.1 fusion replay ใช้ frozen n20 scores และ fixed engineering low/high=0.2/0.8 Candidate baseline เปิดเฉพาะ candidate legitimate stream Result files ราย windowมีไว้ตรวจ integration ไม่มี fusion accuracy เพราะ baseline และ labels ไม่ verified

## 13. Resource Benchmark

**MEASURED RESULT.** Warm single-window inference รวม preprocessing, 30 repeats/warmup 5:

| Window | Model | Size bytes | Median/P95 ms | Peak RSS MiB |
|---:|---|---:|---|---:|
| 10 | CART | 5,602 | 1.921/2.050 | 164.406 |
| 10 | RF | 8,447 | 16.108/16.432 | 168.438 |
| 10 | LR | 5,770 | 1.973/2.132 | 164.609 |
| 20 | CART | 4,262 | 1.918/1.969 | 164.828 |
| 20 | RF | 7,009 | 15.547/16.226 | 167.375 |
| 20 | LR | 4,366 | 1.962/2.104 | 163.984 |

Window accumulation duration ใน development data: n10 median/P95=0.922/1.331 s, n20=2.048/2.663 s, n50=5.172/7.137 s เป็น capture-specific latency proxy

Time-Shield v2.1 n20 candidate monitoring 87 windows: batch median=2.9465 ms, P95=3.1625 ms, amortized median=0.03387 ms/window, sampled RSS baseline/peak=95.797/96.266 MiB, growth=0.469 MiB Scope รวม distance+EWMA+persistence แต่ไม่รวม extraction

Environment: macOS 15.7.9 arm64, Python 3.14.7, NumPy 2.5.4, pandas 3.1.0, scikit-learn 1.9.1, SciPy 1.18.1, joblib 1.6.0

**NOT MEASURED:** end-to-end PCAP-to-alert latency, feature extraction runtime แยกต่อ frame/window, preprocessing runtime แยกจาก inference, training peak memory, energy consumption, deployment false-alert processing cost และ physical attack-onset latency CPU percent/RSS รวม Python/runtime libraries ไม่ใช่ model-only memory

## 14. Independent Evaluation Readiness

**IMPLEMENTED DESIGN.** `scripts/import_external_pcap.py` stream-extracts Beacons และ audit RSSI/TSF/IE/timestamp field presence `src/independent_evaluation.py` ตรวจ safe paths, hashes, authorization, evidence, roles, intervals, capture independence และ cloned-BSSID frame attribution `src/external_inference.py` ตรวจ frozen artifact hash, feature order, size, finite values และ predict โดยไม่ retrain

Protocol ต้องการอย่างน้อย 2 independent sessions ต่อ verified role ปัจจุบัน eligible independent sessions=0 ดังนั้น independent legitimate FPR, Evil Twin recall, Time-Shield และ fusion evaluation ยังทำไม่ได้ Legitimate-only API ตั้ง attack recall/precision/F1 เป็น null และ final FPR เป็น null

Pending AMID CSV/PCAP ยังไม่ปรากฏใน repository และไม่ได้ inspect จึงยังไม่อ้าง compatibility ก่อนใช้ต้องตรวจ Beacon-level schema, frame/capture keys, RSSI, timestamp, TSF, IE/RSN/rates, sequence/retry, channel, provenance, physical AP/session independence และ mapping ที่ไม่สร้าง identity จาก prediction

ข้อมูลเพิ่มเติมที่ต้องการ: original PCAP, full SHA256/lineage, device inventory, receiver/environment metadata, synchronized event logs, verified normal/attack intervals, frame attribution สำหรับ BSSID clone, enrollment/calibration/monitoring chronology และ exposure duration สำหรับ false alerts/AP-hour

## 15. Reproducibility and Tests

Models อยู่ใต้ `models/preliminary_non_temporal_v1/` พร้อม selection manifest ที่ freeze ก่อน development scoring Data manifests เก็บ source hashes, feature files, protocol, random seed และ package versions Strict baseline checkpoint ตรวจ 20/20 files unchanged หลังงานใหม่ Time-Shield v2.1 manifest ตรวจ outputs 14/14 hashes ตรงและยืนยัน historical artifacts unchanged

Current test run: **66 tests + 152 subtests passed** ครอบคลุม joins, unknown labels, frame conservation, chronology, leakage, sequence wrap, TSF reset/gap, separate eligibility, preprocessing isolation, temporal covariance/distance, EWMA/persistence, candidate/verified enrollment gates, 120 fusion combinations, legitimate-only metrics และ duplicated capture rejection

Partial failed run `results/time_shield_exploratory_v2/` หยุดก่อนสร้าง score outputs เพราะ duplicate keyword ใน replay merge มี `FAILED_RUN.json` และถูกแทนด้วย immutable successful `results/time_shield_exploratory_v2_1/` การเก็บ failure trace ช่วยให้ provenance ตรวจสอบได้

ข้อจำกัด reproducibility คือ PCAP ต้นฉบับถือว่า immutable หลัง hash extraction, full re-extraction ต้องมี TShark/Capinfos compatible, runtime timestamps และ benchmark noise เปลี่ยนได้ และ same-capture results ไม่สร้าง statistical independence

## 16. Research Limitations and Threats to Validity

- **Ground-truth validity:** candidate roles มาจาก author description/filter anchor ไม่มี physical-device authentication
- **External validity:** supervised dataมาจาก capture/session เดียวและ receiver/environment เดียว
- **Shortcut learning:** configuration/IE, RSSI และ frame length แยก devices/scenario ได้ง่ายภายใน capture
- **Temporal confounding:** gaps, packet loss, receiver clock, movement และ reboot สามารถเปลี่ยน interarrival/TSF relation
- **Selection history:** development-test เคยถูก inspect จึงไม่ใช่ pristine final test
- **Dependence:** windows จาก stream/capture เดียวมี temporal correlation; window count ไม่เท่ากับ independent sample count
- **Metric validity:** candidate legitimate alert fraction ไม่ใช่ verified FPR; drift ไม่ใช่ attack label
- **Threshold transfer:** candidate calibration p99 และ shrinkage sensitivity ยังไม่ผ่าน independent trusted APs
- **Instrumentation:** monitor adapter/driver อาจไม่มี RSSI/TSF/IE fields เหมือน AWID3
- **Statistical power:** protocol minimum two sessionsต่อ role เป็น readiness floor ไม่รับประกัน confidence interval หรือ population generalization

## 17. What Can Be Claimed in D3

- **MEASURED RESULT:** pipeline สกัดและ audit AWID3 Beacons พร้อม reproducible joins/hashes ได้
- **IMPLEMENTED DESIGN:** multi-factor fingerprint 21 features, non-overlapping windows และ separate ML/temporal quality gates ทำงานและมี tests
- **MEASURED RESULT:** preliminary same-capture ML มีผลตามตาราง และแสดง configuration distribution shift/shortcut risk อย่างชัดเจน
- **IMPLEMENTED DESIGN:** Time-Shield มี regularized Mahalanobis, standardized Euclidean comparison, EWMA, persistence และ STABLE/DRIFT/UNAVAILABLE พร้อม reset เมื่อข้อมูลไม่ valid
- **MEASURED RESULT:** candidate-only exploratory enrollment/calibration/monitoring v2.1 ให้ threshold, score distributions, state counts และ runtime ตามส่วน 11/13
- **IMPLEMENTED DESIGN:** four-state fusion และ independent intake/frozen inference พร้อมสำหรับข้อมูลที่มี evidence เหมาะสม
- **MEASURED RESULT:** tests, manifests และ frozen-artifact integrity ผ่านตามส่วน 15

ทุก claim ต้องมีคำว่า preliminary/exploratory, same-capture และ candidate-role เมื่ออ้างผล AWID3

## 18. What Cannot Yet Be Claimed

- ไม่สามารถอ้าง final classifier หรือโมเดลที่ดีที่สุด
- ไม่สามารถอ้าง verified Evil Twin detection accuracy, verified FPR หรือ false alerts/AP-hour
- ไม่สามารถอ้าง unseen AP, cross-dataset, new receiver หรือ deployment generalization
- ไม่สามารถอ้าง candidate baseline เป็น verified trusted AP baseline
- ไม่สามารถตีความ DRIFT เป็นหลักฐาน Evil Twin หรือ STABLE เป็นหลักฐานว่า AP legitimate
- ไม่สามารถอ้าง AMID compatibility/ผล AMID ก่อนตรวจไฟล์จริง
- ไม่สามารถอ้าง n50 model comparison, end-to-end latency, training peak memory หรือ metrics ที่ระบุ NOT MEASURED

## 19. Remaining Work and Data Requirements

1. นำ independent PCAP/AMID ที่ pending เข้าผ่าน importer โดยไม่ assign labels อัตโนมัติ แล้วตรวจ field-value coverage และ capture lineage
2. สร้าง device/event evidence ที่ผูก physical transmitter กับ session/interval/window โดยเฉพาะ cloned BSSID
3. แยก verified legitimate enrollment, calibration และ monitoring ตามเวลา; freeze baseline/threshold ก่อนเปิด final monitoring
4. เก็บอย่างน้อยสอง independent sessions ต่อ verified role และเพิ่มจำนวนตาม power analysis ที่เหมาะสม
5. รัน frozen ML โดยคง feature order/preprocessing/thresholds และรายงาน legitimate-only metrics เป็น null สำหรับ attack metrics
6. เปรียบเทียบ ML-only, Time-Shield-only และ fusion พร้อม Pending Rate; คำนวณ FPR/AP-hour เฉพาะเมื่อมี verified normal exposure duration
7. ทดสอบ normal operation, receiver movement, reboot, SSID clone, SSID+BSSID clone และ configuration clone ใน authorized testbed
8. หลัง independent evaluation เท่านั้นจึงพิจารณา final model selection และ D3 conclusions เชิง generalization

### แหล่งผลหลัก

- Dataset/labels: `results/audit/`
- Window attrition: `results/audit/window_attrition_v2/`
- Prepared features: `data/processed/ml_non_temporal_v1/`
- Preliminary ML: `results/preliminary_non_temporal_v1/`, `models/preliminary_non_temporal_v1/`
- Historical temporal/fusion: `results/temporal_fusion/`
- New exploratory Time-Shield: `results/time_shield_exploratory_v2_1/`
- Operational/fusion readiness: `results/operational_validation_v1/`
- Independent intake: `data/independent/`, `results/independent_evaluation_readiness.json`

