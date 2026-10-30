# Time-Shield operational validation และ readiness v1

สถานะ: engineering validation สำเร็จ; trusted operational validation **ยังติดข้อจำกัด ground truth**
ผลนี้ใช้การตรวจ artifacts และ feature tables ที่มีอยู่ ไม่ได้รันการฝึกหรือเลือก classifier ใหม่

## 1. Audit ของ Time-Shield

`src/temporal_drift.py` มี temporal vector (median inter-arrival ms, MAD ms, TSF slope s/s),
standardization, regularized correlation, Mahalanobis/standardized Euclidean distance, EWMA และ
persistence K อยู่แล้ว การ regularize correlation หลัง standardization เทียบเท่ากับการใช้ covariance
ที่ปรับ scale แล้ว ค่า slope เป็น observed timing slope ไม่ใช่ pure hardware clock skew

`src/window_aggregation.py` คำนวณ slope เฉพาะเมื่อ receive timestamp และ TSF เพิ่มขึ้นทุกคู่;
window ที่มี reset จะไม่มี slope และ incoming gaps/resets ถูก flag ด้วย
`src/window_policy.py` แยก ML และ temporal eligibility และ processed table mask ค่า temporal-invalid
โดยยังใช้ strict gate เดิม การไม่มี alert ยังไม่ให้ STABLE: ต้องมี K valid windows ติดต่อกันต่ำกว่าหรือเท่ากับ threshold

เพิ่ม `src/trusted_temporal.py` เป็น operational entry point ที่ตรวจ verified legitimate role,
หลักฐานผูก device กับ window IDs, stream เดียว, non-overlap และ enrollment จบก่อน monitoring
baseline ไม่ปรับตัวระหว่าง monitoring; gap/reset/missing fields ล้าง EWMA/persistence และเป็น UNAVAILABLE
การส่ง physical_device_id เข้าสู่ monitoring ต้องผ่านการตรวจหลักฐานภายนอกก่อน ไม่อนุมานจาก MAC
low-level `fit_baseline` เดิมเป็น numerical primitive และไม่ตรวจ identity ด้วยตัวเอง

Parameter plan อยู่ใน `configs/operational_validation_v1.json`: primary gap 1.5, shrinkage 0.1,
beta 0.3, K=3, sensitivity shrinkage 0.01/0.1/0.5/1.0; threshold ยังเป็น null เพราะไม่มี verified calibration
จึงยังไม่มี trusted baseline ใหม่ให้ freeze การทดสอบ numerical covariance ใช้ unit fixtures เท่านั้น

## 2. Trusted enrollment และ temporal coverage

Audit พบ candidate legitimate 8,685 frames, candidate Evil Twin 3,776 frames และ unknown 6,946 frames
ไม่มี verified legitimate observations (`independent_identity_verification=false`)
baseline จากงาน Time-Shield เก่าอาศัย candidate-role assumption จึงนำมาใช้เป็น verified trusted enrollment ไม่ได้
ชื่อ capture “normal” หรือการอยู่นอก attack filter ไม่ได้เปลี่ยนสถานะนี้

ด้านล่างเป็นคุณภาพ candidate legitimate windows จาก attrition ที่มีอยู่ หลังตัด split-boundary windows:

| Gap factor | n10 valid / total | n20 valid / total | n50 valid / total |
|---|---:|---:|---:|
| 1.5 (primary เดิม) | 750 / 867 | 323 / 433 | 88 / 172 |
| 2.0 (descriptive) | 799 / 867 | 366 / 433 | 115 / 172 |
| 3.0 (descriptive) | 862 / 867 | 428 / 433 | 167 / 172 |

ความไวต่อ gap threshold ข้างต้นเป็น coverage sensitivity เท่านั้น ไม่มีการเลือก threshold จาก scores
หรือเปลี่ยน primary policy เพื่อเพิ่มจำนวน enrollment

เมื่อ replay เส้นทางไม่มี trusted baseline โดยรวม candidate legitimate ทุก window (รวม boundary/tail):
n10=869, n20=435, n50=174 windows เป็น UNAVAILABLE ทั้งหมด; STABLE=0 และ DRIFT=0
ผลนี้แสดง availability ของระบบ ไม่ใช่ผลตรวจจับหรือการยืนยันว่าไม่มี drift

Mahalanobis/EWMA score distributions, chronological verified enrollment/monitoring และ empirical covariance
sensitivity ยังทำไม่ได้ จึงบันทึกเป็น null พร้อม blocker แทนการเติมคะแนน กราฟที่มีเป็น raw temporal-feature
distributions ของ candidate windows และ coverage figure พร้อมข้อความระบุ enrollment gate

Runtime ของ UNAVAILABLE path บน n20 จำนวน 435 candidate windows (30 repeats, warmup 5):
median 4.289 ms/batch, P95 13.064 ms/batch; sampled process RSS 212.594 MiB, sampled growth 0 MiB
ตัวเลขนี้รวม runtime/libraries และไม่รวม distance scoring, PCAP extraction หรือ training peak
จึงไม่ใช่ benchmark ของ Time-Shield ที่มี trusted baseline ครบวงจร

## 3. Four-state fusion

เพิ่ม temporal_valid แยกจาก ML quality ใน `src/decision_fusion.py` โดยยังรองรับ caller เดิม
กฎเรียงตาม priority ดังนี้:

| เงื่อนไข | ผล |
|---|---|
| ML-invalid หรือไม่มี finite ML score | Pending |
| ML-valid และ score >= high | Evil Twin Suspected |
| score < high, baseline มี, temporal-valid และ DRIFT | Suspicious Trusted AP |
| score <= low, baseline มี, temporal-valid และ STABLE | Consistent with Trusted Baseline |
| อื่น ๆ | Pending |

ถ้า temporal-invalid จะไม่ใช้ STABLE/DRIFT ที่ค้างอยู่; ML score สูงที่ยัง ML-valid มีสิทธิ์ให้ suspicion
แม้เกิด gap/reset ส่วน conflicting high ML + STABLE ให้ Evil Twin Suspected ตาม priority
low ML + DRIFT ให้ Suspicious Trusted AP มิใช่ ground-truth Evil Twin

`fusion_rule_table.csv` มี 120 combinations รวมค่าที่เท่ากับ thresholds
engineering replay ใช้ scores ที่ freeze ไว้ของ 6 primary models, low=0.2/high=0.8 และ baseline unavailable
thresholds นี้เป็น engineering constants ไม่ใช่ค่าที่ tune เพื่อ deployment หรือ fusion accuracy
ผลราย window อยู่ใน `frozen_prediction_fusion_replay.csv`; ไม่มีการคำนวณ fusion detection metrics

## 4. External data readiness

ใช้ intake/validator เดิมและเพิ่มการกัน capture hash เดียวที่ลงทะเบียนหลายชื่อ ไม่ให้สร้าง independent sessions
จากไฟล์ซ้ำ พร้อม fail gate เมื่อมี session invalid ค่า distinct SHA256 อย่างเดียวไม่พิสูจน์ว่าเป็น independent
capture: การ crop/re-export capture เดิมและการใช้ AP เดิมต้องตรวจ lineage และ physical device inventory โดยคน

เพิ่ม `scripts/import_external_pcap.py --pcap PATH --out NEW_DIR` สำหรับ streaming Beacon extraction
และรายงาน required/optional dissector fields กับ nonempty counts ของ RSSI, TSF, IE และ timestamps
TShark ในเครื่องมี fields ที่ใช้ครบ แต่ยังไม่มี registered independent PCAP ให้ทดสอบ actual import
การมี dissector ไม่รับรองว่า capture จาก receiver ใหม่จะมี RSSI/TSF ครบ

`src/external_inference.py` ตรวจ artifact hash, frozen preprocessing feature order, window size และ finite
features ก่อน predict_proba โดยไม่ fit; replay 6 frozen artifacts ให้คะแนนตรงกับ predictions เดิมที่ tolerance 1e-12
API รับ prepared, quality-checked window tables; raw-PCAP-to-reviewed-label-to-window workflow
ยังต้องยืนยันกับข้อมูลใหม่จริง โดยเฉพาะ frame-level attribution ในกรณี BSSID cloning
legitimate-only metric API ให้ attack recall/precision/F1 เป็น null และยังไม่อ้าง final FPR

Readiness session count ยังเป็นศูนย์ การผ่าน schema/hash เป็นเพียง mechanical check; ผู้วิจัยต้องตรวจ
หลักฐาน ground truth และ independence ก่อนอนุญาต evaluation บนข้อมูลจริง

## 5. Tests และ reproducibility

63 tests และ 152 subtests ผ่าน รวม 120 fusion combinations, enrollment provenance/chronology rejection,
gap/reset/missing timestamp persistence, frozen baseline, covariance numerical cases, legitimate-only metrics
และ duplicated-capture session rejection Unit fixtures ไม่ถูกใช้เป็น experimental evidence

`integrity.json` ยืนยัน historical artifacts 202 ไฟล์ไม่มีการเปลี่ยนแปลง; models, scores, splits และ baseline เก่าอยู่ครบ
`manifest.json` เก็บ input/code/output checksums และ `test_results.txt` เก็บผลทดสอบจริง
คำสั่งทำซ้ำต้องใช้ output ใหม่:

```bash
.venv/bin/python scripts/validate_operations_v1.py --out results/operational_validation_v2
```

## 6. ข้อความสำหรับ D3 methodology / preliminary findings

ระบบได้แยกคุณภาพของ non-temporal ML ออกจาก temporal continuity และใช้ Time-Shield ที่ตรวจ median
inter-arrival, MAD และ valid TSF slope ผ่าน regularized Mahalanobis distance, EWMA และ persistence
การสะดุดของ capture หรือ TSF reset ทำให้ temporal state เป็น UNAVAILABLE และไม่คำนวณ slope ข้าม reset
Decision fusion ใช้สี่สถานะโดยแยก suspicion ออกจาก ground truth และผ่านการทดสอบกฎครบชุด
อย่างไรก็ตาม AWID3 observations ที่ยอมรับในงานนี้มีเพียง candidate identity labels จึงยังไม่สามารถ
สร้าง verified trusted baseline หรือสรุป Time-Shield/fusion accuracy ได้ ผล coverage และ frozen-model replay
เป็น preliminary engineering evidence; การประเมิน generalization ต้องใช้ independently captured sessions
พร้อม device inventory, synchronized event logs และ packet/window attribution ที่ตรวจสอบได้

## 7. ข้อมูลที่ยังต้องจัดหา

- Verified legitimate enrollment, calibration และ monitoring ที่แบ่งตามเวลาชัดเจน พร้อมหลักฐาน device/window
- Independent captures ตาม protocol อย่างน้อย 2 sessions ต่อ verified class; จำนวนนี้เป็นขั้นต่ำโครงการ
  ไม่ได้รับประกัน statistical power หรือ generalization โดยลำพัง
- Device IDs/รุ่น, receiver/channel/ตำแหน่ง, capture lineage และ clock synchronization/uncertainty
- Ground truth สำหรับ normal, movement, reboot และ authorized cloning scenarios;
  SSID+BSSID cloning ต้องมี external transmitter attribution ที่ละเอียดพอสำหรับ per-window labels
- ระยะเวลาและ exposure ที่ตรวจสอบได้ก่อนวัด false alerts/AP-hour และ final FPR

ยังไม่เลือก final classifier และยังไม่อ้าง unseen-AP generalization
