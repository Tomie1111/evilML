# สถานะ Independent Evaluation Readiness

สถานะปัจจุบัน: **BLOCKED — รอ independent capture และ external ground-truth evidence**

| รายการ | จำนวน |
|---|---:|
| Session manifests | 0 |
| Valid sessions | 0 |
| Verified legitimate sessions ที่นับได้ | 0 |
| Verified Evil Twin sessions ที่นับได้ | 0 |
| ขั้นต่ำที่กำหนดต่อคลาส | 2 |
| Frozen model artifacts ที่ตรวจ hash ผ่าน | 13 / 13 |

ตัวตรวจไม่ได้โหลดหรือ score โมเดล และไม่ได้สร้าง labels, observations หรือ metrics ใหม่
ผล machine-readable อยู่ที่ `results/independent_evaluation_readiness.json`

## สิ่งที่เตรียมไว้

- Protocol: `configs/independent_evaluation_protocol.json`
- Empty registry: `data/independent/session_registry.json`
- Manifest template: `data/independent/session_manifest.template.json`
- Intake instructions: `data/independent/README.md`
- Validator: `src/independent_evaluation.py`
- Readiness command: `scripts/check_independent_evaluation_readiness.py`

ทุก capture และ evidence file ต้องผูกกับ SHA256, ระบุ authorized testbed และยืนยันว่า independent
จาก development data โดยชัดแจ้ง Device role ต้องอ้าง external device/event evidence ไม่ใช่ BSSID,
attack filter หรือ model prediction

กรณี SSID+BSSID cloning จะไม่นับ interval เป็น verified per-window ground truth หากไม่มี
external frame-attribution evidence เพราะ passive BSSID เพียงอย่างเดียวแยก physical transmitter ไม่ได้

## เงื่อนไขเดินหน้าต่อ

ต้องมี session อิสระที่ valid อย่างน้อย 2 session ต่อ verified role เมื่อ gate ผ่านแล้วจึงเปิด frozen
models เพื่อประเมิน ML-only จากนั้นจึงทำ trusted enrollment ของ Time-Shield และเปรียบเทียบ ML-only,
Time-Shield-only และ fusion โดยไม่ปรับ threshold จาก final test

