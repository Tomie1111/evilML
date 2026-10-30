# รายงาน Preliminary Non-Temporal ML v1

## ขอบเขตและสถานะ

การทดลองนี้เป็น **same-capture chronological development experiment** บน candidate labels
ที่ผู้ใช้ยอมรับตาม labeling protocol เท่านั้น ไม่ใช่ final model comparison และไม่ใช่หลักฐานว่า
โมเดล generalize ไปยัง AP หรือ capture session ใหม่ได้ ชุดข้อมูลมี original labeled capture เพียง 1
session และมี independent test session 0 session

Protocol ถูกประกาศใน `configs/non_temporal_exploratory.json` และเลือก hyperparameters ด้วย train/validation
ก่อน freeze `models/preliminary_non_temporal_v1/selection_manifest.json` จากนั้นจึงประเมิน
development-test เพียงครั้งเดียว ไม่มี oversampling หรือ SMOTE และไม่ได้ใช้ test เพื่อปรับโมเดลภายหลัง

## ผล model comparison

Positive class คือ candidate Evil Twin ข้อมูลทุกแถวด้านล่างใช้ configuration + radio + frame features

| Window | Model | Validation F1 | Dev-test Precision | Dev-test Recall | Dev-test F1 | Dev support (legit/evil) |
|---:|---|---:|---:|---:|---:|---:|
| 10 | Decision Tree | 0.800 | 0.000 | 0.000 | 0.000 | 173 / 144 |
| 10 | Random Forest | 0.800 | 0.000 | 0.000 | 0.000 | 173 / 144 |
| 10 | Logistic Regression | 1.000 | 1.000 | 1.000 | 1.000 | 173 / 144 |
| 20 | Decision Tree | 1.000 | 1.000 | 1.000 | 1.000 | 86 / 72 |
| 20 | Random Forest | 0.803 | 0.000 | 0.000 | 0.000 | 86 / 72 |
| 20 | Logistic Regression | 1.000 | 1.000 | 1.000 | 1.000 | 86 / 72 |

ค่าที่เป็น 1.000 ยังไม่ถือเป็นผลยืนยัน: legit และ Evil Twin ใน capture นี้แยกกันชัดมากด้วย
RSSI และ frame length และจึงอาจเป็น receiver-position, device หรือ scenario shortcut
`independently_verified_fpr` ไม่ถูกรายงาน เพราะไม่มี verified independent normal session;
candidate-legitimate alert fraction อยู่ที่ 0 ในการทดลองนี้

## Ablation และ root cause

ที่ window size 20, Decision Tree แบบ configuration-only มี validation F1 = 0.803 แต่ dev-test F1 = 0
(false negative 72/72) ขณะที่ radio-only, frame-only, radio+frame และชุดผสมที่ทดลองได้ dev-test F1 = 1.000
Temporal-only ไม่ได้ทดลองใน policy นี้ เพราะ window ที่ temporal-invalid ถูกเก็บไว้สำหรับ non-temporal ML
และ temporal values ถูก mask ตาม quality policy

สาเหตุหลักของความไม่เสถียรคือ configuration distribution shift:

- Evil Twin ใน train มี IE structure `1;3;7;45;61;127;191;192;195`
- Evil Twin ใน dev-test มี IE structure `1;3;48` ซึ่งไม่เคยอยู่ใน train
- 100% ของ Evil Twin dev-test windows มีค่า unseen ใน capabilities, RSN capabilities,
  group cipher, pairwise cipher และ IE structure
- Size-10 Decision Tree ใช้ pairwise-cipher category เพียงตัวเดียว และ Random Forest ให้น้ำหนักสูงกับ
  configuration categories จึงทำนาย Evil Twin dev-test ทั้งหมดเป็น legitimate
- Size-20 radio-only tree ใช้ RSSI median เพียงตัวเดียว และ frame-only tree ใช้ frame-length mean
  เพียงตัวเดียว แม้คะแนนดี แต่ยังเป็น shortcut ภายใน capture เดียว ไม่ใช่ attack mechanism ที่ยืนยันแล้ว

ดังนั้นผลนี้สนับสนุนข้อสรุปว่าโมเดล configuration-heavy มี overfit/shortcut risk สูง และคะแนนสมบูรณ์ของ
Logistic Regression หรือ ablation อื่นยังไม่เพียงพอสำหรับเลือก final model

## Lightweight resource measurement

วัด warm inference รวม preprocessing ใน process แยก, 30 repeats, single window:

| Window | Model | Artifact | Median | P95 |
|---:|---|---:|---:|---:|
| 10 | Decision Tree | 5,602 B | 1.921 ms | 2.050 ms |
| 10 | Random Forest | 8,447 B | 16.108 ms | 16.432 ms |
| 10 | Logistic Regression | 5,770 B | 1.973 ms | 2.132 ms |
| 20 | Decision Tree | 4,262 B | 1.918 ms | 1.969 ms |
| 20 | Random Forest | 7,009 B | 15.547 ms | 16.226 ms |
| 20 | Logistic Regression | 4,366 B | 1.962 ms | 2.104 ms |

Median observed window duration ใน dev-test คือ 0.922 วินาทีสำหรับ size 10 และ 2.048 วินาทีสำหรับ
size 20; ค่านี้เป็น capture-specific detection latency proxy ไม่ใช่ค่ารับประกันใน deployment
RSS memory ในไฟล์ benchmark รวม Python runtime/libraries จึงไม่ใช่ model-only memory

## ข้อสรุปและ gate

Pipeline เดินต่อถึง preliminary model training, comparison, feature ablation และ resource measurement
ได้แล้ว แต่ **supervised ML final evaluation ยังไม่ feasible อย่างมีความหมาย** เพราะไม่มี independent labeled
session และเห็น shortcut/distribution shift ชัดเจน จึงยังไม่ควรเลือก final classifier, ทำ final comparison,
หรืออ้าง unseen-AP performance

ขั้นถัดไปที่ถูกต้องคือเก็บหรือจัดหา capture session อิสระที่มี ground truth จากอุปกรณ์/เหตุการณ์จริง
โดย freeze protocol และ candidate models ก่อนเปิดข้อมูลนั้น จากนั้นจึงประเมิน ML-only; Time-Shield และ
decision fusion จะถูกนำมาเทียบหลัง ML ผ่าน independent validation ตามลำดับใน Master Prompt

