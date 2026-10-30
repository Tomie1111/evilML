# ตรวจสาเหตุหน้าต่าง Evil Twin ถูกคัดออก

ข้อมูลนี้มาจาก PCAP เดิมและ candidate AP-role labels ที่ยอมรับสำหรับการทดลองเบื้องต้นเท่านั้น ไม่มีการสร้างเฟรม หน้าต่าง หรือ label เพิ่ม และไม่ใช้ผลโมเดลบน development test เพื่อเลือกเกณฑ์

## ผลของเกณฑ์เดิม

เกณฑ์เดิมใช้หน้าต่างคงที่ ไม่ซ้อนกัน และตัดทั้งหน้าต่างเมื่อ arrival หรือ TSF delta ภายในหน้าต่าง/ขอบขาเข้ามากกว่า 1.5 เท่าของ beacon interval:

| ขนาด | Evil Twin windows ทั้งหมด | ผ่าน Time-Shield | ใช้ฟีเจอร์ ML ที่ไม่อาศัยเวลาได้ |
|---:|---:|---:|---:|
| 10 | 378 | 89 | 376 |
| 20 | 190 | 13 | 188 |
| 50 | 76 | 0 | 74 |

จำนวนเหตุผลอาจซ้ำในหน้าต่างเดียวกัน จึงไม่ควรนำมาบวกกันเป็นจำนวนหน้าต่างที่ถูกคัดออก สำหรับ Evil Twin ขนาด 20 มี **177 หน้าต่างที่ติด capture gap**, 1 หน้าต่างมี TSF ลดลง/ซ้ำ, 1 หน้าต่างมี slope ไม่ finite เพราะจุด TSF นั้น และ 2 หน้าต่างท้ายมีเฟรมไม่ครบ ข้อมูล beacon ของ Evil Twin ไม่มี missing field ในฟิลด์ที่ใช้ ขนาด 50 ทั้ง 76 หน้าต่างติด capture gap อย่างน้อยหนึ่งจุด

ในสอง rogue profiles มี arrival gaps ตามเกณฑ์ 1.5 รวม **602 intervals** จาก 3,774 intervals; 601 จุดมี TSF gap ตรงกัน พบ TSF ลดลงหนึ่งจุดภายใน profile ที่สอง นี่คือความไม่ต่อเนื่องที่สังเกตได้ ไม่ใช่หลักฐานยืนยัน packet loss หรือ reboot จากต้นทาง การเรียงเฟรมด้วย BSSID อย่างเดียวทำให้สอง profile มารวมกันและเกิดหน้าต่างข้าม profile 1 หน้าต่าง ส่วน stable-profile grouping ในข้อมูลนี้ให้กลุ่มเหมือน BSSID+capabilities

## เกณฑ์คุณภาพแยกตามงาน

- **ML (configuration + radio + frame):** หน้าต่างต้องครบ มี candidate role เดียว ฟีเจอร์ที่ใช้ต้องครบและ profile คงที่ Capture gap หรือ TSF reset ไม่ทำให้ RSSI, capabilities, frame length และ sequence statistics ที่คำนวณได้เสียโดยอัตโนมัติ ฟีเจอร์ด้านเวลาของหน้าต่างที่ไม่ผ่าน Time-Shield ถูกตั้งเป็น missing ในตาราง ML ใหม่ และต้องไม่แอบเติมเพื่อใช้โมเดลที่รวม temporal features
- **Time-Shield:** คงเกณฑ์เดิม 1.5 พร้อมตรวจขอบขาเข้า ห้ามคำนวณ slope ข้าม TSF reset และไม่เติมช่องว่างของเวลา

จำนวน Evil Twin windows ที่พร้อมใช้ ML ภายใต้เกณฑ์ที่แนะนำ (train / validation / development test): **90 / 141 / 144** สำหรับขนาด 10, **45 / 70 / 72** สำหรับขนาด 20 และ **18 / 27 / 28** สำหรับขนาด 50 หน้าต่างที่คร่อม split ถูกตัดออกจากตัวเลขนี้ เกณฑ์ขั้นต่ำเชิงปฏิบัติที่ประกาศไว้คือ 20 / 10 / 10 ต่อคลาสในสามชุด จึงมีขนาด 10 และ 20 ที่เพียงพอสำหรับ *การทดลองเบื้องต้นภายใน capture เดียว* ส่วนขนาด 50 มีตัวอย่างโจมตีใน train เพียง 18

## Sensitivity และข้อสรุป

ทดลองเกณฑ์ gap 1.5, 2.0, 3.0 เท่า, การแบ่งหน้าต่างใหม่หลัง gap และวิธี grouping อีกสองแบบ โดยเปรียบเทียบ **จำนวนข้อมูลที่ใช้ได้** เท่านั้น เพิ่ม gap เป็น 2.0 ทำให้หน้าต่าง Evil Twin ขนาด 20 ที่ผ่าน temporal gate เป็น 5 / 8 / 15; ที่ 3.0 เป็น 25 / 51 / 49 การแบ่ง segment หลัง gap ที่ 1.5 ให้ 6 / 9 / 16 และสร้างหน้าต่างท้ายไม่ครบจำนวนมาก จึงไม่เลือกเกณฑ์ 3.0 เพียงเพื่อเพิ่มจำนวน; ช่วงที่ข้าม beacon ที่สังเกตไม่ครบอาจถูกยอมรับเข้ามา

**แนะนำให้ใช้หน้าต่างคงที่ แยก BSSID+capabilities พร้อม ML eligibility เฉพาะฟีเจอร์ configuration/radio/frame และคง Time-Shield gate เดิม** ทั้งสองคลาสในข้อมูลนี้มาจาก Evil Twin PCAP เดียวกัน มี independent labeled capture session **1** และ independent test session **0** จึงยังไม่รองรับ final model comparison หรือการอ้างผลกับ AP ใหม่ ผลโมเดล strict-policy ที่รันก่อนการตรวจ attrition ถูกตรึงไว้เป็นผล exploratory ใน `results/strict_policy_checkpoint.json` และไม่ได้ใช้เลือกเกณฑ์ใหม่

หลังล็อกเกณฑ์ดังกล่าว ได้รัน CART เบื้องต้นบน train และ validation เท่านั้น (Evil Twin 45/70 หน้าต่าง) ผล validation F1 = 1.0 โดยมี legitimate 86 และ Evil Twin 70 หน้าต่างใน validation การตรวจต้นไม้พบว่า **IE structure เป็นตัวแยกหลักเพียงตัวเดียว** ผลนี้จึงมีความเสี่ยงสูงที่จะจำ configuration ของ AP ใน capture เดิม และไม่ใช่หลักฐานว่าตรวจ AP ใหม่ได้ ไม่มีการคำนวณคะแนน development test สำหรับโมเดลนี้ ดู `models/exploratory_non_temporal_v1/validation_only.json`

ดูจำนวนแยกทุก class/session/stream/split/reason ที่ `attrition_by_stream.csv`, `attrition_by_reason.csv`, `window_attrition.csv`, `policy_support.csv` และ `feasibility_gate.csv` ตารางฟีเจอร์พร้อม flags ใหม่อยู่ใน `data/processed/ml_non_temporal_v1/` รายงานยืนยัน hash และ frame conservation ใน `manifest.json`
