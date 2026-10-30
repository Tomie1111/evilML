# Dataset audit และ label verification — รอบแรก

## ขอบเขตและผลตัดสิน

**ยังไม่อนุญาต supervised training ตามนิยาม verified ใน protocol รอบนี้**: มีหลักฐานบทความผู้จัดทำรองรับ dataset-role mapping แต่ไม่มี independent device/event logs และยังไม่ได้รับการยอมรับ proposed labeling protocol สำหรับใช้ candidate roles เป็น training targets.

คำว่า verified ในรายงานนี้หมายถึงตัวตนอุปกรณ์ที่มีหลักฐานอิสระผูกกับ capture ไม่ใช่เพียงตรวจว่า CSV ตรงกับ PCAP หรือ attack filter. การแยกสถานะนี้ไม่ได้หักล้างคำอธิบาย testbed ของผู้จัดทำหรือ NORMAL labels ในงานเดิม.

## สิ่งที่ตรวจยืนยันได้จากไฟล์

- พบ capture files 14 ไฟล์ (รวม derived pcapng); original PCAP 13 ไฟล์.
- labeled beacon 19,407 แถว; attack-frame label table 105,661 แถว.
- ใช้ primary key `(pcap path, original frame number)` และตรวจ uniqueness ก่อน join; ไม่ใช้ row index.
- นับเฟรมและ hash PCAP ทุกไฟล์ด้วย capinfos; re-extract Beacon และ replay filter ทางการจาก Read_me.txt เฉพาะ Evil_Twin/Rogue_AP.
- อ่าน PCAP ผ่าน TShark subprocess ลง CSV โดยตรง; ไม่โหลด PCAP ทั้งก้อนใน RAM.

| การตรวจ | ผล |
|---|---|
| duplicate_labeled_keys | 0 |
| duplicate_attack_label_keys | 0 |
| existing_label_join_mismatches | 0 |
| pcap_beacon_mismatches | 0 |
| pcap_official_filter_mismatches | 0 |
| raw_csv_mismatches | 2 |
| every_labeled_capture_inspected | True |
| scenario_annotations_consistent | True |
| attack_scenario_labels_consistent | True |

ผล integrity ใช้ canonical labeled CSV/attack-label CSV เทียบ PCAP โดยตรง. ไฟล์ raw CSV เดิมเป็นหลักฐานเสริมและแยกรายงานความต่าง ไม่ให้การขาดแถวในสำเนาเสริม กลายเป็นข้อสรุปว่า canonical labels ผิด.

| Capture | เฟรมทั้งหมด | Beacon | ตรง official filter ทุกชนิดเฟรม |
|---|---:|---:|---:|
| pcaps/4. Rogue_AP.pcap | 1,973,193 | 6,946 | 1,310 |
| pcaps/7. Evil_Twin.pcap | 3,778,728 | 12,461 | 104,351 |

| Identity status | จำนวน |
|---|---:|
| verified_legitimate | 0 |
| verified_evil_twin | 0 |
| candidate_legitimate | 8,685 |
| candidate_evil_twin | 3,776 |
| unknown | 6,946 |

## หลักฐานและข้อสมมติ

- [บทความผู้จัดทำ](https://www.researchgate.net/publication/349539294_Empirical_Evaluation_of_Attacks_Against_IEEE_80211_Enterprise_Networks_The_AWID3_Dataset), DOI 10.1109/ACCESS.2021.3061609, หัวข้อ Evil_Twin อธิบาย MAC suffix ของ rogue ต่างจาก legitimate และใช้ configuration เดิมใน implementation ถัดไป.
- Read_me.txt ระบุ full address ใน filter; การรวมหลักฐานนี้กับ role mapping เดิมรองรับ candidate roles สำหรับ capture นี้ แต่ไม่ใช่การตรวจยืนยันตัวส่งจาก MAC เพียงอย่างเดียว.
- เก็บ attack_related_label, attack_label_status และ legacy beacon_role_label เดิมไว้ครบ แล้วเพิ่ม identity_status กับ evidence_id; unknown ไม่ถูกแทนด้วย NORMAL.
- Rogue_AP ใช้ same-BSSID และไม่มี identity annotations ที่แยกอุปกรณ์ได้ในชุดนี้ จึงคง unknown ทั้ง capture.
- แถวที่ไม่ตรง filter ไม่ได้แปลว่าปกติ; ช่วงก่อน/หลัง filter ไม่ใช่ device power-on/off logs.

## ความเสี่ยง leakage และ shortcut

- ห้าม predictive inputs: SSID/BSSID/MAC, frame number, absolute timestamp, raw TSF, capture filename/scenario, stream ID และ label/provenance ทุกชนิด.
- `src/preprocessing.py` ใช้ feature allowlist; ชื่ออื่นถูกปฏิเสธ เพื่อไม่หลุดด้วยการ rename ฟิลด์.
- Capability/RSN/IE/rates/frame length อาจจำ configuration ของ AP; frame length ยังเป็นส่วนหนึ่งของ filter จึงเสี่ยง label-definition shortcut หากนำ filter matches เป็น target.
- RSSI อาจแทนตำแหน่ง receiver; channel/beacon interval อาจคงที่ ต้องตัดสินความคงที่จาก train เท่านั้น.
- ไม่แบ่ง beacon แบบ random; มี Evil_Twin session เดียว จึงยังทดสอบ unseen physical AP ไม่ได้.
- การแบ่งตามเวลาอาจทำให้ train ไม่มี class โจมตี หรือเห็นเพียง profile แรก ต้องตรวจ class/profile support ก่อน fit.
- ตาราง shortcut ใน audit ใช้อธิบายข้อจำกัด ไม่ใช้เลือกฟีเจอร์จาก test data.

## ฟีเจอร์และคุณภาพ

- feature_availability.csv ระบุ field จริง วิธีคำนวณที่เสนอ อัตราว่างระดับ source-frame และความเสี่ยงราย feature/capture.
- Configuration: capabilities, RSN presence/capabilities, cipher/AKM suites, supported rates, selected IE structure, beacon interval.
- Radio: antenna RSSI, frequency; ยังไม่มี independent receiver capture เพื่อรับรอง field compatibility.
- Frame: length, modulo-4096 sequence increments, retry. Sequence jump ไม่พิสูจน์ beacon loss.
- Temporal: receive time/TSF มีให้คำนวณ interarrival/MAD/slope; stream_quality.csv รายงาน gaps/nonpositive deltas. ต้องไม่ regress ข้าม TSF reset และต้องแยก candidate streams.
- RSN fields ว่างใน open profile เป็น structural absence ได้ ไม่ควรเติม cipher เอง; RSN presence ต้องอาศัย IE parsing ที่สมบูรณ์.
- ใช้ timestamp แบบ Decimal/integer ns ไม่แปลง absolute epoch เป็น float; CSV summary เก่าบางไฟล์มีเศษเวลาจาก float จึงไม่ใช้เป็นฐาน join.
- full_capture_inventory.csv นับ total frames ครบ; beacon count ของ captures นอกสองกรณีที่ตรวจเป็นช่องว่าง (not inspected), ไม่ใช่ศูนย์.
- derived pcapng มีเลขเฟรมใหม่ ห้าม join กับ source capture ด้วยหมายเลขเฟรมตรง ๆ.

- พบ supplemental raw CSV discrepancies 2 แถว; ดู raw_csv_join_audit.csv. ในข้อมูลรอบนี้ Rogue_AP.csv ขาดเฟรม 211266 และ 231295 แต่ PCAP/labeled CSV มีทั้งสองเฟรม และขาด fixed beacon fields ตาม flagged_beacons.csv. ไม่ทราบเหตุผลการคัดออกใน exporter เก่า จึงไม่ใช้ไฟล์เสริมนี้แทน PCAP.
- พบ nonpositive temporal boundaries ภายใน diagnostic streams 1 จุด; ดู temporal_discontinuities.csv. ต้อง flag หน้าต่างที่ข้ามจุดเหล่านี้ ไม่คำนวณ slope ข้าม reset.

## ผลกระทบต่อ Time-Shield เดิม

ดู previous_time_shield_overlap.csv: enrollment อยู่ก่อน first observed rogue; calibration คร่อมช่วงนั้น และ holdout อยู่หลังเริ่มพบ rogue. การแจ้งเตือนบน legitimate stream ไม่เท่ากับ FPR ในสภาพแวดล้อมปลอดโจมตี. งานนี้ไม่แก้ baseline ไม่ fit ซ้ำ และไม่ปรับ threshold.

## สิ่งที่ยังไม่ได้ทำและทางไปต่อ

ขั้นตอน 1–3 ของ execution list เสร็จในขอบเขต audit นี้. ยังไม่สร้าง window feature datasets, split สำหรับ ML, model artifacts, performance metrics, ablation หรือ fusion. ต้องยอมรับ labeling_protocol.md ก่อนใช้ candidate roles เป็น targets หรือเพิ่ม independent device/event evidence.

จากนั้นสร้างหน้าต่าง 10/20/50 beacon พร้อม conservative mixed/unknown policy, ตรวจ chronology/class support, fit preprocessing เฉพาะ train และทดลอง CART/RF/LR ก่อนเชื่อม Time-Shield. รายงาน preliminary same-capture performance แยกจาก independent-AP evaluation ซึ่งยังไม่มีข้อมูล.

ผลตรวจ CSV/PCAP สอดคล้องกันไม่ใช่การรับรอง identity โดยตัวมันเอง และไม่มีการสร้างข้อมูลหรือ metrics เทียม.
