# Lab 2b — dedupe + score: ให้ Claude เขียน PySpark เอง แล้วคนตรวจโค้ด (G2)

**หัวข้อ** M6.2 (ตัวอย่าง 7.2 dedupe/risk score), M5.1 (อ่านและวิจารณ์ Python ที่ AI เขียน), M6.4 (ประเมินนโยบาย score) · **เวลา** 60 นาที · **ข้อมูล** curated Parquet จาก lab 2 ของตัวเอง (`/m6-10/<ชื่อ>/lab2-ids/curated`) · **ต้องผ่าน lab 2 ก่อน**

## โจทย์

lab 2 ใช้ template ที่เชื่อถือได้ lab นี้กลับด้าน: **ไม่มี template** Claude ต้องเขียน PySpark เองตามตรรกะตัวอย่าง 7.2 ของรายงาน research (fingerprint → window → score → route) ดังนั้น "หลักฐานว่าถูก" ไม่มาจาก sha256 ของ template อีกต่อไป แต่มาจาก (1) คนอ่านโค้ด (2) ผลรวมตรวจสอบได้ (sum event_count = alert เข้า) (3) ผลตรงกับที่คำนวณด้วยมือล่วงหน้า

## prompt ที่ผู้เรียนพิมพ์

```
เขียน PySpark ที่อ่าน curated parquet ของ lab 2 แล้วทำตามตัวอย่าง 7.2 ใน docs/python-security-automation-research.md:
fingerprint = sha256 ของ signature_id|source_ip|destination_ip ตัด 16 ตัว, window 600 วินาที,
score = base(severity) + 8*asset_crit + min(10, 2*(repeats-1)) clamp 0..100, route <25 auto-close / >=60 escalate / อื่น queue
ให้ ASSET_CRIT ของ 10.70.0.66 = 4 ค่าอื่น 2 เขียน offenses เป็น JSON lines และ report สรุป
อย่าใช้ template ของ skill server แต่ให้อ่าน reference ของ skill author-debug-pyspark-security-jobs ก่อน
ก่อน submit ให้บอกผมว่าคาดว่าจะได้กี่ offense ต่อ signature
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง บันทึกในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | alert 340 รายการ ถ้าต้องเปิดดูทีละอันคงไม่ไหว รวมเป็นเรื่อง (offense) ได้กี่เรื่อง | report: `alerts_in`, `offenses_out`, `reduction_pct` + `hdfs_query_records` บน offenses ตรวจว่า sum event_count = alerts_in | ตรวจ |
| 2 | ก่อนรัน เราเดาได้ไหมว่าจะเหลือกี่เรื่อง จากจังหวะของ alert แต่ละชนิดและขนาด window | สถิติ interval จาก lab 3 หารด้วย window 600 s ต่อ signature | ตรวจ |
| 3 | เรื่องไหนควรขึ้นหัวคิว beacon DNS 120 ครั้ง, ส่งข้อมูลออก 6 MB, หรือ SSH ไป 25 เครื่อง ระบบจัดให้เราแบบไหน | report: `by_signature`, `by_route`, `raw_score` และ `magnitude` ของแต่ละ offense | ตรวจ |
| 4 | ทำไม score ของทุกเรื่องเท่ากันหมด แล้ว analyst จะเรียงลำดับงานอย่างไร | สูตรในโค้ด: base(severity) + 8×asset_crit ชนเพดาน 100 ก่อนคิด burst | ตัดสิน |
| 5 | ถ้าจะแก้สูตร แก้ตรงไหน และใครควรเป็นคนกำหนด asset criticality กับ threshold escalate | ข้อเสนอของผู้เรียน อ้างตัวเลข raw_score ที่ได้ | ตัดสิน |
| 6 | "ลด alert ได้ 88%" ฟังดูดี แต่เราทิ้งเรื่องจริงไปด้วยหรือเปล่า วัดได้ไหม | ชุดข้อมูลมี label TP/FP หรือไม่ | ตัดสิน |
| 7 | โค้ดที่คุณเขียนเองโดยไม่มี template ไว้ใจได้เท่า lab 2 ไหม ก่อน submit ต้องดูอะไร | อ่านโค้ดจาก `spark_read_job`: fingerprint ใช้ฟิลด์ไหน, window fixed หรือ sliding (ต่างจาก 7.2 ไหม ประกาศ deviation หรือยัง), clamp ถูกทิศไหม, ไม่มี `log_skill_validate_spark_job` ให้ใช้ | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. `log_skill_get` author-debug-pyspark-security-jobs → `log_skill_read_resource` references/pyspark-api-and-lineage.md และ security-report-checklist.md (กติกา: ห้าม `F.all`, ใช้ native function, ห้าม overwrite, submit SHA ที่ผ่าน dry run เท่านั้น)
2. Claude เขียนโค้ด → `spark_save_job` ชื่อใหม่ (`<ชื่อ>_lab2b_offense_v1.py`; แก้แล้วต้องเป็น v2 ไม่ทับ)
3. `spark_validate_job` (ได้แค่ valid_python + imports_pyspark; **ไม่มี** `log_skill_validate_spark_job` เพราะไม่มี policy สำหรับงานนี้)
4. `hdfs_mkdir` → `spark_submit_job` (argv = curated parquet, offenses path, report path) → `spark_job_status` จน SUCCEEDED
5. `hdfs_read_text` report, `hdfs_query_records` บน offenses (group_by signature, route; sum event_count; distinct window_start, destination_ip) เพื่อตรวจผลรวมด้วย tool อิสระ
6. `hdfs_sha256` ทั้ง report และ offenses

## บันทึกคำตอบ

กรอกทีละข้อตามเลขในตาราง "คำถามที่ถาม Claude ต่อ" คอลัมน์ 2 คือสิ่งที่ Claude ตอบ (ย่อได้ แต่ตัวเลขต้องตรง) คอลัมน์ 3 คือ tool และฟิลด์ที่ Claude อ้าง ถ้า Claude ไม่อ้าง ให้สั่งถามใหม่ก่อนกรอก คอลัมน์ 4: ข้อประเภท ตรวจ ให้เขียนว่าเทียบกับ output ดิบแล้วตรงไหม (อย่างน้อย 1 ข้อต่อ lab ต้องเทียบจริง) ข้อประเภท ตัดสิน ให้เขียนคำตัดสินของตัวเองและเหตุผล

| # | Claude ตอบว่า | อ้าง tool → ฟิลด์ | ตรวจแล้วตรงไหม / ตัดสินว่าอย่างไร |
| --- | --- | --- | --- |
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |

## จุดที่คนต้องทำ

- **อ่านโค้ดทุกบรรทัด** ก่อน submit: fingerprint ใช้ฟิลด์ไหน, window เป็น fixed หรือ sliding (ตัวอย่าง 7.2 เป็น sliding deque — ถ้าโค้ดต่างจากนั้น Claude ต้องประกาศ deviation ใน docstring), clamp ถูกทิศไหม
- ทำนายผลก่อนรัน แล้วเทียบ — ถ้าตรง แสดงว่าเข้าใจทั้งข้อมูลและโค้ด
- ตัดสินนโยบาย: threshold escalate 60 เหมาะกับองค์กรไหม, ASSET_CRIT ใครเป็นคนกำหนด
- สังเกตว่า report ของ lab นี้ **ไม่มี contract** ใน skill server (`report_contract_version: lab2b-offense-report-v0`) → ความน่าเชื่อถือต่ำกว่า lab 2 โดยออกแบบ

## Claude ผิดตรงไหนได้บ้าง

- เรียก `F.all(...)` หรือ API ที่ไม่มี → ต้องดู reference ก่อน
- ใช้ sliding window ด้วย Python UDF + deque บน Spark → ช้าและผิด semantics ของ distributed; ให้ Claude อธิบายว่าทำไมเลือก fixed window และผลต่างคืออะไร
- แก้โค้ดแล้ว save ทับชื่อเดิม → snapshot ของ job เก่าหายไม่ได้ (server เก็บ) แต่ผิดกติกา repair discipline ของ skill
- บอกว่า "ลด alert ได้ x% ดีมาก" โดยไม่พูดถึงว่า TP หลุดกี่ % — ชุดนี้ไม่มี label จึง**วัดไม่ได้** ต้องรายงานว่าวัดไม่ได้ ไม่ใช่สรุปว่าดี
