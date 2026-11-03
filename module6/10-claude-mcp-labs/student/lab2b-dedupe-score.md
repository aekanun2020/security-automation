# Lab 2b — dedupe + score: ให้ Claude เขียน PySpark เอง แล้วคนตรวจโค้ด (G2)

**หัวข้อ** M6.2 (ตัวอย่าง 7.2 dedupe/risk score), M5.1 (อ่านและวิจารณ์ Python ที่ AI เขียน), M6.4 (ประเมินนโยบาย score) · **เวลา** 60 นาที · **ข้อมูล** curated Parquet จาก lab 2 ของตัวเอง (`/m6-10/<ชื่อ>/lab2-ids/curated`) · **ต้องผ่าน lab 2 ก่อน**

## โจทย์

lab 2 ใช้ template ที่เชื่อถือได้ lab นี้กลับด้าน: **ไม่มี template** Claude ต้องเขียน PySpark เองตามตรรกะตัวอย่าง 7.2 ของรายงาน research (fingerprint → window → score → route) ดังนั้น "หลักฐานว่าถูก" ไม่มาจาก sha256 ของ template อีกต่อไป แต่มาจาก (1) คนอ่านโค้ด (2) ผลรวมตรวจสอบได้ (sum event_count = alert เข้า) (3) ผลตรงกับที่คำนวณด้วยมือล่วงหน้า

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ บันทึกคำตอบในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | ก่อน submit ทำนายจำนวน offense ต่อ signature และรวมทั้งหมด พร้อมวิธีคิดจากช่วงห่างของ alert และขนาด window | ตัวเลขจากสถิติ lab 3 (interval, จำนวน, เวลาเริ่ม) + การหารด้วย 600 s |
| 2 | โค้ดที่ Claude เขียนใช้ window แบบ fixed หรือ sliding ต่างจากตัวอย่าง 7.2 อย่างไร และประกาศ deviation ไว้ตรงไหน | บรรทัดโค้ดจาก `spark_read_job` + docstring |
| 3 | fingerprint สร้างจากฟิลด์ใดบ้าง ตัดกี่ตัวอักษร | บรรทัดโค้ด |
| 4 | ผลจริง: `alerts_in`, `offenses_out`, `reduction_pct`, และ `sum_event_count` เท่ากับ alerts_in ไหม | report JSON + `hdfs_query_records` บน offenses (sum event_count) เป็นการตรวจอิสระ |
| 5 | จำนวน offense จริงต่อ signature ตรงกับที่ทำนายไหม ถ้าไม่ตรง ต่างตรงไหน | `by_signature` ใน report เทียบคำทำนายข้อ 1 |
| 6 | `by_route` แยกเป็นอะไรบ้าง ทำไม auto-close และ queue จึงเป็น 0 | report JSON + สูตร score |
| 7 | `raw_score` และ `magnitude` มีค่า min–max เท่าไร ทำไม magnitude เท่ากันทุกรายการ แสดงวิธีคำนวณจาก base(severity) + 8×asset_crit | report JSON + สูตรในโค้ด |
| 8 | เสนอวิธีแก้สูตรอย่างน้อย 1 วิธีที่ทำให้ beacon 10 ครั้งกับ SSH 4 ครั้งได้ score ต่างกัน | ข้อเสนอของผู้เรียน (ไม่มีคำตอบตายตัว) |
| 9 | "ลด alert ได้ 88%" บอกได้ไหมว่า TP หลุดกี่ % ทำไม | ชุดข้อมูลมี label หรือไม่ |

## prompt ที่ผู้เรียนพิมพ์

```
เขียน PySpark ที่อ่าน curated parquet ของ lab 2 แล้วทำตามตัวอย่าง 7.2 ใน docs/python-security-automation-research.md:
fingerprint = sha256 ของ signature_id|source_ip|destination_ip ตัด 16 ตัว, window 600 วินาที,
score = base(severity) + 8*asset_crit + min(10, 2*(repeats-1)) clamp 0..100, route <25 auto-close / >=60 escalate / อื่น queue
ให้ ASSET_CRIT ของ 10.70.0.66 = 4 ค่าอื่น 2 เขียน offenses เป็น JSON lines และ report สรุป
อย่าใช้ template ของ skill server แต่ให้อ่าน reference ของ skill author-debug-pyspark-security-jobs ก่อน
ก่อน submit ให้บอกผมว่าคาดว่าจะได้กี่ offense ต่อ signature
```

## ลำดับ tool ที่ควรเห็น

1. `log_skill_get` author-debug-pyspark-security-jobs → `log_skill_read_resource` references/pyspark-api-and-lineage.md และ security-report-checklist.md (กติกา: ห้าม `F.all`, ใช้ native function, ห้าม overwrite, submit SHA ที่ผ่าน dry run เท่านั้น)
2. Claude เขียนโค้ด → `spark_save_job` ชื่อใหม่ (`<ชื่อ>_lab2b_offense_v1.py`; แก้แล้วต้องเป็น v2 ไม่ทับ)
3. `spark_validate_job` (ได้แค่ valid_python + imports_pyspark; **ไม่มี** `log_skill_validate_spark_job` เพราะไม่มี policy สำหรับงานนี้)
4. `hdfs_mkdir` → `spark_submit_job` (argv = curated parquet, offenses path, report path) → `spark_job_status` จน SUCCEEDED
5. `hdfs_read_text` report, `hdfs_query_records` บน offenses (group_by signature, route; sum event_count; distinct window_start, destination_ip) เพื่อตรวจผลรวมด้วย tool อิสระ
6. `hdfs_sha256` ทั้ง report และ offenses

## บันทึกคำตอบ

กรอกให้ครบทุกข้อตามเลขในตาราง "สิ่งที่ต้องค้นให้ได้" ค่าทุกค่าต้องชี้กลับไปที่ tool และฟิลด์ที่อ่านมา

| # | คำตอบ | tool → ฟิลด์/บรรทัดที่อ่านค่ามา |
| --- | --- | --- |
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |

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
