# Lab 2b — dedupe + score: ให้ Claude เขียน PySpark เอง แล้วคนตรวจโค้ด (G2)

**หัวข้อ** M6.2 (ตัวอย่าง 7.2 dedupe/risk score), M5.1 (อ่านและวิจารณ์ Python ที่ AI เขียน), M6.4 (ประเมินนโยบาย score) · **เวลา** 60 นาที · **ข้อมูล** curated Parquet จาก lab 2 (`/module7/lab2-ids/curated`) · **ต้องผ่าน lab 2 ก่อน**

## โจทย์

lab 2 ใช้ template ที่เชื่อถือได้ lab นี้กลับด้าน: **ไม่มี template** Claude ต้องเขียน PySpark เองตามตรรกะตัวอย่าง 7.2 ของรายงาน research (fingerprint → window → score → route) ดังนั้น "หลักฐานว่าถูก" ไม่มาจาก sha256 ของ template อีกต่อไป แต่มาจาก (1) คนอ่านโค้ด (2) ผลรวมตรวจสอบได้ (sum event_count = alert เข้า) (3) ผลตรงกับที่คำนวณด้วยมือล่วงหน้า

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ คำตอบอยู่ในส่วนเฉลยด้านล่าง

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
2. Claude เขียนโค้ด → `spark_save_job` ชื่อใหม่ (`module7_lab2b_offense_v1.py`; แก้แล้วต้องเป็น v2 ไม่ทับ)
3. `spark_validate_job` (ได้แค่ valid_python + imports_pyspark; **ไม่มี** `log_skill_validate_spark_job` เพราะไม่มี policy สำหรับงานนี้)
4. `hdfs_mkdir` → `spark_submit_job` (argv = curated parquet, offenses path, report path) → `spark_job_status` จน SUCCEEDED
5. `hdfs_read_text` report, `hdfs_query_records` บน offenses (group_by signature, route; sum event_count; distinct window_start, destination_ip) เพื่อตรวจผลรวมด้วย tool อิสระ
6. `hdfs_sha256` ทั้ง report และ offenses

## เฉลย (รันจริง 2026-11-02 job `291d645c-75c3-4e96-9862-0a1555474f41`, code sha256 `9ec912f1…`, 15 วินาที)

**คำทำนายก่อน submit** (คนควรคำนวณได้จากสถิติ lab 3): C2 DNS 120 event ห่าง 60 s → 12 window ละ 10 → **12 offense**; Outbound 120 event ห่าง 10 s เริ่ม 02:10:00 ซึ่งตรงขอบ window พอดี (1787537400 / 600 = 2979229 ลงตัว) → **2 offense** (60 + 60); East-West 100 event ไป 25 host ภายใน 4 นาที → fingerprint ต่างกันตาม destination → **25 offense** ละ 4 event; รวม **39**

**ผลจริง** (report sha256 `3137c7e1…`, offenses sha256 `7c6c4385…`)

| ตัวเลข | ค่า |
| --- | --- |
| alerts_in | 340 |
| offenses_out | **39** |
| reduction_pct | **88.53** |
| sum_event_count = alerts_in | true (340) |
| by_signature | C2 DNS 12 offense / 120 event / 12 window; East-West 25 / 100 / 1 window; Outbound 2 / 120 / 2 window |
| by_route | escalate 39 (auto-close 0, queue 0) |
| raw_score min–max | 123–127 |
| magnitude min–max | **100–100** |

offense แรก: fingerprint `cd71af772d9c38bb` window 00:00–00:09 event_count 10 raw_score 127 → magnitude 100 → escalate

**บทเรียนหลักของ lab นี้** สูตร 7.2 กับข้อมูลนี้ให้ magnitude 100 ทุกรายการ เพราะ severity 1 ของ Suricata แปลงเป็น base 85 บวก asset_crit 4×8 = 32 ก็เกิน 100 แล้วก่อนคิด burst — score จึง**ไม่แยกลำดับความสำคัญ**ระหว่าง beacon 10 ครั้ง กับ SSH 4 ครั้ง ผู้เรียนต้องเสนอว่าจะแก้อย่างไร (ลด base, ใช้ severity ของ Suricata ตรง ๆ ที่ 1 = สูงสุด, ถ่วงด้วย event_count แบบ log, หรือใช้ fp_rate จาก label เมื่อมี)

## จุดที่คนต้องทำ

- **อ่านโค้ดทุกบรรทัด** ก่อน submit: fingerprint ใช้ฟิลด์ไหน, window เป็น fixed หรือ sliding (โค้ดเฉลยเป็น fixed `floor(epoch/600)` ซึ่ง**ต่างจาก 7.2** ที่เป็น sliding deque — Claude ต้องประกาศ deviation ใน docstring), clamp ถูกทิศไหม
- ทำนายผลก่อนรัน แล้วเทียบ — ถ้าตรง แสดงว่าเข้าใจทั้งข้อมูลและโค้ด
- ตัดสินนโยบาย: threshold escalate 60 เหมาะกับองค์กรไหม, ASSET_CRIT ใครเป็นคนกำหนด
- สังเกตว่า report ของ lab นี้ **ไม่มี contract** ใน skill server (`report_contract_version: lab2b-offense-report-v0`) → ความน่าเชื่อถือต่ำกว่า lab 2 โดยออกแบบ

## Claude ผิดตรงไหนได้บ้าง

- เรียก `F.all(...)` หรือ API ที่ไม่มี → ต้องดู reference ก่อน
- ใช้ sliding window ด้วย Python UDF + deque บน Spark → ช้าและผิด semantics ของ distributed; ให้ Claude อธิบายว่าทำไมเลือก fixed window และผลต่างคืออะไร
- แก้โค้ดแล้ว save ทับชื่อเดิม → snapshot ของ job เก่าหายไม่ได้ (server เก็บ) แต่ผิดกติกา repair discipline ของ skill
- บอกว่า "ลด alert ได้ 88% ดีมาก" โดยไม่พูดถึงว่า TP หลุดกี่ % — ชุดนี้ไม่มี label จึง**วัดไม่ได้** ต้องรายงานว่าวัดไม่ได้ ไม่ใช่สรุปว่าดี
