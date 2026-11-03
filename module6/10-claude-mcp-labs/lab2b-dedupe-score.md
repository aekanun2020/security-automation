# Lab 2b — dedupe + score: ให้ Claude เขียน PySpark เอง แล้วคนตรวจโค้ด (G2)

**หัวข้อ** M6.2 (ตัวอย่าง 7.2 dedupe/risk score), M5.1 (อ่านและวิจารณ์ Python ที่ AI เขียน), M6.4 (ประเมินนโยบาย score) · **เวลา** 60 นาที · **ข้อมูล** curated Parquet จาก lab 2 (`/module7/lab2-ids/curated`) · **ต้องผ่าน lab 2 ก่อน**

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

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | alert 340 รายการ ถ้าต้องเปิดดูทีละอันคงไม่ไหว รวมเป็นเรื่อง (offense) ได้กี่เรื่อง | report: `alerts_in`, `offenses_out`, `reduction_pct` + `hdfs_query_records` บน offenses (ต้องเป็น part file เดียว คือโค้ด coalesce(1)) ตรวจว่า sum event_count = alerts_in | ตรวจ |
| 2 | ก่อนรัน เราเดาได้ไหมว่าจะเหลือกี่เรื่อง จากจังหวะของ alert แต่ละชนิดและขนาด window | สถิติ interval จาก lab 3 หารด้วย window 600 s ต่อ signature | ตรวจ |
| 3 | เรื่องไหนควรขึ้นหัวคิว beacon DNS 120 ครั้ง, ส่งข้อมูลออก 6 MB, หรือ SSH ไป 25 เครื่อง ระบบจัดให้เราแบบไหน | report: `by_signature`, `by_route`, `raw_score` และ `magnitude` ของแต่ละ offense | ตรวจ |
| 4 | ทำไม score ของทุกเรื่องเท่ากันหมด แล้ว analyst จะเรียงลำดับงานอย่างไร | สูตรในโค้ด: base(severity) + 8×asset_crit ชนเพดาน 100 ก่อนคิด burst | ตัดสิน |
| 5 | ถ้าจะแก้สูตร แก้ตรงไหน และใครควรเป็นคนกำหนด asset criticality กับ threshold escalate | ข้อเสนอของผู้เรียน อ้างตัวเลข raw_score ที่ได้ | ตัดสิน |
| 6 | "ลด alert ได้ 88%" ฟังดูดี แต่เราทิ้งเรื่องจริงไปด้วยหรือเปล่า วัดได้ไหม | ชุดข้อมูลมี label TP/FP หรือไม่ | ตัดสิน |
| 7 | โค้ดที่คุณเขียนเองโดยไม่มี template ไว้ใจได้เท่า lab 2 ไหม ก่อน submit ต้องดูอะไร | อ่านโค้ดจาก `spark_read_job`: fingerprint ใช้ฟิลด์ไหน, window fixed หรือ sliding (ต่างจาก 7.2 ไหม ประกาศ deviation หรือยัง), clamp ถูกทิศไหม, ไม่มี `log_skill_validate_spark_job` ให้ใช้ | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. `log_skill_get` author-debug-pyspark-security-jobs → `log_skill_read_resource` references/pyspark-api-and-lineage.md และ security-report-checklist.md (กติกา: ห้าม `F.all`, ใช้ native function, ห้าม overwrite, submit SHA ที่ผ่าน dry run เท่านั้น)
2. Claude เขียนโค้ด → `spark_save_job` ชื่อใหม่ (`module7_lab2b_offense_v1.py`; แก้แล้วต้องเป็น v2 ไม่ทับ)
3. `spark_validate_job` (ได้แค่ valid_python + imports_pyspark; **ไม่มี** `log_skill_validate_spark_job` เพราะไม่มี policy สำหรับงานนี้)
4. `hdfs_mkdir` → `spark_submit_job` (argv = curated parquet, offenses path, report path) → `spark_job_status` จน SUCCEEDED
5. `hdfs_read_text` report, `hdfs_query_records` บน offenses (group_by signature, route; sum event_count; distinct window_start, destination_ip) เพื่อตรวจผลรวมด้วย tool อิสระ — ใช้ได้ต่อเมื่อโค้ดเขียน offenses ด้วย `coalesce(1)` ให้เป็น part file เดียว ถ้าปล่อยให้ Spark เขียนหลาย part (เช่น 39 ไฟล์) tool จะคืน `Expected an HDFS file` เมื่อชี้ที่ directory
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

**รันซ้ำ 2026-11-03** (job `b8d8a9ff…`, โค้ดเขียนใหม่โดยไม่ดูโค้ดเฉลย sha `b0e07fdc…`): ทำนาย 39 ก่อน submit แล้วได้ 39 / 88.53 / 12-25-2 / raw 123–127 / magnitude 100 / escalate 39 / fingerprint แรก cd71af772d9c38bb เท่ากันทุกค่า ทั้งที่โค้ดคนละชุด แสดงว่าผลถูกกำหนดโดยข้อมูลและสูตร ไม่ใช่โค้ดเฉพาะครั้ง รอบ 2 (job `307f14e3…`, โค้ดเพิ่ม coalesce(1)) `hdfs_query_records` บน offenses part file เดียวคืน 3 กลุ่ม sum event_count 100/120/120 = 340 และ distinct window_start 1/12/2 ตามเฉลย

**บทเรียนหลักของ lab นี้** สูตร 7.2 กับข้อมูลนี้ให้ magnitude 100 ทุกรายการ เพราะ severity 1 ของ Suricata แปลงเป็น base 85 บวก asset_crit 4×8 = 32 ก็เกิน 100 แล้วก่อนคิด burst — score จึง**ไม่แยกลำดับความสำคัญ**ระหว่าง beacon 10 ครั้ง กับ SSH 4 ครั้ง ผู้เรียนต้องเสนอว่าจะแก้อย่างไร (ลด base, ใช้ severity ของ Suricata ตรง ๆ ที่ 1 = สูงสุด, ถ่วงด้วย event_count แบบ log, หรือใช้ fp_rate จาก label เมื่อมี)

## จุดที่คนต้องทำ

- **อ่านโค้ดทุกบรรทัด** ก่อน submit: fingerprint ใช้ฟิลด์ไหน, window เป็น fixed หรือ sliding (โค้ดเฉลยเป็น fixed `floor(epoch/600)` ซึ่ง**ต่างจาก 7.2** ที่เป็น sliding deque — Claude ต้องประกาศ deviation ใน docstring), clamp ถูกทิศไหม
- ทำนายผลก่อนรัน แล้วเทียบ — ถ้าตรง แสดงว่าเข้าใจทั้งข้อมูลและโค้ด
- ตัดสินนโยบาย: threshold escalate 60 เหมาะกับองค์กรไหม, ASSET_CRIT ใครเป็นคนกำหนด
- สังเกตว่า report ของ lab นี้ **ไม่มี contract** ใน skill server (`report_contract_version: lab2b-offense-report-v0`) → ความน่าเชื่อถือต่ำกว่า lab 2 โดยออกแบบ

## Claude ผิดตรงไหนได้บ้าง

- เรียก `F.all(...)` หรือ API ที่ไม่มี → ต้องดู reference ก่อน
- ใช้ sliding window ด้วย Python UDF + deque บน Spark → ช้าและผิด semantics ของ distributed; ให้ Claude อธิบายว่าทำไมเลือก fixed window และผลต่างคืออะไร
- เขียน offenses โดยไม่ `coalesce(1)` → ได้ part file เท่าจำนวน offense แล้ว `hdfs_query_records`/`hdfs_sha256` ใช้กับ directory ไม่ได้ ต้องชี้ทีละไฟล์หรือเขียนใหม่ (เกิดจริงตอนรันซ้ำ 2026-11-03)
- แก้โค้ดแล้ว save ทับชื่อเดิม → snapshot ของ job เก่าหายไม่ได้ (server เก็บ) แต่ผิดกติกา repair discipline ของ skill
- บอกว่า "ลด alert ได้ 88% ดีมาก" โดยไม่พูดถึงว่า TP หลุดกี่ % — ชุดนี้ไม่มี label จึง**วัดไม่ได้** ต้องรายงานว่าวัดไม่ได้ ไม่ใช่สรุปว่าดี
