# Lab 2 — Spark report: จาก alert 340 บรรทัดเป็น ids-report-v1 (G2)

**หัวข้อ** M5.2 (batch analytics), M6.2 (alert aggregate), M5.3 (sha256, idempotency), M5.1 (อ่าน PySpark) · **เวลา** 45 นาที · **ข้อมูล** Suricata alerts ใน HDFS

## โจทย์

ให้ Claude สร้างรายงานสรุป alert ตาม contract `ids-report-v1` โดยใช้ Spark job ที่ render จาก template ที่เชื่อถือได้ ผู้เรียนต้องตรวจทุกจุดที่ server ให้หลักฐาน: sha256 ของโค้ด, สถานะ job, และ report ผ่าน contract

## prompt ที่ผู้เรียนพิมพ์

```
สร้าง ids-report จาก /student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
ด้วย parser suricata-eve-alert-json-v1 เขียน output ไว้ที่ /m6-10/<ชื่อผู้เรียน>/lab2-ids
ให้ validate ทั้งก่อน submit และ validate report หลังจบ แล้วสรุปตัวเลขให้ดู
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง บันทึกในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | alert 340 รายการใน 3 ชั่วโมงนี้ สรุปแล้วเห็นภาพอะไร rule ไหนยิงมากสุด เป็นพฤติกรรมประเภทไหน | report JSON: `top_signatures`, `top_categories`, `severity_summary` | ตรวจ |
| 2 | มาจากเครื่องเดียวหรือหลายเครื่อง ไปหาใครบ้าง | report JSON: `top_source_ips`, `top_destination_ips` (รวม host ที่โดนทีละน้อย) | ตรวจ |
| 3 | alert พวกนี้ถูก block แล้ว หรือ IDS แค่เห็นแล้วปล่อยผ่าน | report JSON: `top_alert_actions` | ตรวจ |
| 4 | เริ่มกี่โมง จบกี่โมง ตอนนี้ยังเกิดอยู่ไหม | report JSON: `event_time_min`, `event_time_max` เทียบเวลาปัจจุบันของข้อมูล | ตรวจ |
| 5 | log ทุกบรรทัดถูกนับครบไหม มีบรรทัดที่ parse ไม่ได้แล้วหลุดจากรายงานหรือเปล่า | report JSON: `total_records`, `parse_quality.parsed`, `parse_quality.failed` | ตรวจ |
| 6 | รายงานนี้เชื่อได้แค่ไหน โค้ดที่รันคือโค้ดที่ตรวจแล้วจริงไหม รันเมื่อไร ใครตรวจ | sha256 ของโค้ดที่ render, save, validate expected, snapshot ของ job ต้องตรงกัน + job_id, เวลา, สถานะ SUCCEEDED + `log_skill_validate_report` | ตรวจ |
| 7 | ทำไมคุณต้องลองสองรอบกว่าจะ render โค้ดได้ และเราควรให้มันแก้ template เองไหม | error ของ `log_skill_render_spark_job` รอบแรก + `matches_trusted_template` ของ `log_skill_validate_spark_job` | ตัดสิน |
| 8 | ถ้าพรุ่งนี้ต้องทำรายงานเดิมอีก จะได้ผลเดิมไหม และทำไมระบบห้ามเขียนทับ output เก่า | idempotency_key ใน `spark_submit_job` + พฤติกรรม `errorifexists` ในโค้ด | ตรวจ |
| 9 | รายงานนี้บอกได้ไหมว่าเกิด incident | report บอกสถิติ ไม่มี verdict (กติกาข้อ 5 ของ skill) | ตัดสิน |

## ลำดับ tool ที่ควรเห็น (11 ขั้น)

| # | tool | server | ผลที่ต้องเห็น |
| --- | --- | --- | --- |
| 1 | `log_skill_get` analyze-ids-alerts-with-spark | skill | กติกา 6 ข้อ: ใช้ parser ids/json_lines เท่านั้น, model ไม่เขียน PySpark |
| 2 | `log_skill_render_spark_job` (skill, parser_id) | skill | code + `code_sha256` — ถ้าได้ error ให้อ่านข้อความแล้วคิดว่าต้องใช้ skill ชนิดใด |
| 3 | `spark_save_job` filename, code | spark | `sha256` ต้องเท่ากับข้อ 2 |
| 4 | `hdfs_mkdir` /m6-10/<ชื่อ>/lab2-ids | spark | คืน physical path `/mcp/m6-10/...` |
| 5 | `spark_validate_job` | spark | valid_python, imports_pyspark |
| 6 | `log_skill_validate_spark_job` (code) | skill | `matches_trusted_template: true` + รายการ checks |
| 7 | `spark_submit_job` arguments = [physical input, physical curated, physical report], idempotency_key, expected_sha256 | spark | status RUNNING, job_id |
| 8 | `spark_job_status` (วนจนกว่าจะไม่ใช่ RUNNING) | spark | **SUCCEEDED** exit_code 0 |
| 9 | `hdfs_list` report dir → `hdfs_read_text` part-*.txt | spark | JSON 1 บรรทัด |
| 10 | `log_skill_validate_report` | skill | `valid: true` |
| 11 | `hdfs_sha256` ของ report | spark | เก็บไว้ใน hashes.json |

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
| 8 | | | |
| 9 | | | |

## จุดที่คนต้องทำ

- ยืนยันว่า sha256 ตรงกันทั้ง 4 จุดก่อนอนุมัติผล (Claude อาจบอกว่า "ตรง" โดยไม่ได้เทียบ)
- อ่าน PySpark ที่ render (ประมาณ 80 บรรทัด) แล้วตอบ: บรรทัดไหนทำให้ record กลายเป็น `failed`, ทำไมใช้ `errorifexists`
- ตีความค่า `alert_action` ที่ได้: IDS block หรือแค่เห็น — report บอกสถิติ ไม่ได้บอกว่าเกิด incident (ข้อ 5 ของ skill)

## Claude ผิดตรงไหนได้บ้าง

- ส่ง virtual path (`/student/...`) ให้ Spark → job FAILED หา input ไม่เจอ ให้ดู `spark_job_logs`
- สรุปตัวเลขทันทีหลัง submit ขณะ status ยัง RUNNING
- เขียน output ทับ path เดิม → `errorifexists` ทำให้ FAILED; ต้องใช้ path ใหม่ ไม่ใช่ลบของคนอื่น
- ใช้ `spark_replace_job_text` แก้ template "ให้สวยขึ้น" → `matches_trusted_template` เป็น false ต้องปฏิเสธ
