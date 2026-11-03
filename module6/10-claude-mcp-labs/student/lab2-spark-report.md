# Lab 2 — Spark report: จาก alert 340 บรรทัดเป็น ids-report-v1 (G2)

**หัวข้อ** M5.2 (batch analytics), M6.2 (alert aggregate), M5.3 (sha256, idempotency), M5.1 (อ่าน PySpark) · **เวลา** 45 นาที · **ข้อมูล** Suricata alerts ใน HDFS

## โจทย์

ให้ Claude สร้างรายงานสรุป alert ตาม contract `ids-report-v1` โดยใช้ Spark job ที่ render จาก template ที่เชื่อถือได้ ผู้เรียนต้องตรวจทุกจุดที่ server ให้หลักฐาน: sha256 ของโค้ด, สถานะ job, และ report ผ่าน contract

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ บันทึกคำตอบในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | ต้อง render ด้วย skill ชื่ออะไรจึงได้โค้ด ถ้าใส่ชื่อ workflow skill จะได้ error ว่าอะไร และ server เลือก `workflow_skill` ให้เองว่าอะไร | ผล `log_skill_render_spark_job` ทั้งรอบที่ผิดและรอบที่ถูก |
| 2 | sha256 ของโค้ดที่ 4 จุด (render, save, validate expected, snapshot ของ job) มีค่าอะไร ตรงกันทุกจุดไหม | ค่าจาก `log_skill_render_spark_job`, `spark_save_job`, `log_skill_validate_spark_job`, `spark_job_status` |
| 3 | argument 3 ตัวที่ส่งให้ job คืออะไร เป็น path แบบใด | argument ใน `spark_submit_job` |
| 4 | job ใช้เวลาเท่าไร สถานะสุดท้ายและ exit_code คืออะไร | `spark_job_status` ครั้งสุดท้าย (เวลา submit → เวลาจบ) |
| 5 | `total_records`, `parsed`, `failed` เท่าไร | report JSON ที่อ่านด้วย `hdfs_read_text` |
| 6 | `event_time_min` → `event_time_max` ครอบคลุมช่วงใด | report JSON |
| 7 | top_signatures 3 ตัวและจำนวนของแต่ละตัว | report JSON |
| 8 | alert ทั้งหมดมาจาก source_ip กี่ตัว และ destination_ip 2 อันดับแรกคือใคร ที่เหลืออีกกี่ host ละกี่ alert | report JSON `top_source_ips`, `top_destination_ips` |
| 9 | `alert_action` มีค่าอะไรบ้าง และหมายความว่า IDS ทำอะไรกับ traffic นั้น | report JSON + นิยามใน skill |
| 10 | sha256 ของ report มี 2 ค่า (ไฟล์ใน HDFS กับที่ `validate_report` คืน) ทำไมต่างกัน | `hdfs_sha256` เทียบ `report_sha256` ของ `log_skill_validate_report` |
| 11 | ในโค้ด PySpark ที่ render บรรทัดใดทำให้ record กลายเป็น `failed` และทำไมเขียน output ด้วย `errorifexists` | อ่านโค้ดจาก `spark_read_job` ระบุเลขบรรทัด |

## prompt ที่ผู้เรียนพิมพ์

```
สร้าง ids-report จาก /student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
ด้วย parser suricata-eve-alert-json-v1 เขียน output ไว้ที่ /m6-10/<ชื่อผู้เรียน>/lab2-ids
ให้ validate ทั้งก่อน submit และ validate report หลังจบ แล้วสรุปตัวเลขให้ดู
```

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
| 10 | | |
| 11 | | |

## จุดที่คนต้องทำ

- ยืนยันว่า sha256 ตรงกันทั้ง 4 จุดก่อนอนุมัติผล (Claude อาจบอกว่า "ตรง" โดยไม่ได้เทียบ)
- อ่าน PySpark ที่ render (ประมาณ 80 บรรทัด) แล้วตอบ: บรรทัดไหนทำให้ record กลายเป็น `failed`, ทำไมใช้ `errorifexists`
- ตีความค่า `alert_action` ที่ได้: IDS block หรือแค่เห็น — report บอกสถิติ ไม่ได้บอกว่าเกิด incident (ข้อ 5 ของ skill)

## Claude ผิดตรงไหนได้บ้าง

- ส่ง virtual path (`/student/...`) ให้ Spark → job FAILED หา input ไม่เจอ ให้ดู `spark_job_logs`
- สรุปตัวเลขทันทีหลัง submit ขณะ status ยัง RUNNING
- เขียน output ทับ path เดิม → `errorifexists` ทำให้ FAILED; ต้องใช้ path ใหม่ ไม่ใช่ลบของคนอื่น
- ใช้ `spark_replace_job_text` แก้ template "ให้สวยขึ้น" → `matches_trusted_template` เป็น false ต้องปฏิเสธ
