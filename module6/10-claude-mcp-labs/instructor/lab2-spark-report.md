# Lab 2 — Spark report: จาก alert 340 บรรทัดเป็น ids-report-v1 (G2)

**หัวข้อ** M5.2 (batch analytics), M6.2 (alert aggregate), M5.3 (sha256, idempotency), M5.1 (อ่าน PySpark) · **เวลา** 45 นาที · **ข้อมูล** Suricata alerts ใน HDFS

## สถานการณ์

ตีสองกว่า alert เข้ามาครบ 340 ตัวแล้ว จะไล่อ่านทีละบรรทัดไม่ทัน น้องต้องการภาพรวมหนึ่งหน้า rule ไหนยิงเท่าไร จากเครื่องไหน ไปไหน ถูก block ไหม เริ่มกี่โมงจบกี่โมง คำถามที่พา lab นี้คือ ภาพรวมทั้งคืนเป็นอย่างไร และก่อนเอาตัวเลขไปบอกใคร ต้องตอบให้ได้ว่าโค้ดที่ทำรายงานนี้คือโค้ดที่ตรวจแล้วจริง ไม่ใช่โค้ดที่ Claude แต่งขึ้นเอง

## โจทย์

ให้ Claude สร้างรายงานสรุป alert ตาม contract `ids-report-v1` โดยใช้ Spark job ที่ render จาก template ที่เชื่อถือได้ ผู้เรียนต้องตรวจทุกจุดที่ server ให้หลักฐาน: sha256 ของโค้ด, สถานะ job, และ report ผ่าน contract

## prompt ที่ผู้เรียนพิมพ์

```
สร้าง ids-report จาก /student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
ด้วย parser suricata-eve-alert-json-v1 เขียน output ไว้ที่ /m6-10/<ชื่อผู้เรียน>/lab2-ids
ให้ validate ทั้งก่อน submit และ validate report หลังจบ แล้วสรุปตัวเลขให้ดู
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง

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
| 2 | `log_skill_render_spark_job` (skill = **parse-suricata-eve-alerts**, parser_id) | skill | code + `code_sha256` |
| 3 | `spark_save_job` filename, code | spark | `sha256` ต้องเท่ากับข้อ 2 |
| 4 | `hdfs_mkdir` /m6-10/<ชื่อ>/lab2-ids | spark | คืน physical path `/mcp/m6-10/...` |
| 5 | `spark_validate_job` | spark | valid_python, imports_pyspark |
| 6 | `log_skill_validate_spark_job` (code) | skill | `matches_trusted_template: true` + checks 16 รายการ |
| 7 | `spark_submit_job` arguments = [physical input, physical curated, physical report], idempotency_key, expected_sha256 | spark | status RUNNING, job_id |
| 8 | `spark_job_status` (วนจนกว่าจะไม่ใช่ RUNNING) | spark | **SUCCEEDED** exit_code 0 |
| 9 | `hdfs_list` report dir → `hdfs_read_text` part-*.txt | spark | JSON 1 บรรทัด |
| 10 | `log_skill_validate_report` | skill | `valid: true` |
| 11 | `hdfs_sha256` ของ report | spark | เก็บไว้ใน hashes.json |

## เฉลย (รันจริง 2026-11-02 job `30d2a9d4-f6ad-412b-8dcf-dfaff1ce1233`)

**ข้อผิดพลาดที่เกิดจริงตอนรันเฉลย** เรียก render ด้วย `skill_name = analyze-ids-alerts-with-spark` → error `parser 'suricata-eve-alert-json-v1' not found` เพราะ workflow skill มี `parsers: []` ต้องเรียกด้วย skill ของ parser (`parse-suricata-eve-alerts`) แล้ว server จะหา workflow ให้เอง (`workflow_skill: analyze-ids-alerts-with-spark`) — ใช้เป็นตัวอย่าง "Claude ลองผิดแล้วแก้" ได้

**ห่วงโซ่ sha256 ที่ต้องตรงกันทั้งสาย**

| จุด | sha256 |
| --- | --- |
| template (`assets/spark_ids_alert_report_job.py.tmpl`) | a5b95a8d… |
| parser YAML | 9198c155… |
| code ที่ render | `000a31479ed493810f179599615436c811aa4c9b77cd016dc6babd6d4386169b` |
| spark_save_job คืน | 000a3147… (ตรง) |
| validate_spark_job expected | 000a3147… (ตรง) |
| snapshot ของ job ที่ submit | 000a3147… (ตรง) |

สังเกต: code_sha256 เดียวกับ job `dfir16_*_f5.py` ที่รันเมื่อ 2026-09-08 แปลว่า template ไม่เปลี่ยนตั้งแต่นั้น

**argument ที่ส่ง**

```
/mcp/student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
/mcp/module7/lab2-ids/curated
/mcp/module7/lab2-ids/report
```

**เวลา** submit 14:43:42Z → SUCCEEDED 14:46:25Z (2 นาที 43 วินาที บน 2 workers)

**report** (ผ่าน `validate_report`: valid true, report_sha256 538c5ef1…; ไฟล์ใน HDFS sha256 08e4e229…)

| ฟิลด์ | ค่า |
| --- | --- |
| total_records / parsed / failed | 340 / 340 / 0 |
| event_time_min → max | 2026-08-24 00:00:00 → 02:44:00 |
| top_signatures | C2 DNS 120, Outbound Transfer 120, East-West Remote Service 100 |
| top_categories | Network Trojan 120, Corporate Privacy Violation 120, Admin Privilege Gain 100 |
| top_source_ips | 10.70.0.66 = 340 (ทั้งหมด) |
| top_destination_ips | 10.70.0.53 = 120, 203.0.113.66 = 120, แล้ว 10.70.1.x อีก 25 host ละ 4 |
| top_applications | dns 120, http 120, unknown 100 |
| top_protocols | tcp 220, udp 120 |
| severity_summary | critical 340 (ทุก alert severity 1) |
| alert_action | allowed 340 |

**output ใน HDFS** `curated/part-*.snappy.parquet` 31 KB + `_SUCCESS`; `report/part-*.txt` 2,175 byte + `_SUCCESS`

## จุดที่คนต้องทำ

- ยืนยันว่า sha256 ตรงกันทั้ง 4 จุดก่อนอนุมัติผล (Claude อาจบอกว่า "ตรง" โดยไม่ได้เทียบ)
- อ่าน PySpark ที่ render (ประมาณ 80 บรรทัด) แล้วตอบ: บรรทัดไหนทำให้ record กลายเป็น `failed`, ทำไมใช้ `errorifexists`
- ตีความ: `alert_action = allowed` ทั้ง 340 แปลว่า IDS เห็นแต่ไม่ block — report บอกสถิติ ไม่ได้บอกว่าเกิด incident (ข้อ 5 ของ skill)

## Claude ผิดตรงไหนได้บ้าง

- ส่ง virtual path (`/student/...`) ให้ Spark → job FAILED หา input ไม่เจอ ให้ดู `spark_job_logs`
- สรุปตัวเลขทันทีหลัง submit ขณะ status ยัง RUNNING
- เขียน output ทับ path เดิม → `errorifexists` ทำให้ FAILED; ต้องใช้ path ใหม่ ไม่ใช่ลบของคนอื่น
- ใช้ `spark_replace_job_text` แก้ template "ให้สวยขึ้น" → `matches_trusted_template` เป็น false ต้องปฏิเสธ
