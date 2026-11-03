# Lab 0 — สำรวจเครื่องมือ: MCP มีอะไรให้ Claude ใช้

**หัวข้อ** M5.4 (API contract), M5.3 (allowlist, idempotency) · **เวลา** 20 นาที · ไม่แตะข้อมูล

## โจทย์

ก่อนสั่งงาน ผู้เรียนต้องรู้ว่า Claude ทำอะไรได้ผ่าน MCP บ้าง และกติกาที่ server บังคับคืออะไร

## สิ่งที่ต้องค้นให้ได้

คำถามข้างล่างคือสิ่งที่ analyst จะถามกันเมื่อเจอเรื่องนี้หน้า SIEM ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร คอลัมน์ขวาบอกว่าคำตอบต้องมาจากผลของ tool ใด (ระบุชื่อ tool และฟิลด์ที่อ่านค่ามา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ ข้อที่เป็นการตัดสินใจไม่มีคำตอบตายตัวแต่ต้องอ้างตัวเลขที่ค้นได้ คำตอบอยู่ในส่วนเฉลยด้านล่าง

| # | คำถามที่คุยกันใน SOC | ค้นจากอะไร |
| --- | --- | --- |
| 1 | ถ้าจะให้ Claude ช่วยงาน SOC ผ่าน MCP ชุดนี้ มันทำอะไรแทนเราได้บ้าง และอะไรยังต้องเป็นคนทำ | รายชื่อ tool ทั้งสอง server จัดกลุ่มตามหน้าที่ (เก็บ, อ่าน, วิเคราะห์, รัน job, เขียน parser) จาก ToolSearch และ `log_skill_list` |
| 2 | parser ที่มีให้ ครอบคลุม log ของเราไหม (firewall, IDS, flow, DNS, Windows, Linux) อะไรขาด | `log_skill_list` แยก parser กับ workflow |
| 3 | ถ้า Claude บอกว่า "job เสร็จแล้ว ผลเป็นแบบนี้" เราจะเชื่อได้เมื่อไร | กติกาของ server: `spark_job_status` ต้อง SUCCEEDED และ report ต้องผ่าน `log_skill_validate_report` |
| 4 | ของที่ Claude รันไปแล้ว อีกเดือนย้อนดูได้ไหมว่าใช้โค้ดไหนกับไฟล์ไหน | snapshot โค้ด, sha256, idempotency key ที่ `spark_job_status` และ `spark_list_jobs` เก็บไว้ |
| 5 | มีทางที่ Claude จะเขียนหรือรันโค้ดอะไรก็ได้บนคลัสเตอร์ของเราไหม | `log_skill_read_resource` คืนแค่ text, parser ใหม่เป็น draft ต้อง promote ผ่าน Git, template ต้องผ่าน `log_skill_validate_spark_job` |
| 6 | ทำไมบางครั้ง Claude สั่ง Spark แล้ว job หาไฟล์ไม่เจอ ทั้งที่ไฟล์อยู่ใน HDFS | virtual path กับ physical path ที่ `hdfs_mkdir` คืนมา และกติกาว่า path แบบไหนส่งให้ใครได้ |

## prompt ที่ผู้เรียนพิมพ์

```
mcp server for spark, hdfs มี tool ไรบ้าง
```

```
mcp server for security skill มีอะไรบ้าง
```

## ลำดับ tool ที่ควรเห็น Claude เรียก

1. โหลด schema ของ tool (ToolSearch) — Claude ยังไม่รู้ argument จนกว่าจะโหลด
2. `log_skill_list` และ `log_skill_list_drafts` — เพื่อตอบว่ามี skill อะไร (ไม่ใช่เดาจากชื่อ)

## เฉลย (ณ 2026-11-02)

**spark-hdfs server: 23 tools**

| กลุ่ม | tool |
| --- | --- |
| HDFS จัดการไฟล์ | hdfs_list, hdfs_stat, hdfs_mkdir, hdfs_delete, hdfs_write_text, hdfs_import_file, hdfs_sha256 |
| HDFS อ่าน | hdfs_read_text (≤ 1 MB), hdfs_read_lines (ทีละช่วง มีเลขบรรทัด) |
| HDFS วิเคราะห์ | hdfs_query_records (filter/group_by/sum/distinct/สถิติเวลา/CIDR), hdfs_correlate_records (join สองไฟล์ด้วย key + เวลา), hdfs_pcap_packets (TShark filter) |
| HDFS สถานะ | hdfs_cluster_status |
| Spark โค้ด | spark_save_job, spark_read_job, spark_replace_job_text, spark_validate_job |
| Spark รัน | spark_submit_job, spark_job_status, spark_job_logs, spark_list_jobs, spark_cancel_job |
| Spark สถานะ | spark_cluster_status |

**log-skill server: 14 tools, 23 skills (parser 12, workflow 11), draft 0**

| กลุ่ม | tool |
| --- | --- |
| ค้นหา/อ่าน | log_skill_list, log_skill_search, log_skill_get, log_skill_list_resources, log_skill_read_resource, log_skill_resolve |
| ทดสอบ parser | log_skill_test_parser (≤ 100 sample), log_skill_validate |
| สร้าง Spark job | log_skill_render_spark_job, log_skill_validate_spark_job, log_skill_validate_report |
| เขียน skill ใหม่ | log_skill_save_draft, log_skill_list_drafts, log_skill_get_draft |

**กติกาที่ต้องจำ** (จาก instruction ของ server เอง)

- HDFS tool รับ virtual path ใต้ `/mcp` เช่น `/lab/input.log` และคืน physical path `/mcp/lab/input.log`
- ส่งให้ Spark ต้องใช้ physical path; ห้ามส่ง `/mcp/...` กลับเข้า HDFS tool
- ลำดับ Spark: save → validate → submit → poll status → logs เมื่อ fail
- ไม่ถือว่า job สำเร็จจนกว่าสถานะเป็น SUCCEEDED
- ไฟล์และ conf ของ Spark ถูก allowlist: pip install เพิ่มไม่ได้

สถานะ cluster ที่รันเฉลย: Spark master ALIVE, 2 workers × 1 core × 1 GB; HDFS root มี generic-security (45 ชุดผลรันเก่า), integration, investigations, lab13, lab16, student

## จุดที่คนต้องทำ

- ตัดสินใจว่าเชื่อ "รายการ tool" จากการเรียก list จริง ไม่ใช่จากคำอธิบายของ Claude
- สังเกตว่า Claude บอก "ประเมิน" กับ "ตรวจแล้ว" ต่างกันตรงไหน

## Claude ผิดตรงไหนได้บ้าง

- ตอบรายการ tool จากความจำโดยไม่เรียก list → ให้ผู้เรียนถามกลับ "เรียก list จริงหรือยัง"
- อธิบายกติกา path สลับกัน → ทดสอบใน lab 2 จะเห็นผลทันที (job หา input ไม่เจอ)
