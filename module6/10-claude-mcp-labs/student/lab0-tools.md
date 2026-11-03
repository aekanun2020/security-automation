# Lab 0 — สำรวจเครื่องมือ: MCP มีอะไรให้ Claude ใช้

**หัวข้อ** M5.4 (API contract), M5.3 (allowlist, idempotency) · **เวลา** 20 นาที · ไม่แตะข้อมูล

## โจทย์

ก่อนสั่งงาน ผู้เรียนต้องรู้ว่า Claude ทำอะไรได้ผ่าน MCP บ้าง และกติกาที่ server บังคับคืออะไร

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ บันทึกคำตอบในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | spark-hdfs server มี tool กี่ตัว แบ่งได้กี่กลุ่ม และ tool ใดอ่านไฟล์ได้ไม่เกินกี่ MB | รายชื่อ tool จาก ToolSearch จัดกลุ่มเอง + ข้อจำกัดจาก description ของ `hdfs_read_text` |
| 2 | log-skill server มี skill กี่ตัว แยกเป็น parser กี่ตัว workflow กี่ตัว และ draft กี่ตัว | ผล `log_skill_list` และ `log_skill_list_drafts` (ไม่ใช่เดาจากชื่อ) |
| 3 | มี tool ใดไหมที่ *รัน* โค้ดของ skill ได้ แล้ว `log_skill_read_resource` คืนอะไร | description ของ tool และ instruction ของ server |
| 4 | virtual path กับ physical path ต่างกันอย่างไร ยกตัวอย่างค่าที่ `hdfs_mkdir` คืนมา และ path แบบไหนห้ามส่งกลับเข้า HDFS tool | instruction ของ spark-hdfs server + ผล `hdfs_mkdir` จริง 1 ครั้ง |
| 5 | ก่อน `spark_submit_job` ต้องเรียก tool อะไรบ้างตามลำดับ และสถานะใดที่ถือว่า job สำเร็จ | instruction ของ server (save → validate → submit → status SUCCEEDED) |
| 6 | ทำไม Claude ต้องโหลด schema (ToolSearch) ก่อน จึงเรียก tool ได้ | ข้อความ error หรือ step แรกที่เห็นในแชท |

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

## จุดที่คนต้องทำ

- ตัดสินใจว่าเชื่อ "รายการ tool" จากการเรียก list จริง ไม่ใช่จากคำอธิบายของ Claude
- สังเกตว่า Claude บอก "ประเมิน" กับ "ตรวจแล้ว" ต่างกันตรงไหน

## Claude ผิดตรงไหนได้บ้าง

- ตอบรายการ tool จากความจำโดยไม่เรียก list → ให้ผู้เรียนถามกลับ "เรียก list จริงหรือยัง"
- อธิบายกติกา path สลับกัน → ทดสอบใน lab 2 จะเห็นผลทันที (job หา input ไม่เจอ)
