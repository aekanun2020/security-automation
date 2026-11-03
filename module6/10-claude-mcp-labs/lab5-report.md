# Lab 5 — รายงาน: จาก ids-report-v1 เป็น dashboard และ PDF (G4) — ร่าง

**หัวข้อ** M6.3 (pandas → Jinja2 → PDF, 8.1–8.3), M6.4 (dashboard 9.4) · **เวลา** 45 นาที · **สถานะ** ⏳ ร่าง — ใช้ report จาก lab 2 ซึ่งมีแล้ว รันได้ทันที

## โจทย์

69% ของ SOC ยังทำรายงานด้วยมือ (SANS 2025) ผู้เรียนให้ Claude เปลี่ยน JSON report ที่ผ่าน contract แล้วเป็น (1) dashboard แบบ Artifact (2) PDF 1 หน้าสำหรับผู้บริหาร โดย **ตัวเลขทุกตัวต้องมาจาก report ไม่ใช่จาก Claude**

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ คำตอบอยู่ในส่วนเฉลยด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | report ที่อ่านคือไฟล์ใด sha256 ของไฟล์เท่าไร และ `validate_report` ยังผ่านไหม | `hdfs_list` → `hdfs_read_text` → `hdfs_sha256` → `log_skill_validate_report` |
| 2 | KPI 3 ตัว (total, parsed, failed) เท่าไร และตรงกับ lab 2 ไหม | report JSON |
| 3 | signature 3 ตัวและจำนวน; destination 2 อันดับแรกและอีกกี่ host ที่เหลือ — chart ซ่อน 25 host นี้ไหม | report JSON + chart ใน dashboard |
| 4 | sha256 ที่พิมพ์ท้ายหน้าใช้ค่าไหน (ไฟล์ หรือ validate_report) ทำไมสองค่าต่างกัน | `hdfs_sha256` เทียบ `report_sha256` |
| 5 | job_id ที่พิมพ์ท้ายหน้าคืออะไร ตรงกับ job ที่ผลิต report นี้ไหม | `spark_list_jobs` หรือบันทึก lab 2 |
| 6 | ตัวเลขทุกตัวใน PDF ชี้กลับไป field ใดใน JSON ได้ไหม มีตัวเลขใดที่ไม่มีใน report (เช่น % ของ traffic) ปนเข้ามาหรือไม่ | ตารางจับคู่ ตัวเลขใน PDF ↔ field ใน JSON |
| 7 | narrative ใช้คำว่า "rule ตรง" หรือ "ถูกโจมตี" ข้อความใดเกินข้อมูล | อ่าน narrative ทีละประโยค |
| 8 | รายงานนี้ให้ MTTD/MTTR ได้ไหม ทำไม และบอกผู้บริหารอย่างไร | ชุดข้อมูลมี ticket/นาฬิกาตอบสนองหรือไม่ |

## prompt ที่ผู้เรียนพิมพ์

```
อ่าน report ที่ /module7/lab2-ids/report แล้วทำ dashboard: KPI (total, parsed, failed), bar chart ตาม signature,
ตาราง top destination แล้วทำ PDF 1 หน้าสรุปสำหรับผู้บริหาร ภาษาไทย
ระบุ sha256 ของ report และ job_id ไว้ท้ายหน้า
```

## ลำดับ tool ที่ควรเห็น

1. `hdfs_list` → `hdfs_read_text` part-*.txt → `hdfs_sha256`
2. `log_skill_validate_report` (ซ้ำ เพื่อให้แน่ใจว่าไฟล์ที่อ่านคือฉบับที่ผ่าน)
3. Artifact (HTML dashboard) — ตัวเลขจาก JSON โดยตรง
4. skill pdf (Bash + reportlab/weasyprint) → ไฟล์ PDF ในโฟลเดอร์ module6/10-claude-mcp-labs/outputs/

## เฉลยที่คาด

ตัวเลขต้องตรงกับ lab 2: total 340, parsed 340, failed 0, signature 120/120/100, destination 10.70.0.53 = 120, 203.0.113.66 = 120, severity critical 340, job 30d2a9d4…, report sha256 08e4e229… (ไฟล์ใน HDFS) / 538c5ef1… (ที่ validate_report คำนวณจาก JSON ที่ parse แล้ว — ให้ผู้เรียนอธิบายว่าทำไมสองค่านี้ต่างกัน)

narrative ที่ Claude เขียนต้องใช้คำว่า "rule ตรง" ไม่ใช่ "ถูกโจมตี" และไม่เติมตัวเลขที่ไม่มีใน report (เช่น "คิดเป็น x% ของ traffic" ต้องมาจาก lab 3 ไม่ใช่เดา)

## จุดที่คนต้องทำ

- นิยามนาฬิกา: MTTD/MTTR คำนวณไม่ได้จากชุดนี้เพราะไม่มี ticket — ต้องบอกผู้บริหารว่ารายงานนี้ไม่มี metric นั้น
- ตรวจตัวเลขใน PDF กับ JSON ทีละตัวก่อนส่ง
- ตัดสินว่า dashboard แชร์ให้ใครได้ (Artifact เป็น private โดยปริยาย)

## Claude ผิดตรงไหนได้บ้าง

- เติม narrative เกินข้อมูล ("ผู้โจมตีน่าจะเป็น…")
- ใช้ตัวเลขจาก lab 3 ปนกับ lab 2 โดยไม่บอกที่มา
- สร้าง chart ที่ซ่อน 25 host ปลายทางของระยะ lateral เพราะ "น้อยเกิน" — ทั้งที่เป็นสัญญาณสำคัญ
