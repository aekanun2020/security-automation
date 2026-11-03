# Lab 5 — รายงาน: จาก ids-report-v1 เป็น dashboard และ PDF (G4) — ร่าง

**หัวข้อ** M6.3 (pandas → Jinja2 → PDF, 8.1–8.3), M6.4 (dashboard 9.4) · **เวลา** 45 นาที · **สถานะ** ⏳ ร่าง — ใช้ report จาก lab 2 ซึ่งมีแล้ว รันได้ทันที

## โจทย์

69% ของ SOC ยังทำรายงานด้วยมือ (SANS 2025) ผู้เรียนให้ Claude เปลี่ยน JSON report ที่ผ่าน contract แล้วเป็น (1) dashboard แบบ Artifact (2) PDF 1 หน้าสำหรับผู้บริหาร โดย **ตัวเลขทุกตัวต้องมาจาก report ไม่ใช่จาก Claude**

## prompt ที่ผู้เรียนพิมพ์

```
อ่าน report ที่ /module7/lab2-ids/report แล้วทำ dashboard: KPI (total, parsed, failed), bar chart ตาม signature,
ตาราง top destination แล้วทำ PDF 1 หน้าสรุปสำหรับผู้บริหาร ภาษาไทย
ระบุ sha256 ของ report และ job_id ไว้ท้ายหน้า
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | ผู้บริหารถามว่า "ช่วงนี้เกิดอะไรขึ้น" ตอบด้วยตัวเลขอะไร 3 ตัว | report JSON: `total_records`, `parse_quality.parsed`, `parse_quality.failed` ตรงกับ lab 2 | ตรวจ |
| 2 | rule ไหนยิงบ่อย เครื่องไหนโดนบ่อย | report JSON: `top_signatures`, `top_destination_ips` | ตรวจ |
| 3 | 25 เครื่องที่โดน lateral แต่ละเครื่องแค่ 4 alert ควรขึ้น chart ไหม ถ้าตัดออกจะเสียอะไร | `top_destination_ips` เทียบ chart ใน dashboard | ตัดสิน |
| 4 | ถ้าผู้ตรวจสอบถาม ตัวเลขทุกตัวในรายงานชี้กลับไปข้อมูลต้นทางได้ไหม | ตารางจับคู่ตัวเลขใน PDF ↔ field ใน JSON + sha256 ของ report + job_id | ตรวจ |
| 5 | จะเขียนว่า "ถูกโจมตี" หรือ "rule ตรง" ต่างกันอย่างไรต่อผู้บริหาร | อ่าน narrative ทีละประโยคเทียบกับสิ่งที่ report มีจริง | ตัดสิน |
| 6 | ผู้บริหารถาม MTTD/MTTR เรามีให้ไหม ถ้าไม่มี บอกอย่างไร | ชุดข้อมูลมีเวลาเปิด/ปิด ticket หรือไม่ | ตัดสิน |
| 7 | ทำไม sha256 ของรายงานมีสองค่า ถ้าถูกถามจะอธิบายอย่างไร | `hdfs_sha256` ของไฟล์ เทียบ `report_sha256` ที่ `log_skill_validate_report` คำนวณจาก JSON ที่ parse แล้ว | ตรวจ |

## ลำดับ tool ที่ควรเห็น

1. `hdfs_list` → `hdfs_read_text` part-*.txt → `hdfs_sha256`
2. `log_skill_validate_report` (ซ้ำ เพื่อให้แน่ใจว่าไฟล์ที่อ่านคือฉบับที่ผ่าน)
3. Artifact (HTML dashboard) — ตัวเลขจาก JSON โดยตรง
4. skill pdf (Bash + reportlab/weasyprint ถ้ามี; เครื่องผู้สอน 2026-11-03 ไม่มีทั้งสอง ใช้ matplotlib `PdfPages` แทนได้ ต้องใช้ฟอนต์ที่มีทั้งไทยและละติน เช่น `/System/Library/Fonts/Supplemental/Ayuthaya.ttf` ส่วน ThonburiUI.ttc ไม่มี glyph ละติน) → ไฟล์ PDF ในโฟลเดอร์ module6/10-claude-mcp-labs/instructor/outputs/

## เฉลย (รันจริง 2026-11-03)

ตัวเลขต้องตรงกับ lab 2: total 340, parsed 340, failed 0, signature 120/120/100, destination 10.70.0.53 = 120, 203.0.113.66 = 120, severity critical 340, job 30d2a9d4…, report sha256 08e4e229… (ไฟล์ใน HDFS) / 538c5ef1… (ที่ validate_report คำนวณจาก JSON ที่ parse แล้ว — ให้ผู้เรียนอธิบายว่าทำไมสองค่านี้ต่างกัน)

ผลรันจริง 2026-11-03: `outputs/lab5-executive-summary-claude-verify.pdf` (1 หน้า: KPI 3 ช่อง, bar chart 3 signature, ตารางปลายทางครบ 27 รายการ, job_id, sha256 สองค่า) และ `outputs/lab5-dashboard-claude-verify.html` ตัวเลขทุกตัวตรงกับ report ของ job `2237ad28…` (รันซ้ำ lab 2 วันเดียวกัน report byte-identical กับ job `30d2a9d4…`)

narrative ที่ Claude เขียนต้องใช้คำว่า "rule ตรง" ไม่ใช่ "ถูกโจมตี" และไม่เติมตัวเลขที่ไม่มีใน report (เช่น "คิดเป็น x% ของ traffic" ต้องมาจาก lab 3 ไม่ใช่เดา)

## จุดที่คนต้องทำ

- นิยามนาฬิกา: MTTD/MTTR คำนวณไม่ได้จากชุดนี้เพราะไม่มี ticket — ต้องบอกผู้บริหารว่ารายงานนี้ไม่มี metric นั้น
- ตรวจตัวเลขใน PDF กับ JSON ทีละตัวก่อนส่ง
- ตัดสินว่า dashboard แชร์ให้ใครได้ (Artifact เป็น private โดยปริยาย)

## Claude ผิดตรงไหนได้บ้าง

- เติม narrative เกินข้อมูล ("ผู้โจมตีน่าจะเป็น…")
- ใช้ตัวเลขจาก lab 3 ปนกับ lab 2 โดยไม่บอกที่มา
- สร้าง chart ที่ซ่อน 25 host ปลายทางของระยะ lateral เพราะ "น้อยเกิน" — ทั้งที่เป็นสัญญาณสำคัญ
