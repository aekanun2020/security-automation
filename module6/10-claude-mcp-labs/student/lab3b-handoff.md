# Lab 3b — investigation handoff: จาก correlation report เป็นเอกสารส่งต่อ (M6.1, วัตถุประสงค์ข้อ 2)

**หัวข้อ** M6.1 (ส่งต่อเป็น case โดยไม่ต้องมี TheHive), M6.2 (correlation ข้ามแหล่ง), M5.3 (determinism, sha256) · **เวลา** 40 นาที · **ข้อมูล** investigation report v2 ที่มีอยู่ใน HDFS (`/generic-security/coherent-pcap-handoff-retry-20260820050900/input/events.log`)

## โจทย์

lab 3 ได้หลักฐาน 3 ระยะบน asset เดียวกัน ขั้นต่อไปใน SOC คือส่งต่อให้ทีม investigation เป็นเอกสารมาตรฐาน (handoff) ที่ระบุ asset, ลำดับเวลา, หลักฐานประกอบ, สิ่งที่ analyst ต้องทำ และข้อจำกัด skill server มี template ที่ผลิต `security-investigation-handoff-v2` จาก correlation report แบบ deterministic — ผู้เรียนต้องพิสูจน์ความ deterministic นั้นด้วย sha256

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ บันทึกคำตอบในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | input events.log ระบุ candidate อะไร: asset_id, ip, ช่วงเวลา sequence, ช่วงห่าง c2→exfil และ exfil→lateral กี่วินาที, supporting roles กี่รายการ | `hdfs_read_text` events.log ฟิลด์ `investigation_candidates[0]` |
| 2 | contract handoff v2 ผูกค่าคงที่อะไรไว้บ้าง (canonical_sha256, asset, priority, disposition) แล้วใช้กับ incident อื่นได้ไหม | `log_skill_read_resource` references/security-investigation-handoff-contract-v2.json |
| 3 | render ด้วย skill ชื่ออะไร parser อะไร ได้ code_sha256 เท่าไร และ policy validate บังคับประโยคใดต้องมี/ห้ามมี | `log_skill_render_spark_job` + `log_skill_validate_spark_job` |
| 4 | sha256 ของ report ที่ได้ใหม่กับ report รอบ 2026-08-20 ตรงกันไหม ขนาดไฟล์เท่าไร นี่พิสูจน์อะไร | `hdfs_sha256` ทั้ง 2 ไฟล์ |
| 5 | case_id, priority, disposition, verdict ของ case คืออะไร verdict นี้แปลว่า "ยืนยันถูกโจมตี" หรือไม่ | report JSON |
| 6 | timeline มีกี่รายการ แต่ละรายการเกิดเวลาใด มาจาก contract ต้นทางใด | report JSON `timeline` |
| 7 | corroboration มีกี่รายการ รายการใด `simulation: true` และนับเป็นหลักฐานอิสระได้ไหม | report JSON `corroboration` |
| 8 | caveats 4 ข้อคืออะไร | report JSON `caveats` |
| 9 | `raw_view_records` 300,460 เป็น "จำนวน event" ได้ไหม report บอกไว้ว่าอย่างไร | report JSON `parent_evidence` |
| 10 | source_sha256 ของหลักฐานใน timeline ตรงกับไฟล์ input ของรอบ correlation ทั้ง 5 ไฟล์ไหม | `hdfs_sha256` ของไฟล์ใน `/generic-security/coherent-pcap-correlation-20260820041327/input/` เทียบค่าใน report |
| 11 | analyst ต้องทำอะไร 3 ข้อ และข้อใดที่ MCP ทำแทนไม่ได้ | report JSON `analyst_actions` |

## สายงานเต็มที่ server ออกแบบ (ผู้เรียนควรเห็นภาพ)

```
report ต่อแหล่ง (ids-report-v1, c2/exfil/lateral detection report, security-report-v1)
  → evidence envelope 5 บรรทัด (parser pcap-shared-parent-correlation-evidence-json-v2)
  → correlate-security-evidence-with-spark (profile host-threat-sequence: C2 → exfil → lateral ห่างกันไม่เกิน 1800 s บน asset_id เดียว)
  → security-investigation-report-v2 (1 บรรทัด)                 ← input ของ lab นี้
  → build-security-investigation-handoff-with-spark
  → security-investigation-handoff-v2
```

lab นี้ทำเฉพาะขั้นสุดท้าย ขั้น correlate เป็น lab ต่อยอด (input 5 ไฟล์อยู่ที่ `/generic-security/coherent-pcap-correlation-20260820041327/input/`)

## prompt ที่ผู้เรียนพิมพ์

```
อ่าน /generic-security/coherent-pcap-handoff-retry-20260820050900/input/events.log
แล้วสร้าง investigation handoff ด้วย skill build-security-investigation-handoff-with-spark
เขียน output ที่ /m6-10/<ชื่อ>/lab3b-handoff แล้วเทียบ sha256 ของ report ที่ได้กับ report ของรอบ 20 ส.ค.
```

## ลำดับ tool ที่ควรเห็น

1. `hdfs_read_text` events.log → อ่าน `investigation_candidates[0]` ให้ครบ: asset, ip, ช่วงเวลา sequence, ช่องว่างเวลาระหว่างระยะ, supporting roles, exclusion_summary
2. `log_skill_get` build-security-investigation-handoff-with-spark + `log_skill_read_resource` references/security-investigation-handoff-contract-v2.json (ดูว่า contract ผูกค่าคงที่อะไรไว้บ้าง และค่าใดที่ไม่ได้มาจาก input)
3. `log_skill_render_spark_job` ด้วย skill ของ parser ที่อ่าน investigation report (หาด้วย `log_skill_resolve` หรือ `log_skill_search` ไม่ใช่ workflow skill ตามบทเรียน lab 2) → code_sha256
4. `spark_save_job` → `spark_validate_job` → `log_skill_validate_spark_job` (อ่าน policy ที่ใช้ตรวจว่าบังคับให้มีประโยคใด และห้ามอะไร)
5. `spark_submit_job` → `spark_job_status` SUCCEEDED
6. `hdfs_read_text` report → `log_skill_validate_report` → `hdfs_sha256` ทั้ง report ใหม่และ report เก่า

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

- ตัดสินใจ **confirm หรือ dismiss** — ดู disposition ที่ handoff ให้ (ข้อ 5); MCP ไม่เคยประกาศ incident (caveat ข้อ 1)
- ตรวจ chain of custody: source_sha256 ใน timeline ต้องตรงกับไฟล์ใน `/generic-security/coherent-pcap-correlation-20260820041327/input/` (ให้ผู้เรียนเรียก `hdfs_sha256` เทียบ 5 ไฟล์)
- ส่ง handoff เข้าระบบ case จริง (TheHive/Jira) เป็นงานนอก MCP และเป็นการตัดสินใจขององค์กร
- สังเกตว่า template v2 ผูกค่าคงที่กับ asset ตัวเดียว (ข้อ 2) — ใช้กับ incident อื่นไม่ได้ ต้องมี template ใหม่ผ่าน Git review (เหตุผล: bounded teaching artifact ไม่ใช่ engine ทั่วไป)

## Claude ผิดตรงไหนได้บ้าง

- สรุปว่า "ยืนยันแล้วว่าถูกโจมตี" ทั้งที่ verdict และ disposition ใน report ไม่ได้บอกเช่นนั้น
- นับ corroboration ที่ `simulation: true` เป็นหลักฐานอิสระ
- รวม raw_view_records 300,460 เป็น "จำนวน event" — report เองบอกว่าไม่ใช่
- ไม่เทียบ sha256 กับรอบก่อน แล้วอ้างว่า deterministic
