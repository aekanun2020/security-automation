# Lab 3b — investigation handoff: จาก correlation report เป็นเอกสารส่งต่อ (M6.1, วัตถุประสงค์ข้อ 2)

**หัวข้อ** M6.1 (ส่งต่อเป็น case โดยไม่ต้องมี TheHive), M6.2 (correlation ข้ามแหล่ง), M5.3 (determinism, sha256) · **เวลา** 40 นาที · **ข้อมูล** investigation report v2 ที่มีอยู่ใน HDFS (`/generic-security/coherent-pcap-handoff-retry-20260820050900/input/events.log`)

## โจทย์

lab 3 ได้หลักฐาน 3 ระยะบน asset เดียวกัน ขั้นต่อไปใน SOC คือส่งต่อให้ทีม investigation เป็นเอกสารมาตรฐาน (handoff) ที่ระบุ asset, ลำดับเวลา, หลักฐานประกอบ, สิ่งที่ analyst ต้องทำ และข้อจำกัด skill server มี template ที่ผลิต `security-investigation-handoff-v2` จาก correlation report แบบ deterministic — ผู้เรียนต้องพิสูจน์ความ deterministic นั้นด้วย sha256

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

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | จะส่งเรื่องนี้ต่อให้ทีม investigation ต้องบอกเขาอะไรบ้าง เครื่องไหน เกิดอะไร เมื่อไร มีหลักฐานอะไร | `hdfs_read_text` events.log ฟิลด์ `investigation_candidates[0]` + report handoff: asset, ip, timeline, evidence | ตรวจ |
| 2 | เรื่องนี้ด่วนแค่ไหน และสถานะตอนนี้คืออะไร ยืนยันแล้วหรือรอคนตรวจ | report: `priority`, `disposition`, `verdict` | ตรวจ |
| 3 | 3 เหตุการณ์ (DNS beacon, ส่งข้อมูลออก, ไล่ต่อเครื่องอื่น) ห่างกันเท่าไร ถือเป็นเรื่องเดียวกันไหม | `timeline` 3 รายการ + ช่วงห่าง c2→exfil, exfil→lateral ใน candidate | ตัดสิน |
| 4 | หลักฐานประกอบ 2 ชิ้น ชิ้นไหนของจริง ชิ้นไหนจำลอง สรุปแล้วนับได้กี่ชิ้น | `corroboration` ฟิลด์ `simulation` | ตรวจ |
| 5 | ถ้ามีคนถามว่า "หลักฐานนี้ถูกแก้มาหรือเปล่า" เราตอบด้วยอะไร | `source_sha256` ใน timeline เทียบ `hdfs_sha256` ของไฟล์ต้นทาง 5 ไฟล์ + sha256 ของ report ใหม่เทียบรอบ 2026-08-20 | ตรวจ |
| 6 | ตัวเลข 300,460 record ในรายงาน เอาไปบอกผู้บริหารว่า "มี event สามแสน" ได้ไหม | `parent_evidence.raw_view_records` และคำอธิบายในรายงานเรื่อง overlapping views | ตัดสิน |
| 7 | ทีมที่รับต่อต้องทำอะไรบ้าง และอะไรที่ระบบทำแทนไม่ได้ | `analyst_actions` 3 ข้อ + `caveats` | ตรวจ |
| 8 | template ที่ผลิตเอกสารนี้ ใช้กับเคสอื่นได้ไหม ถ้าไม่ได้ ต้องทำอะไร | `log_skill_read_resource` contract v2: ค่าคงที่ที่ผูกกับ asset เดียว | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. `hdfs_read_text` events.log → เห็น `investigation_candidates[0]`: asset-066, 10.70.0.66, sequence 01:59:00 → 02:40:00, c2_to_exfil 660 s, exfil_to_lateral 1800 s, supporting roles 5, exclusion_summary ทุกค่า 0
2. `log_skill_get` build-security-investigation-handoff-with-spark + `log_skill_read_resource` references/security-investigation-handoff-contract-v2.json (จะเห็นว่า contract ผูกค่าคงที่: canonical_sha256 `8d98cfda…`, case_id, asset-066, priority high, disposition needs-review)
3. `log_skill_render_spark_job` skill = **parse-security-investigation-report**, parser = coherent-pcap-investigation-report-json-v2 → code_sha256 `160f6057…`
4. `spark_save_job` → `spark_validate_job` → `log_skill_validate_spark_job` (policy security-investigation-handoff-spark-job-v1: ต้องมี "not a confirmed incident or compromise", ห้าม requests/http)
5. `spark_submit_job` → `spark_job_status` SUCCEEDED
6. `hdfs_read_text` report → `log_skill_validate_report` → `hdfs_sha256` ทั้ง report ใหม่และ report เก่า

## เฉลย (รันจริง 2026-11-02 job `2b6283c3-1b48-4cbd-a79b-e2639164f770`, 9 วินาที)

| จุด | sha256 |
| --- | --- |
| input events.log (3,882 byte) | 9b4876bc… |
| template handoff v2 | c3fe83c1… |
| parser | f32af268… |
| code (render = save = snapshot = validate expected) | `160f60572e70f1b0570116436a8ff33659702e45f46e42846783c7c0b6a7048a` |
| **report ใหม่** (3,433 byte) | **a803c6b7ecc45a5d21756798e0d8e5aa48af481141b0d67bcf767d93a5538d56** |
| **report รอบ 2026-08-20** (3,433 byte) | **a803c6b7ecc45a5d21756798e0d8e5aa48af481141b0d67bcf767d93a5538d56** |
| validate_report | valid true, contract security-investigation-handoff-v2, report_sha256 00ab053d… (คำนวณจาก JSON ที่ parse แล้ว จึงต่างจาก sha ของไฟล์) |

**report ที่ได้** 1 case: `case-v2-8d98cfda8bc05c11-asset-066`, asset-066 / 10.70.0.66, priority high, disposition **needs-review**, verdict **rule-hit**

timeline 3 รายการ: dns_c2 01:59:00 (evidence pcap-dns_c2-0001, contract c2-detection-report-v1) → network_exfil 02:10:00 (exfiltration-detection-report-v1) → east_west_lateral 02:40:00 (lateral-movement-detection-report-v1) แต่ละรายการมี source_sha256 ของไฟล์ต้นทาง

corroboration 2 รายการ: ids_alert 340 record (simulation false), firewall_sim 265 record (**simulation true**)

analyst_actions 3 ข้อ: ยืนยัน asset/เจ้าของ/นาฬิกา → ทบทวนหลักฐาน endpoint/identity/DNS/flow/IDS/firewall → confirm หรือ dismiss พร้อมเหตุผล

caveats 4 ข้อ: rule hit ไม่ใช่ incident; PCAP สังเคราะห์; Suricata alert ไม่ใช่ session; firewall จำลอง

parent_evidence: PCAP sha256 fa9d5c21… (ตรงกับ lab 3), unique conversations 100,000, raw view records รวม 300,460 ซึ่ง "ไม่ใช่ event เฉพาะที่บวกกันได้" (overlapping views)

## จุดที่คนต้องทำ

- ตัดสินใจ **confirm หรือ dismiss** — handoff ให้แค่ needs-review; MCP ไม่เคยประกาศ incident (caveat ข้อ 1)
- ตรวจ chain of custody: source_sha256 ใน timeline ต้องตรงกับไฟล์ใน `/generic-security/coherent-pcap-correlation-20260820041327/input/` (ให้ผู้เรียนเรียก `hdfs_sha256` เทียบ 5 ไฟล์)
- ส่ง handoff เข้าระบบ case จริง (TheHive/Jira) เป็นงานนอก MCP และเป็นการตัดสินใจขององค์กร
- สังเกตว่า template v2 ผูกค่าคงที่กับ asset-066 — ใช้กับ incident อื่นไม่ได้ ต้องมี template ใหม่ผ่าน Git review (เหตุผล: bounded teaching artifact ไม่ใช่ engine ทั่วไป)

## Claude ผิดตรงไหนได้บ้าง

- สรุปว่า "ยืนยันแล้วว่าถูกโจมตี" ทั้งที่ verdict คือ rule-hit และ disposition คือ needs-review
- นับ corroboration จำลอง (firewall_sim) เป็นหลักฐานอิสระ
- รวม raw_view_records 300,460 เป็น "จำนวน event" — report เองบอกว่าไม่ใช่
- ไม่เทียบ sha256 กับรอบก่อน แล้วอ้างว่า deterministic
