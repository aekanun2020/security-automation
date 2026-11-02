# Module 7 — SOC Automation ด้วย Claude + MCP (คนเป็นผู้ตรวจ)

ผู้รับผิดชอบ: ครูเอ้ · ร่าง 2026-11-02 สำหรับคาบ 2026-11-03 · ศัพท์ดูใน [glossary](../docs/glossary.md) · ที่มาของโครง: [บันทึกถาม-ตอบ Q9–Q10](../docs/qa-2026-11-02-mcp-spark-hdfs.md)

## แนวคิด

Module 5–6 สอนให้ผู้เรียน **เขียน Python เอง** เพื่อทำ automation ส่วน Module 7 สอนอีกวิธี: ผู้เรียน **สั่ง Claude ให้ใช้เครื่องมือ (MCP) ทำงาน** แล้วทำหน้าที่ตรวจผลและอนุมัติ ตรงกับวัตถุประสงค์หลักสูตรข้อ 4 และคอลัมน์ "AI ทำได้ / คนต้องทำ" ใน [checklist ELK→QRadar](../docs/elastic-siem-vs-qradar.md)

```
ผู้เรียน (prompt + ตรวจ + อนุมัติ)
   │
   ▼
Claude Desktop ── ดึง feed / ทำ PDF / Artifact (ออกเน็ตได้ ต้องขออนุญาต)
   │
   ├── MCP ① log-skill server   : resolve / test_parser / render_spark_job / validate_report / save_draft
   │
   └── MCP ② spark-hdfs server  : hdfs_* (อ่าน/เขียน/query/correlate/pcap) + spark_* (save/validate/submit/status/logs)
                                   │
                                   ▼
                              HDFS (/mcp/...) + Spark cluster (2 workers)
```

**หลักที่ server บังคับ และผู้เรียนต้องเข้าใจก่อนเริ่ม**

1. Claude ไม่ได้เขียน PySpark เอง แต่ render จาก template ที่เชื่อถือได้ แล้วตรวจ sha256 ว่าตรง (lab 2b จงใจกลับด้าน: Claude เขียนเองและคนต้องอ่านโค้ดแทน)
2. skill code อ่านได้อย่างเดียว ไม่รัน (`log_skill_read_resource` คืน text เฉย ๆ)
3. job ที่ submit มี snapshot โค้ด, sha256, idempotency key เก็บไว้ audit ย้อนหลังได้
4. parser ใหม่เป็น draft เสมอ ต้องมีคน promote ผ่าน Git
5. **ไม่เชื่อผล job จนกว่าสถานะเป็น `SUCCEEDED`** และ report ต้องผ่าน `log_skill_validate_report`
6. path: HDFS tool ใช้ virtual path (`/lab/x.log`) และคืน physical path (`/mcp/lab/x.log`) ส่งให้ Spark ต้องใช้ physical path; ห้ามส่ง `/mcp/...` กลับเข้า HDFS tool

## ข้อมูลที่ใช้ทุก lab

ชุด `incident-lab` ใน HDFS (`/student/agentic-siem/incident-lab/input/`) มาจาก PCAP เดียวกัน จึง correlate ข้ามแหล่งได้

| ไฟล์ | ขนาด | parser ที่มีใน skill server |
| --- | --- | --- |
| coherent-course-100k.pcap | 61 MB | ค้นด้วย `hdfs_pcap_packets` |
| coherent-pcap-suricata-alerts-340.jsonl | 154 KB | suricata-eve-alert-json-v1 |
| coherent-pcap-zeek-conn-100k.jsonl | 37 MB | zeek-conn-json-v1 |
| coherent-pcap-zeek-dns-120.jsonl | 52 KB | zeek-dns-json-v1 |
| coherent-pcap-netflow-v5-100k.jsonl | 54 MB | netflow-v5-pcap-course-exfil-json-v1 |
| coherent-pcap-fortigate-100k.log | 48 MB | fortinet-fortigate-pcap-sim-7x |

เรื่องราวในข้อมูล (ผู้สอนรู้ ผู้เรียนต้องค้นเอง): host `10.70.0.66` ทำ C2 DNS beacon ทุก 60 วินาที (02:00 ชม.) → ส่งข้อมูลออก `203.0.113.66:443` ทุก 10 วินาที (20 นาที) → scan SSH ไป `10.70.1.0/24` (4 นาที) ทั้งหมดอยู่ใน 2026-08-24 00:00–02:44 UTC

## รายการ lab

| lab | gap | ผู้เรียนสั่ง Claude ว่า | สถานะเฉลย |
| --- | --- | --- | --- |
| [0 สำรวจเครื่องมือ](lab0-tools.md) | — | MCP มี tool อะไร กติกา path คืออะไร | ✅ จากเซสชัน 2026-11-02 |
| [1 parser](lab1-parser.md) | G1 | log บรรทัดนี้ใช้ parser ไหน ทดสอบให้ดู | ✅ รันจริง |
| [2 Spark report](lab2-spark-report.md) | G2 | สร้าง ids-report จาก Suricata alerts ใน HDFS | ✅ รันจริง job 30d2a9d4 |
| [3 correlate](lab3-correlate.md) | G2 | จับคู่ alert กับ Zeek conn และยืนยันด้วย PCAP | ✅ รันจริง |
| [4 enrich](lab4-enrich.md) | G3 | ดึง Feodo/KEV/EPSS แล้วเช็ค IP ใน alert | ⏳ ร่าง รันตอนเช้า (ต้องขออนุญาตดาวน์โหลด) |
| [5 รายงาน](lab5-report.md) | G4 | ทำ dashboard และ PDF จาก report | ⏳ ร่าง |
| [2b dedupe/score](lab2b-dedupe-score.md) | G2 | เขียน PySpark เองตามตัวอย่าง 7.2 (ไม่มี template) แล้วคนตรวจโค้ด | ✅ รันจริง job 291d645c: 340 → 39 offense, score ชน 100 ทุกตัว |
| [3b investigation handoff](lab3b-handoff.md) | — | สร้าง handoff-v2 จาก correlation report แล้วพิสูจน์ determinism | ✅ รันจริง job 2b6283c3: sha256 ตรงกับรอบ 20 ส.ค. |

ทุก lab มี 5 ส่วน: โจทย์ → prompt → ลำดับ tool ที่ควรเห็น → เฉลย → จุดที่คนต้องทำ และปิดท้ายด้วย "Claude ผิดตรงไหนได้บ้าง"

## หัวข้อตาม course outline ที่ครอบคลุม

| หัวข้อ | lab | ครอบคลุม | ยังขาด |
| --- | --- | --- | --- |
| M5.2 Log Analysis Automation | 1, 2, 3 | ✔ parse, canonical schema, Zeek, PCAP, batch analytics | Drain3, EVTX, Sigma |
| M6.2 Automated Alert Processing | 2, 3 | ◐ aggregate, correlate | dedupe/score (2b), Jira |
| M5.4 API Integration | 0, 4 | ◐ MCP เป็น API contract, feed สาธารณะ | OAuth2, HMAC, Wazuh API |
| M5.5 Threat Intelligence | 4 | ◐ ingest feed, match กับ log | STIX, TAXII, MISP |
| M6.3 Automated Reporting | 5 | ✔ report contract → PDF/dashboard | Navigator layer |
| M6.4 SecOps Optimization | 5 | ◐ dashboard | MTTD/MTTR, FP ต่อ rule |
| M5.3 Automation Scripts | 0, 2 | ◐ sha256, subprocess ปลอดภัย | TLS, Nmap, schedule, secrets |
| M5.1 Python Fundamentals | 2, 2b | ◐ อ่าน/แก้ PySpark | ผู้เรียนไม่ได้เขียนเองทั้งหมด |
| M6.1 Workflow Automation | 3b | ◐ handoff | TheHive, SOAR |

**ยังไม่บรรลุ** M5.3 (TLS, Nmap, schedule, secrets), M5.4 auth flow, M5.5 STIX/MISP, M6.1 SOAR จริง, M6.4 metrics จาก ticket, G5 Sigma, G6 ML — สี่ข้อหลังเพราะไม่มี ticket export, label และ rule engine ในระบบ เสนอเป็นคาบถัดไปเมื่อมี Elastic (ดู [codex-queue](../codex-queue/README.md) ใบงาน 002–016)

## ลำดับสอนที่แนะนำ (ครึ่งวัน)

0 (20 นาที) → 1 (30) → 2 (45) → พัก → 3 (45) → 3b (40) → 2b (60) → 4/5 ถ้าเหลือเวลา เหตุผล: 3b ต่อจาก 3 โดยตรงและเร็ว (9 วินาที) ส่วน 2b ต้องการให้ผู้เรียนอ่านโค้ดจึงวางท้าย

## ก่อนสอน

- ผู้สอนเปิด Claude Desktop ที่ต่อ MCP ทั้งสองตัวไว้แล้ว ผู้เรียนดูผ่านจอหรือทำตามบนเครื่องที่ต่อ MCP เดียวกัน
- ทุกคนต้องใช้ **ชื่อ output ของตัวเอง** ใน HDFS เช่น `/module7/<ชื่อ>/lab2-ids` เพราะ Spark เขียนแบบ `errorifexists`
- สิ่งที่ Claude ทำผิดได้และผู้เรียนต้องจับ (รวบรวมจากการรันจริง): ใส่ชื่อ skill ผิดตอน render (ต้องใช้ skill ของ parser ไม่ใช่ workflow), ส่ง virtual path ให้ Spark, รายงานผลก่อน job SUCCEEDED, อ่าน report จาก part file ผิดไฟล์, สรุปว่า "ถูกโจมตีแน่" ทั้งที่ tool คืนเพียงสถิติ (interpretation: no incident verdict)
