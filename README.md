# Security Automation

สื่อการสอนและงานค้นคว้าสำหรับหลักสูตร SOC / blue-team automation

- **Module 5 – Python for Cybersecurity**: Python Fundamentals, Log Analysis Automation, Security Automation Scripts, API Integration for Security Tools, Threat Intelligence Automation
- **Module 6 – Security Automation Project**: Security Workflow Automation, Automated Alert Processing, Automated Reporting, Security Operations Optimization
- **Module 7 – SOC Automation ด้วย Claude + MCP** (เพิ่ม 2026-11-02): ผู้เรียนสั่ง Claude ใช้ MCP ทำ parser, Spark report, correlate, enrich, รายงาน โดยคนเป็นผู้ตรวจ — [module7-claude-mcp/](module7-claude-mcp/README.md)

## วัตถุประสงค์ของหลักสูตร

1. มีความรู้พื้นฐานด้าน Cybersecurity ตามกรอบมาตรฐานสากล
2. สามารถวิเคราะห์เหตุการณ์ด้านความมั่นคงปลอดภัยและดำเนินการ Incident Analysis ได้อย่างเป็นระบบ
3. สามารถดำเนินการ Digital Forensics และวิเคราะห์หาสาเหตุของเหตุการณ์ด้านความมั่นคงปลอดภัยได้
4. สามารถพัฒนาเครื่องมือและระบบอัตโนมัติด้าน Cybersecurity ด้วยภาษา Python เพื่อสนับสนุนการปฏิบัติงานภายในองค์กร

Module 5–6 ใน repo นี้ตอบวัตถุประสงค์ข้อ 4 โดยตรง และต่อยอดจากข้อ 2–3

**ผู้รับผิดชอบตาม course outline**

| Module | ผู้สอน |
| --- | --- |
| Module 1, Module 4 | อ.เที่ยง |
| Module 5, Module 6 | ครูเอ้ |
| Module อื่น ๆ ที่เหลือ | อ.เมิร์ท |

## โครงสร้าง

```
docs/
  python-security-automation-research.md   # รายงาน research ฉบับเต็ม (9 หัวข้อ, โค้ด 58 ตัวอย่าง, references)
  glossary.md                              # อภิธานศัพท์
  elastic-siem-vs-qradar.md                # ELK เทียบ QRadar รายส่วน + blueprint ใบงาน Codex
  lab-design-by-gap.md                     # lab design ตาม gap G1–G6
  datasets-for-gap-labs.md                 # ชุดข้อมูลจริงสำหรับ lab ตาม gap G1–G6
  nt-siem-landscape.md                     # บริบทผู้เรียน: SIEM ที่ NT cyfence ใช้
  research_notes/                          # บันทึกการค้นคว้าต้นทาง (รอบรายงานหลัก 5 ชุด, รอบ datasets 3 ชุด)
module5/                                   # โค้ดและแบบฝึกหัดของแต่ละหัวข้อ (01–05)
module6/                                   # โค้ดและแบบฝึกหัดของแต่ละหัวข้อ (06–09)
module7-claude-mcp/                        # SOC automation ด้วย Claude + MCP (lab 0–5, คนเป็นผู้ตรวจ)
codex-queue/                               # ใบงานสั่ง Codex, กติกา, ผลและรายงาน
```

## คิวสั่งงาน Codex

ใบงานสำหรับให้ Codex สร้างโค้ดตาม lab design อยู่ใน [codex-queue/](codex-queue/README.md) (กติกา, ใบงาน 001–007, ผลและรายงาน) เจ้าของอนุมัติด้วยข้อความ `อนุมัติ NNN`

## เอกสาร

- อภิธานศัพท์: [docs/glossary.md](docs/glossary.md) คำย่อและชื่อเฉพาะทั้งหมดที่ใช้ใน repo นี้ อ่านก่อนเริ่ม lab
- รายงาน research: [docs/python-security-automation-research.md](docs/python-security-automation-research.md)
- ฉบับ doc ที่แก้ไขร่วมกันได้: https://claude.ai/artifact/QUBmwvhnnbs7f14y8Tb2z2
- ELK เป็น SIEM ใกล้ QRadar ได้แค่ไหน และ blueprint ให้ Codex สร้าง: [docs/elastic-siem-vs-qradar.md](docs/elastic-siem-vs-qradar.md) (โน้ตต้นทางใน docs/research_notes/elastic-siem/)
- Lab design ตาม gap G1–G6: [docs/lab-design-by-gap.md](docs/lab-design-by-gap.md) (6 lab พร้อมชุดข้อมูล ตัวเลขก่อน/หลัง และแบบสอบถาม gap)
- ชุดข้อมูลจริงสำหรับ lab ตาม gap G1–G6: [docs/datasets-for-gap-labs.md](docs/datasets-for-gap-labs.md) (โน้ตต้นทางใน docs/research_notes/datasets-for-gap-labs/)
- บันทึกถาม-ตอบ 2026-11-02 เรื่อง MCP server Spark/HDFS, security skill server และความเหมาะสมทำ lab: [docs/qa-2026-11-02-mcp-spark-hdfs.md](docs/qa-2026-11-02-mcp-spark-hdfs.md)
- บริบทผู้เรียน: [docs/nt-siem-landscape.md](docs/nt-siem-landscape.md) ข้อมูลสาธารณะเรื่อง SIEM ที่ NT cyfence ใช้ (IBM QRadar, McAfee/Trellix ESM) และสิ่งที่ต้องยืนยันกับผู้เรียน

หมายเหตุ: ตัวอย่างโค้ดในรายงานยังไม่ได้รันทดสอบ ควร smoke-test ก่อนนำไปใช้ในชั้นเรียน ข้อมูลและจำนวนดาว GitHub เป็นค่า ณ 2026-11-01
