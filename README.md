# Security Automation

สื่อการสอนและงานค้นคว้าสำหรับหลักสูตร SOC / blue-team automation

- **Module 5 – Python for Cybersecurity**: Python Fundamentals, Log Analysis Automation, Security Automation Scripts, API Integration for Security Tools, Threat Intelligence Automation
- **Module 6 – Security Automation Project**: Security Workflow Automation, Automated Alert Processing, Automated Reporting, Security Operations Optimization

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
  lab-design-by-gap.md                     # lab design ตาม gap G1–G6
  datasets-for-gap-labs.md                 # ชุดข้อมูลจริงสำหรับ lab ตาม gap G1–G6
  nt-siem-landscape.md                     # บริบทผู้เรียน: SIEM ที่ NT cyfence ใช้
  research_notes/                          # บันทึกการค้นคว้าต้นทาง (รอบรายงานหลัก 5 ชุด, รอบ datasets 3 ชุด)
module5/                                   # โค้ดและแบบฝึกหัดของแต่ละหัวข้อ (01–05)
module6/                                   # โค้ดและแบบฝึกหัดของแต่ละหัวข้อ (06–09)
```

## เอกสาร

- รายงาน research: [docs/python-security-automation-research.md](docs/python-security-automation-research.md)
- ฉบับ doc ที่แก้ไขร่วมกันได้: https://claude.ai/artifact/QUBmwvhnnbs7f14y8Tb2z2
- Lab design ตาม gap G1–G6: [docs/lab-design-by-gap.md](docs/lab-design-by-gap.md) (6 lab พร้อมชุดข้อมูล ตัวเลขก่อน/หลัง และแบบสอบถาม gap)
- ชุดข้อมูลจริงสำหรับ lab ตาม gap G1–G6: [docs/datasets-for-gap-labs.md](docs/datasets-for-gap-labs.md) (โน้ตต้นทางใน docs/research_notes/datasets-for-gap-labs/)
- บริบทผู้เรียน: [docs/nt-siem-landscape.md](docs/nt-siem-landscape.md) ข้อมูลสาธารณะเรื่อง SIEM ที่ NT cyfence ใช้ (IBM QRadar, McAfee/Trellix ESM) และสิ่งที่ต้องยืนยันกับผู้เรียน

หมายเหตุ: ตัวอย่างโค้ดในรายงานยังไม่ได้รันทดสอบ ควร smoke-test ก่อนนำไปใช้ในชั้นเรียน ข้อมูลและจำนวนดาว GitHub เป็นค่า ณ 2026-11-01
