# Module 6 — Security Automation Project

ผู้รับผิดชอบ: ครูเอ้ · รายละเอียดเต็มใน [รายงาน research](../docs/python-security-automation-research.md) ส่วนที่ 6–9 · ศัพท์ที่ไม่คุ้นดูได้ใน[อภิธานศัพท์](../docs/glossary.md)

| ลำดับ | หัวข้อ | ความเกี่ยวข้องกับ log analysis | ตัวอย่างโค้ดในรายงาน |
| --- | --- | --- | --- |
| 6 | [Security Workflow Automation](06-security-workflow-automation/) | ระดับ 2 ปลายน้ำ (6.7) | 6.1–6.7 |
| 7 | [Automated Alert Processing](07-automated-alert-processing/) | ระดับ 2 ปลายน้ำ (ทุกชิ้น) | 7.1–7.4 |
| 8 | [Automated Reporting](08-automated-reporting/) | ระดับ 2 ปลายน้ำ (8.1, 8.2) | 8.1–8.6 |
| 9 | [Security Operations Optimization](09-security-operations-optimization/) | ระดับ 2 ปลายน้ำ (9.2–9.4) | 9.1–9.4 |
| 10 | [แทร็ก lab: Claude + MCP](10-claude-mcp-labs/) | วิธีสอนทางเลือก: ผู้เรียนสั่ง Claude ใช้ MCP ทำ 7.2, 6.1, 8.1 และ M5.2 บน Spark/HDFS โดยคนเป็นผู้ตรวจ (เพิ่ม 2026-11-02) | lab 0–5, 2b, 3b |

## โปรเจ็กต์ปลายทางที่ research เสนอ

ต่อตัวอย่าง 7.1 → 7.2 → 6.1/7.4 → 8.1/8.4/9.1–9.3 เป็น pipeline เดียวบน platform ฟรี:

```
Wazuh / Elastic (detection จาก log)
  → webhook → FastAPI normalizer เป็น OCSF Detection Finding (7.1)
  → dedupe / risk score (7.2) → enrich ด้วย reputation และ CTI (7.3, Cortex 6.2)
  → TheHive alert/case (6.1) หรือ Jira ticket (7.4) → Shuffle / n8n workflow
  → รายงาน PDF (8.1), Navigator layer (8.4), MTTD/MTTR และ FP ต่อ rule (9.2, 9.3), dashboard (9.4)
```

ทุกขั้นรับอินพุตที่สืบมาจาก log ดังนั้น M5.2 เป็นข้อกำหนดก่อนเรียนของทั้ง Module 6

## หลักฐานที่ใช้ตั้งโจทย์โปรเจ็กต์

ตัวเลขจากแบบสำรวจที่ใช้เป็น "ค่าก่อนเรียน" ของแต่ละ gap (ดู [lab design ตาม gap](../docs/lab-design-by-gap.md)) ทุกตัวเลขเป็นภาพรวมของ SOC ทั่วโลก ไม่ใช่ตัวเลขของ NT ศัพท์ในตารางนิยามไว้ใน [glossary หมวด 1](../docs/glossary.md#1-งาน-soc)

| ตัวเลข | หมายความว่า | ตั้งโจทย์ | แหล่ง | สถานะการอ้าง |
| --- | --- | --- | --- | --- |
| 69% ของ SOC ยังรายงาน metrics ด้วยมือ | SOC 7 ใน 10 แห่งยังทำรายงานตัวเลขให้ผู้บริหารโดย export จาก SIEM และระบบ ticket มาจัดใน Excel/PowerPoint เอง ทั้งที่ข้อมูลอยู่ในระบบแล้ว | G4 · M6.3, M6.4 · lab 5 | SANS SOC Survey 2025 ครั้งที่ 9 ผู้ตอบจาก 57 ประเทศ ([PDF](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)) | อ้างจาก PDF ตรง |
| 85% trigger incident response จาก endpoint alert | เหตุที่ต้องลงมือจัดการจริงส่วนใหญ่เริ่มจากแจ้งเตือนของ EDR บนเครื่องปลายทาง (endpoint) ไม่ใช่จาก firewall หรือ rule ใน SIEM log จาก endpoint จึงเป็นแหล่งที่สำคัญที่สุด | M5.2 (EVTX) · M6.2 | SANS SOC Survey 2025 | อ้างผ่านสรุปของผู้ผลิต ([Swimlane](https://swimlane.com/blog/global-soc-survey-insights/), [Torq](https://torq.io/blog/sans-2025-soc-survey)) ยังไม่ได้ตรวจกับ PDF |
| 42% dump ข้อมูลทั้งหมดลง SIEM โดยไม่มีแผน | SOC 4 ใน 10 แห่งเทข้อมูลทุกอย่างลง SIEM โดยไม่มีแผนว่าจะดึงกลับมาใช้อย่างไร ผลคือ log จำนวนมากไม่มี parser ค้นไม่ได้ และเสียค่าเก็บ | G1 · M5.2 · lab 1 | SANS SOC Survey 2025 ([PDF](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)) | อ้างจาก PDF ตรง |
| เกือบครึ่งของ SOC มี false positive ≥ 50% | alert ที่ดังทุกวันเกินครึ่งเป็นการเตือนผิด analyst เสียเวลากับของปลอม และของจริงหลุดได้ง่าย | G2 · M6.2 · lab 2, 2b, 3 | Critical Start SOC survey 2019 จาก SOC ราว 50 แห่ง ([ประกาศ](https://criticalstart.com/resources/criticalstart-releases-third-annual-security-operations-center-soc-professional-survey)) | ตัวเลขปี 2019 กลุ่มตัวอย่างเล็ก และสื่ออื่นรายงานตัวเลขขัดแย้งกัน |
| Gartner จัด standalone SOAR เป็น "obsolete before plateau" (2024) | ใน Hype Cycle 2024 บริษัทวิจัย Gartner มองว่า SOAR ที่ขายแยกล้าสมัยก่อนจะถึงช่วงใช้งานมั่นคง เพราะ SIEM และ platform ใหญ่รวมความสามารถนี้เข้าไปแล้ว ผู้ซื้อไม่ต้องซื้อแยก | M6.1 เลือกสอน Python แทนผลิตภัณฑ์ SOAR ตัวใดตัวหนึ่ง | Gartner Hype Cycle for Security Operations, 29 ก.ค. 2024 | Gartner ติด paywall อ้างผ่านผู้ผลิต SOAR และสองแหล่งระบุวันที่ไม่ตรงกัน |
| แต่ทุก platform ในขอบเขตยังมี entry point Python | platform ทุกตัวที่รายงานสำรวจ (เช่น n8n, Wazuh) เปิดช่องให้เสียบฟังก์ชัน Python ที่รับ dict เข้าและคืน dict ออก ชื่อผลิตภัณฑ์ SOAR อาจหายไป แต่ทักษะ Python ต่อระบบยังจำเป็น | M6.1 ตัวอย่าง 6.1–6.7 | [รายงาน research ส่วนที่ 6](../docs/python-security-automation-research.md) | ตรวจจากเอกสารของแต่ละ platform ณ 2026-11-01 |

## ข้อควรระวัง

- โค้ดทุกชิ้นในรายงานยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน
- ตัวเลข dedupe window, FP threshold และสัดส่วน alerts ต่อ analyst เป็นความเห็นของ practitioner/ผู้ผลิต ไม่ใช่มาตรฐาน
- repo สาธารณะของ TheHive ถูก archive แล้ว (StrangeBee เป็นเชิงพาณิชย์); Awesome-SOAR ไม่อัปเดตตั้งแต่ ส.ค. 2024
