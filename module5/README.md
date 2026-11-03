# Module 5 — Python for Cybersecurity

ผู้รับผิดชอบ: ครูเอ้ · รายละเอียดเต็มใน [รายงาน research](../docs/python-security-automation-research.md) ส่วนที่ 1–5 · ศัพท์ที่ไม่คุ้นดูได้ใน[อภิธานศัพท์](../docs/glossary.md)

| ลำดับ | หัวข้อ | ความเกี่ยวข้องกับ log analysis | ตัวอย่างโค้ดในรายงาน |
| --- | --- | --- | --- |
| 1 | [Python Fundamentals](01-python-fundamentals/) | ระดับ 1 โดยตรง | 1.1–1.3 |
| 2 | [Log Analysis Automation](02-log-analysis-automation/) | ระดับ 1 โดยตรง (หัวข้อแกน) | 2.1–2.7 |
| 3 | [Security Automation Scripts](03-security-automation-scripts/) | ระดับ 2 ปลายน้ำ | 3.1–3.5 |
| 4 | [API Integration for Security Tools](04-api-integration/) | ระดับ 2 ปลายน้ำ (4.9, 4.10) | 4.1–4.10 |
| 5 | [Threat Intelligence Automation](05-threat-intelligence-automation/) | ระดับ 3 ไม่แตะ log | 5.1–5.10 |

## ลำดับการสอนที่ research เสนอ

1. เริ่มจาก standard library ล้วน (ตัวอย่าง 1.1–1.3, 2.1, 3.1–3.3) ก่อนเพิ่ม third-party ทีละตัว: pandas, drain3, pysigma, zat, requests + Retry, stix2/taxii2-client
2. ใน M5.2 ไล่รูปแบบ log จาก raw text (syslog, combined access log) → binary (EVTX) → vendor interchange (CEF) → normalization (ECS/OCSF) และให้ผู้เรียน map record ใด ๆ เข้า field ของ ECS/OCSF ได้
3. ใน M5.4 ใช้ CISA KEV และ MITRE ATT&CK TAXII เป็น integration แรก เพราะไม่ต้อง auth และมี schema ชัด

## ข้อควรระวัง

- โค้ดทุกชิ้นในรายงานยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน
- threshold ในตัวอย่าง (brute force 5 ครั้ง/60–300 วินาที, beacon CV < 0.3) เป็นธรรมเนียมของชุมชน ไม่ใช่มาตรฐาน
- repo ที่ถูก archive แล้วและไม่ควรใช้สอน: pyattck (มี.ค. 2026), OpenCTI client-python (ธ.ค. 2025)
