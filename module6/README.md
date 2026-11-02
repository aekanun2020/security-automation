# Module 6 — Security Automation Project

ผู้รับผิดชอบ: ครูเอ้ · รายละเอียดเต็มใน [รายงาน research](../docs/python-security-automation-research.md) ส่วนที่ 6–9

| ลำดับ | หัวข้อ | ความเกี่ยวข้องกับ log analysis | ตัวอย่างโค้ดในรายงาน |
| --- | --- | --- | --- |
| 6 | [Security Workflow Automation](06-security-workflow-automation/) | ระดับ 2 ปลายน้ำ (6.7) | 6.1–6.7 |
| 7 | [Automated Alert Processing](07-automated-alert-processing/) | ระดับ 2 ปลายน้ำ (ทุกชิ้น) | 7.1–7.4 |
| 8 | [Automated Reporting](08-automated-reporting/) | ระดับ 2 ปลายน้ำ (8.1, 8.2) | 8.1–8.6 |
| 9 | [Security Operations Optimization](09-security-operations-optimization/) | ระดับ 2 ปลายน้ำ (9.2–9.4) | 9.1–9.4 |

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

- SANS SOC Survey 2025: 69% ของ SOC ยังรายงาน metrics ด้วยมือ; 85% trigger incident response จาก endpoint alert; 42% dump ข้อมูลทั้งหมดลง SIEM โดยไม่มีแผน
- Critical Start: เกือบครึ่งของ SOC มี false positive ≥ 50%
- Gartner จัด standalone SOAR เป็น "obsolete before plateau" (2024) แต่ทุก platform ในขอบเขตยังมี entry point Python

## ข้อควรระวัง

- โค้ดทุกชิ้นในรายงานยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน
- ตัวเลข dedupe window, FP threshold และสัดส่วน alerts ต่อ analyst เป็นความเห็นของ practitioner/ผู้ผลิต ไม่ใช่มาตรฐาน
- repo สาธารณะของ TheHive ถูก archive แล้ว (StrangeBee เป็นเชิงพาณิชย์); Awesome-SOAR ไม่อัปเดตตั้งแต่ ส.ค. 2024
