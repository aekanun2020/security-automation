# M6.2 Automated Alert Processing

ศัพท์ที่ไม่คุ้นดูได้ใน[อภิธานศัพท์](../../docs/glossary.md)

**ความเกี่ยวข้องกับ log analysis:** ระดับ 2 — ทุกตัวอย่างรับ alert ซึ่งคือ log ที่ผ่าน detection rule แล้ว และ normalize ด้วย schema เดียวกับ M5.2

- รับอินพุตจาก: M5.2 (ECS/OCSF), M5.5 (indicator สำหรับ enrich), M6.1 (TheHive/Jira)
- ส่งต่อให้: M6.3 ใช้ alert ที่ score แล้วทำรายงาน; M6.4 คำนวณ false positive ต่อ rule

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 7](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- pipeline มาตรฐาน: ingest → normalize (OCSF/ECS) → dedupe (fingerprint ใน sliding window) → enrich → score → route/auto-close/escalate
- OCSF Detection Finding class_uid 2004 (schema 1.9.0) เป็น schema ขั้นต่ำ
- Google SRE: "every page should be actionable" เป็นเกณฑ์ auto-close
- หลักฐาน alert overload: Critical Start 2019/2021 (เกือบครึ่งของ SOC มี false positive ≥ 50%); SANS SOC Survey 2025 (85% trigger IR จาก endpoint alert)
- Red Canary alert states / suppression; Panther, Expel, Florian Roth เรื่อง detection quality

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- elastic/detection-rules (≈2.9k), ocsf-schema (≈910), SOCFortress CoPilot (≈538), Cortex-Analyzers (≈494)

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 7.1 FastAPI webhook receiver normalize alert เป็น OCSF Detection Finding
- ตัวอย่าง 7.2 sliding-window deduplication และ risk scoring
- ตัวอย่าง 7.3 อ่าน Elastic Security alert ด้วย elasticsearch-py แล้ว enrich
- ตัวอย่าง 7.4 escalate เป็น Jira ticket

## หมายเหตุจากการค้นคว้า

ตัวเลข dedupe window (5–15 นาที) และ "80% FP reduction" มาจากผู้ผลิตรายเดียว ไม่มีสเปก vendor-neutral หรือ peer-reviewed
