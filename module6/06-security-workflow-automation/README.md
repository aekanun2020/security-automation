# M6.1 Security Workflow Automation

**ความเกี่ยวข้องกับ log analysis:** ระดับ 2 — ตอบสนองต่อ rule ที่ยิงจาก log (ตัวอย่าง 6.7); ที่เหลือเป็น orchestration

- รับอินพุตจาก: M5.3 (subprocess), M5.4 (API), M5.5 (enrichment)
- ส่งต่อให้: M6.2 ส่ง alert ที่ normalize แล้วเข้า TheHive/Jira; M6.3 ใช้ case data ทำรายงาน

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 6](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- Gartner บัญญัติ SOAR ราว เม.ย. 2017 และจัด standalone SOAR เป็น "obsolete before plateau" ใน Hype Cycle 2024 (อ้างผ่านผู้ผลิต; Gartner paywall)
- NIST SP 800-61 Rev. 3 (เม.ย. 2025) ปรับเป็น CSF 2.0 Community Profile
- SANS Incident Handler's Handbook (PICERL 6 ขั้น)
- MITRE *11 Strategies of a World-Class Cybersecurity Operations Center* (2022)
- OASIS CACAO Security Playbooks v2.0 (พ.ย. 2023)
- OCSF Detection Finding (class_uid 2004)
- Platform ที่มี entry point Python: TheHive/thehive4py, Cortex/cortexutils, Shuffle (AppBase), Splunk SOAR (phantom), Cortex XSOAR (demisto), StackStorm, Wazuh active response, Tines, n8n

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- n8n (≈209k), Wazuh (≈17.5k), Sigma (≈11.4k), awesome-incident-response (≈9.5k), StackStorm (≈6.6k), Security Onion (≈5.0k), TheHive (≈3.9k, archived), Shuffle (≈2.5k), Cortex (≈1.6k), demisto/content (≈1.3k), Awesome-SOAR (≈1.0k, ไม่อัปเดตตั้งแต่ ส.ค. 2024)

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 6.1 สร้าง TheHive alert พร้อม observables แล้ว promote เป็น case
- ตัวอย่าง 6.2 Cortex analyzer ขั้นต่ำด้วย cortexutils
- ตัวอย่าง 6.3 Splunk SOAR playbook geolocate IP
- ตัวอย่าง 6.4 โครง automation script ของ XSOAR
- ตัวอย่าง 6.5 Shuffle Python app (AppBase)
- ตัวอย่าง 6.6 StackStorm Python action
- ตัวอย่าง 6.7 โครง Wazuh custom active response

## หมายเหตุจากการค้นคว้า

รายชื่อ 11 strategies ในโน้ตมาจากความจำและทำเครื่องหมายว่ายังไม่ได้ตรวจกับ mitre.org (403 ระหว่างค้นคว้า)
