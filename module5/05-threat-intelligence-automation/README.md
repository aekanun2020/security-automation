# M5.5 Threat Intelligence Automation

ศัพท์ที่ไม่คุ้นดูได้ใน[อภิธานศัพท์](../../docs/glossary.md)

**ความเกี่ยวข้องกับ log analysis:** ระดับ 3 — ไม่ได้แตะ log โดยตรง (แต่ indicator ที่ได้ถูกนำไป match กับ log ในขั้น enrich ของ M6.2)

- รับอินพุตจาก: M5.4 (API pattern, AbuseIPDB)
- ส่งต่อให้: M6.2 ขั้น enrich (7.2, 7.3) และ M6.1 Cortex analyzer (6.2)

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 5](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- STIX 2.1 (OASIS, Errata 01 เม.ย. 2025) และ TAXII 2.1 (มิ.ย. 2021); library `stix2`, `taxii2-client`
- MITRE ATT&CK เป็น STIX 2.1 ผ่าน attack-stix-data และ TAXII server สาธารณะ (50 req/10 นาที); `mitreattack-python`
- MISP/PyMISP, OpenCTI/pycti (client-python repo ถูก archive ธ.ค. 2025 ย้ายเข้า monorepo), AlienVault OTX SDK
- Pyramid of Pain (Bianco 2013), Diamond Model (2013), Cyber Kill Chain (Hutchins et al. 2011), NIST SP 800-150 (2016), TLP 2.0 (FIRST 2022)
- Brown & Roberts, *Intelligence-Driven Incident Response*, 2nd ed. (O'Reilly 2023); Costa-Gazcón, *Practical Threat Intelligence and Data-Driven Threat Hunting* (Packt 2021)
- CTI lifecycle 6 ขั้น (Direction → Collection → Processing → Analysis → Dissemination → Feedback) ตาม Recorded Future และ SANS FOR578

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- awesome-threat-intelligence (≈10.8k), IntelOwl (≈4.8k), msticpy (≈2.0k), Yeti (≈2.0k), ThreatIngestor (≈932), iocextract (≈581), ioc-finder (≈184)
- pyattck ถูก archive มี.ค. 2026 ไม่ควรใช้สอน
- abuse.ch URLhaus ต้องใช้ Auth-Key ฟรีแล้ว endpoint CSV เดิมคืน 410

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 5.1 refang และดึง IOC ด้วย iocextract
- ตัวอย่าง 5.2 grammar-based extraction ด้วย ioc-finder
- ตัวอย่าง 5.3 สร้าง STIX 2.1 Indicator/Malware/Relationship/Bundle
- ตัวอย่าง 5.4 poll ATT&CK TAXII 2.1 ด้วย taxii2-client
- ตัวอย่าง 5.5 ค้น event/attribute ใน MISP ด้วย PyMISP
- ตัวอย่าง 5.6 ดึง OTX pulse แล้ว flatten
- ตัวอย่าง 5.7 enrich IP ด้วย AbuseIPDB และ map เข้า ATT&CK
- ตัวอย่าง 5.8 ingest feed abuse.ch ด้วย pandas และ de-duplicate
- ตัวอย่าง 5.9 indicator พร้อม TLP marking ใน OpenCTI ด้วย pycti
- ตัวอย่าง 5.10 multi-provider enrichment ด้วย msticpy TILookup

## หมายเหตุจากการค้นคว้า

ชื่อคอลัมน์ CSV ของ URLhaus/Feodo Tracker ยืนยันไม่ได้ (อยู่หลัง login) ตัวอย่าง 5.8 จึงค้นหา column ตอน runtime
