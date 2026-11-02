# M5.4 API Integration for Security Tools

**ความเกี่ยวข้องกับ log analysis:** ระดับ 2 — ส่ง log ขึ้น SIEM และดึง alert ที่สร้างจาก log (ตัวอย่าง 4.9, 4.10)

- รับอินพุตจาก: M5.3 (Session, retry, secrets)
- ส่งต่อให้: M5.5 ใช้ pattern เดียวกันกับ TAXII/MISP/OTX; M6.2 ใช้ 7.3 (elasticsearch-py) และ reputation lookup

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 4](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- requests `Session` + urllib3 `Retry` (respect_retry_after_header), RFC 6585 §4 (HTTP 429), RFC 6749 §4.4 (OAuth2 client credentials)
- NVD CVE API 2.0 (apiKey header, 5/50 req ต่อ 30 วินาที, 2000 ต่อหน้า)
- CISA KEV JSON feed (ไม่ต้อง auth, BOD 22-01/26-04)
- VirusTotal vt-py (4/นาที, 500/วัน), Shodan, AbuseIPDB (1,000/วัน), Have I Been Pwned (k-anonymity)
- CrowdStrike FalconPy และ Microsoft Graph Security (OAuth2 client credentials)
- Azure Monitor Data Collector (HMAC-SHA256, deprecated; สิ้นสุด support 14 ก.ย. 2026)
- Wazuh API (basic auth → JWT), Splunk SDK, elasticsearch-py, pyTenable, PyMISP, Slack SDK

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- elasticsearch-py (≈4.4k), vt-py (≈792), splunk-sdk-python (≈747), msgraph-sdk-python (≈634), FalconPy (≈517), PyMISP (≈494), nvdlib (≈118)

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 4.1 requests.Session + Retry/backoff
- ตัวอย่าง 4.2 NVD CVE API 2.0 พร้อม pagination และ rate limit
- ตัวอย่าง 4.3 ค้น file hash บน VirusTotal (vt-py)
- ตัวอย่าง 4.4 ดึง CISA KEV แล้ว filter
- ตัวอย่าง 4.5 ส่ง alert เข้า Slack webhook พร้อม retry 429
- ตัวอย่าง 4.6 IP reputation กับ AbuseIPDB
- ตัวอย่าง 4.7 Pwned Passwords แบบ k-anonymity
- ตัวอย่าง 4.8 OAuth2 client credentials ผ่าน FalconPy และ MS Graph
- ตัวอย่าง 4.9 HMAC-SHA256 SharedKey สำหรับ Azure Monitor custom logs
- ตัวอย่าง 4.10 Wazuh API: basic-auth → JWT → Bearer

## หมายเหตุจากการค้นคว้า

รูปแบบ auth สามแบบครอบคลุมทุก API ในขอบเขต: static key ใน header, OAuth2 client credentials/JWT exchange, HMAC-SHA256 research เสนอให้ KEV และ ATT&CK TAXII เป็น integration แรกเพราะไม่ต้อง auth
