# M5.2 Log Analysis Automation

**ความเกี่ยวข้องกับ log analysis:** ระดับ 1 — log analysis โดยตรง (หัวข้อแกนของทั้ง Module 5 และ 6)

- รับอินพุตจาก: M5.1 (regex, Counter, deque, CLI)
- ส่งต่อให้: M6.2 ใช้ schema ECS/OCSF เดียวกันในการ normalize alert; M6.4 วัด visibility coverage จาก data source ที่ parse ได้

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 2](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- RFC 5424 The Syslog Protocol (PRI = facility×8 + severity)
- Apache `mod_log_config` (common/combined) และ nginx `ngx_http_log_module` (`escape=json`)
- Windows EVTX ตาม spec ของ libevtx (Joachim Metz)
- ArcSight CEF Implementation Standard และ IBM LEEF
- Elastic Common Schema 9.5.0 และ OCSF 1.9.0 (Linux Foundation ตั้งแต่ พ.ย. 2024)
- NIST SP 800-92 Rev. 1 (initial public draft ต.ค. 2023 ยังไม่ final)
- งานวิชาการ: Drain (ICWS 2017), loglizer (ISSRE 2016), DeepLog (CCS 2017), Loghub (ISSRE 2023), Elastic beaconing framework (2023)

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- python-evtx (≈786), pyevtx-rs, Plaso (≈2.2k)
- pySigma (≈604) และ sigma-cli (≈220)
- Drain3 (≈904), loglizer (≈1.4k), loghub (≈2.9k), awesome-log-analysis (≈810)
- ZAT (≈456), RITA (≈667) สำหรับ Zeek และ beacon
- Chainsaw (≈3.7k) และ Hayabusa (≈3.4k) ไว้เปรียบเทียบ (Rust)

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 2.1 ตรวจ burst ของ failed login ใน auth.log (sliding window)
- ตัวอย่าง 2.2 อ่าน EVTX ด้วย python-evtx ดึง Event ID 4625
- ตัวอย่าง 2.3 syslog (RFC 5424 และแบบดั้งเดิม) → pandas resample
- ตัวอย่าง 2.4 template mining ด้วย Drain3
- ตัวอย่าง 2.5 แปลง Sigma rule ด้วย pySigma
- ตัวอย่าง 2.6 Zeek conn.log → pandas หา beacon ด้วย ZAT
- ตัวอย่าง 2.7 access log → pandas: อัตรา 404 ต่อ IP, รายชั่วโมง, user agent หายาก

## หมายเหตุจากการค้นคว้า

ลำดับการสอนที่ research เสนอ: raw text (syslog, combined) → binary (EVTX) → vendor interchange (CEF) → normalization (ECS/OCSF) และให้ผู้เรียน map record ใด ๆ เข้า field ของ ECS/OCSF ได้ threshold ในตัวอย่าง (5 ครั้ง/60–300 วินาที, CV < 0.3) เป็นธรรมเนียมของชุมชน ไม่ใช่มาตรฐาน
