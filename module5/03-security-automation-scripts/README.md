# M5.3 Security Automation Scripts

**ความเกี่ยวข้องกับ log analysis:** ระดับ 2 — ปลายน้ำของ log analysis (parse output ที่มีโครงสร้างและตั้งเวลารัน job)

- รับอินพุตจาก: M5.1 (CLI, logging) และวิธี parse จาก M5.2
- ส่งต่อให้: M5.4 ใช้ Session/retry/secrets pattern ต่อ; M6.1 ใช้ subprocess pattern ใน active response

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 3](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- เอกสาร `hashlib.file_digest` (3.11+) และ `hmac.compare_digest`
- เอกสาร `ssl` / `socket` สำหรับตรวจ certificate
- เอกสาร `subprocess.run` (shell=False, check=True, timeout)
- `schedule` (ไม่มี persistence) เทียบ APScheduler 3.x (job store, misfire_grace_time)
- pydantic-settings (`BaseSettings`, `SecretStr`) สำหรับ secrets จาก environment
- Nmap XML output (`-oX`)
- Security Automation with Python (Packt, ก.พ. 2025)

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- python-nmap (release ล่าสุด ต.ค. 2021) และ python-libnmap (≈493)
- awesome-cybersecurity-blueteam (≈5.6k)
- บทความ TechTarget (มี.ค. 2026) เรื่อง SOC use cases ของ Python

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 3.1 SHA-256 file-integrity baseline
- ตัวอย่าง 3.2 ตรวจวันหมดอายุ TLS certificate
- ตัวอย่าง 3.3 parse Nmap XML ด้วย ElementTree / 3.3b ด้วย python-nmap
- ตัวอย่าง 3.4 scheduled job ด้วย `schedule` และ subprocess อย่างปลอดภัย
- ตัวอย่าง 3.5 secrets/config ด้วย pydantic-settings

## หมายเหตุจากการค้นคว้า

ไม่มี snippet parse ไฟล์ .nessus/OpenVAS เพราะหน้า file format ของ Tenable คืน 404 ระหว่างค้นคว้า
