# M6.4 Security Operations Optimization

ศัพท์ที่ไม่คุ้นดูได้ใน[อภิธานศัพท์](../../docs/glossary.md)

**ความเกี่ยวข้องกับ log analysis:** ระดับ 2 — metrics คำนวณจาก timestamp และ rule hit ที่มาจาก log (9.2–9.4); visibility coverage วัดจาก data source ที่ parse ได้

- รับอินพุตจาก: M5.2 (data source/visibility), M6.2 (alert ต่อ rule), M6.3 (Navigator layer)
- ส่งต่อให้: ปิดโปรเจ็กต์ Module 6: dashboard และ tuning backlog

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 9](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- MITRE 11 Strategies (2022) โดยเฉพาะ Strategy 10 "Measure Performance to Improve Performance"
- SOC-CMM (Rob van Os, 2016; spreadsheet v2.4.2, CC BY-SA 4.0) และ SOC-CMM Metrics 101 (นิยาม % false positives, % benign positives, % ATT&CK coverage, % ATT&CK visibility)
- NIST CSF 2.0; SANS SOC Survey 2025 (Crowley); SANS SOC Metrics Cheat Sheet (2025)
- Detection Engineering Maturity Matrix (Kyle Bailey, 2021/2022); Elastic DEBMM (2024)
- DeTT&CT (≈2.4k) สองแกน visibility/detection; Atomic Red Team (≈12.7k) และ CALDERA (≈7.5k, ย้ายไป Apache) สำหรับ validate coverage
- benchmark: M-Trends 2025 (dwell time median 11 วัน) / 2026 (14 วัน), Verizon DBIR 2025/2026, Red Canary, Expel; Google SRE เรื่อง toil และ SLO

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- awesome-soc (≈1.9k, push ล่าสุด ต.ค. 2026) เป็นดัชนีที่ดีที่สุดของหัวข้อนี้
- awesome-detection-engineering (≈1.4k), ThreatHunter-Playbook (≈4.7k), msticpy (≈2.0k)

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 9.1 เปอร์เซ็นต์ coverage เทียบ technique ทั้งหมด (mitreattack-python)
- ตัวอย่าง 9.2 MTTD และ MTTR จาก ticket export
- ตัวอย่าง 9.3 อัตรา false positive ต่อ rule และการจัดลำดับ tuning
- ตัวอย่าง 9.4 โครง Streamlit SOC dashboard

## หมายเหตุจากการค้นคว้า

threshold ของ practitioner (FP 30% vs 50%, 5–50 alerts/analyst/day, coverage 20–40%) ขัดแย้งกันและเป็นความเห็น ไม่ใช่มาตรฐาน; ชื่อระดับ maturity ของ SOC-CMM ยืนยันจาก soc-cmm.com ไม่ได้
