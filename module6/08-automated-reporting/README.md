# M6.3 Automated Reporting

**ความเกี่ยวข้องกับ log analysis:** ระดับ 2 — ข้อมูลตั้งต้นคือ alert/ticket export (ตัวอย่าง 8.1, 8.2); 8.3–8.6 เป็นเรื่อง format

- รับอินพุตจาก: M6.2 (alert ที่ normalize/score แล้ว), M6.1 (case data)
- ส่งต่อให้: M6.4 ใช้ Navigator layer (8.4) และ EPSS (8.5) เป็นหลักฐาน coverage/priority

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 8](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- Jinja2, WeasyPrint, ReportLab, python-docx, python-pptx, matplotlib, plotly, pandas, Streamlit, Pandoc
- Kibana Reporting API (internal/unstable) และ Grafana Enterprise reporting API (ยังไม่ stabilized)
- ATT&CK Navigator Layer Format v4.5
- CVSS v4.0 (FIRST) และ EPSS API ที่ api.first.org/epss/ (`cve` ≤ 2000 ตัวอักษร)
- NIST SP 800-61 Rev. 3 (RS.MA-02 incident reports, ID.IM-03 follow-up/lessons learned), SANS IH forms, SRE postmortem, PCI DSS v4.0.1 10.4/12.10, ISO 27001 9.1
- SANS SOC Survey 2025: 69% ของ SOC ยังรายงาน metrics ด้วยมือ

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- attack-navigator (≈2.5k), mitreattack-python (≈755), Streamlit (≈46k), matplotlib (≈23k), Jinja (≈12k), WeasyPrint (≈9.8k), python-docx (≈5.8k)

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 8.1 รายงาน incident รายสัปดาห์: pandas → Jinja2 → HTML → PDF
- ตัวอย่าง 8.2 bar chart ของ alert ตาม severity
- ตัวอย่าง 8.3 รายงาน DOCX ด้วย python-docx
- ตัวอย่าง 8.4 ATT&CK Navigator layer JSON
- ตัวอย่าง 8.5 ดึง EPSS แล้วจัดลำดับช่องโหว่
- ตัวอย่าง 8.6 Markdown → PDF ผ่าน Pandoc

## หมายเหตุจากการค้นคว้า

ไม่มี snippet ในหัวข้อนี้ที่คัดจากแหล่งภายนอกแบบ verbatim ทุกชิ้นเป็น illustrative จาก API ที่มีเอกสาร
