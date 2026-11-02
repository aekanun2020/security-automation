# M5.1 Python Fundamentals

**ความเกี่ยวข้องกับ log analysis:** ระดับ 1 — log analysis โดยตรง

- รับอินพุตจาก: ไม่มี (จุดเริ่มต้นของ Module 5)
- ส่งต่อให้: M5.2 ใช้ idiom regex + Counter, tail -f และโครง CLI ต่อทันที

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 1](../../docs/python-security-automation-research.md)

## แหล่งต้นฉบับ

- เอกสาร Python standard library: `re`, `collections` (Counter, deque, defaultdict), `csv`, `json`, `argparse`, `logging`, `pathlib`, `datetime` (หมายเหตุ: `argparse.FileType` deprecated ตั้งแต่ 3.14)
- Al Sweigart, *Automate the Boring Stuff with Python*, 3rd ed. (No Starch, พ.ค. 2025) บท 9, 10, 12, 16, 18, 19
- SANS SEC573 (Mark Baggett) ปัจจุบันชื่อ "AI-Powered Security Automation: Building Tools with Python, LLMs, and MCP", 128 labs, GPYC
- Howard Poston, *Python for Cybersecurity* (Wiley, 2022) จัดบทตาม MITRE ATT&CK
- Troncone & Albing, *Cybersecurity Ops with bash* (O'Reilly, 2019) ใช้เปรียบเทียบ shell กับ Python
- David Beazley, "Generator Tricks for Systems Programmers" (PyCon 2008) ที่มาของ idiom `follow()`

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- awesome-threat-detection (0x4D31, ≈4.8k ดาว)
- BHIS webcast "Log File Frequency Analysis with Python" (2017)
- ISC diary 20451 และ `freq.py` ของ Mark Baggett

## ตัวอย่างโค้ดในรายงาน

ยังไม่ได้ย้ายมาเป็นไฟล์ในโฟลเดอร์นี้ (ระดับ 2) ทุกชิ้นยังไม่ได้รันทดสอบ ต้อง smoke-test ก่อนใช้สอน

- ตัวอย่าง 1.1 parse Nginx/Apache combined log ด้วย regex + Counter
- ตัวอย่าง 1.2 streaming log watcher แบบ `tail -f` ด้วย generator
- ตัวอย่าง 1.3 โครง CLI ด้วย argparse + logging + csv/json

## หมายเหตุจากการค้นคว้า

ทั้งสามตัวอย่างทำงานกับ log โดยตรง จึงเป็นฐานของ M5.2
