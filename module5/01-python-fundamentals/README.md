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

## ตัวอย่างโค้ด (ระดับ 2: แยกเป็นไฟล์และ smoke-test แล้ว)

โค้ดคัดจากรายงานโดยไม่แก้ไขตรรกะ ทุกไฟล์ใช้ standard library เท่านั้น ไม่ต้องมี venv

```bash
./run_smoke_tests.sh        # รันทุกตัวอย่าง (1.1 ใช้ access.log ของ M5.2, 1.2 ทดสอบแบบ live, 1.3 ใช้ samples/events.jsonl)
```

| ตัวอย่าง | ไฟล์ | sample | ผล smoke-test (2026-11-02, Python 3.12.7) |
| --- | --- | --- | --- |
| 1.1 | `1_1_combined_log_counter.py` | `../02-log-analysis-automation/samples/access.log` | ผ่าน: top talker และ scanner 203.0.113.50 (73/80 = 91% เป็น 404), user agent หายาก 6 ตัว |
| 1.2 | `1_2_follow_log_watcher.py` | ไฟล์ชั่วคราวที่ harness append บรรทัดลงไประหว่างรัน | ผ่าน: alert `203.0.113.9: 5 failed logins in 60s` ภายใน 5 วินาทีหลัง append ครบ 5 บรรทัด |
| 1.3 | `1_3_jsonl_field_counter.py` | `samples/events.jsonl` (ECS-style 300 event + 2 บรรทัดเสีย) | ผ่าน: นับ `source.ip` ได้ 203.0.113.50 = 100, เขียน CSV ได้, `-v` รายงานบรรทัด JSON เสียที่ตำแหน่งที่ถูกต้อง |

### ข้อสังเกตจาก smoke-test

1. ไม่ต้องแก้โค้ดจากรายงานแม้แต่บรรทัดเดียว ต่างจาก M5.2 ที่ต้องแก้ import ของ 2.2b
2. 1.2 ทดสอบเฉพาะกรณี append ปกติ ยังไม่ได้ทดสอบกรณี logrotate (inode เปลี่ยน) และ truncate ซึ่ง `follow()` อ้างว่ารองรับ เหมาะเป็นแบบฝึกหัดให้ผู้เรียนเขียน test เพิ่ม
3. 1.2 พิมพ์ alert ซ้ำทุกบรรทัดที่ทำให้จำนวนใน window ≥ 5 (ไม่มี `alerted` set แบบ 2.1) ตามรายงาน ผู้สอนอาจใช้เป็นจุดเปรียบเทียบกับ 2.1
4. 1.1 ใช้ sample ร่วมกับ M5.2 โดยตั้งใจ เพื่อให้ผู้เรียนเห็นว่า regex + Counter (1.1) กับ pandas (2.7) ให้ผลเดียวกันบนข้อมูลเดียวกัน
5. 1.3 ส่ง log ระดับ INFO ออก stderr ส่วนผลนับออก stdout จึง pipe ผลไปต่อได้โดยไม่ปน (`2>/dev/null`)

### รายการตัวอย่าง

- ตัวอย่าง 1.1 parse Nginx/Apache combined log ด้วย regex + Counter
- ตัวอย่าง 1.2 streaming log watcher แบบ `tail -f` ด้วย generator
- ตัวอย่าง 1.3 โครง CLI ด้วย argparse + logging + csv/json

## หมายเหตุจากการค้นคว้า

ทั้งสามตัวอย่างทำงานกับ log โดยตรง จึงเป็นฐานของ M5.2
