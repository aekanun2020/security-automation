# Python ขับเคลื่อน SOC: จาก log ดิบสู่รายงานอัตโนมัติ

การค้นคว้าทั้งเก้าหัวข้อของ Module 5 (Python for Cybersecurity) และ Module 6 (Security Automation Project) ชี้ไปที่ข้อสรุปเดียวกัน: งาน blue-team ด้วย Python ตั้งอยู่บน **"แกนกลางเล็ก ๆ ที่ทุกแหล่งเห็นพ้องกัน"** คือ standard library (`re`, `collections`, `csv`/`json`, `argparse`, `logging`, `subprocess`, `hashlib`/`hmac`, `ssl`) บวก `requests`/`pandas` และ **ชั้นมาตรฐานเปิดที่กำหนดรูปร่างข้อมูล** (RFC 5424 syslog, ECS/OCSF สำหรับ normalization, STIX 2.1/TAXII 2.1 สำหรับ threat intelligence, CACAO 2.0 สำหรับ playbook, Navigator layer v4.5 สำหรับ ATT&CK coverage) โดยที่ SDK ของผู้ผลิตแต่ละราย (elasticsearch-py ≈4.4k ดาว, vt-py ≈792, FalconPy ≈517, thehive4py ≈244, pySigma ≈604) เป็นเพียง "ปลายท่อ" ที่สลับได้ หลักฐานจากการสำรวจ SANS SOC Survey 2025 ว่า **69% ของ SOC ยังรายงาน metrics ด้วยมือ** และจาก Critical Start ว่า **เกือบครึ่งของ SOC มีอัตรา false positive ≥50%** คือเหตุผลที่ Module 6 ควรจบด้วยโปรเจ็กต์ที่ต่อท่อ webhook → OCSF normalization → dedupe/score → case/ticket → รายงาน PDF/Navigator layer ครบวงจร สิ่งที่เปลี่ยนไปในปี 2026 และกระทบหลักสูตรโดยตรงคือ SANS SEC573 เปลี่ยนชื่อเป็น "AI-Powered Security Automation: Building Tools with Python, LLMs, and MCP", Gartner จัด SOAR แบบ standalone เป็น "obsolete before plateau" ใน Hype Cycle 2024, `pyattck` ถูก archive (มี.ค. 2026), repo สาธารณะของ TheHive ถูก archive และ abuse.ch ย้ายการดาวน์โหลด URLhaus ไปอยู่หลัง Auth-Key ฟรี ซึ่งทั้งหมดหมายความว่าหลักสูตรต้องสอน *ความสามารถ* (parse, normalize, enrich, score, route, report) มากกว่าผูกกับผลิตภัณฑ์ใด รายงานนี้เรียบเรียงจากบันทึกการค้นคว้าที่รวบรวมเมื่อ 2026-11-01 (จำนวนดาว GitHub ทั้งหมดเป็นค่าโดยประมาณ ณ วันนั้น) จัดเป็นเก้าตอนตามลำดับหลักสูตร แต่ละตอนแบ่งเป็น แหล่งต้นฉบับ → งานเขียนและเครื่องมือยอดนิยมในชุมชน security → ตัวอย่างโค้ด → เอกสารอ้างอิงประจำหัวข้อ และปิดท้ายด้วยข้อจำกัดของการค้นคว้าและรายการอ้างอิงรวม

**หมายเหตุเรื่องโค้ด:** ตัวอย่างโค้ดทุกชิ้นคงไว้ตามบันทึกการค้นคว้า พร้อมบรรทัดระบุที่มา (attribution) ชิ้นที่ทำเครื่องหมาย *illustrative* คือโค้ดที่เขียนขึ้นจาก API ที่มีเอกสารอ้างอิงกำกับ ไม่ได้คัดลอกจากแหล่งใด และ **ยังไม่ได้รันทดสอบในรอบการค้นคว้านี้** ผู้สอนควร smoke-test ก่อนนำไปใช้ในชั้นเรียน

---

## Module 5 — Python for Cybersecurity

## 1. Python Fundamentals: สามแหล่งอิสระชี้ไปที่ชุด module เดียวกัน

### แหล่งต้นฉบับ

จุดเริ่มต้นของหัวข้อนี้คือเอกสาร standard library อย่างเป็นทางการ ซึ่งนิยามเครื่องมือที่นักวิเคราะห์ใช้ซ้ำทุกวัน เอกสาร `re` ระบุว่า module นี้ "provides regular expression matching operations similar to those found in Perl" และอธิบาย named groups `(?P<name>...)` ที่ทำให้ substring ที่จับได้เข้าถึงได้ผ่านชื่อ, `Match.groupdict()` ที่คืน dict ของ named subgroups, `re.finditer()` ที่คืน iterator ของ Match objects และคำแนะนำให้ใช้ raw string เพราะ "Raw string notation (r"text") keeps regular expressions sane" พร้อมหมายเหตุว่า `re.compile()` คุ้มค่าเมื่อใช้ pattern ซ้ำหลายครั้ง แม้ pattern ล่าสุดจะถูก cache อัตโนมัติอยู่แล้ว ([Python docs: re](https://docs.python.org/3/library/re.html)) เอกสาร `collections` นิยาม `Counter` ว่า "a dict subclass for counting hashable objects" โดย `most_common(n)` คืน n รายการที่พบบ่อยที่สุด และตัวอย่างในเอกสารเองคือการนับความถี่คำด้วย `re.findall(r'\w+', ...)` แล้ว `Counter(words).most_common(10)` ซึ่งเป็น pattern "top-N" เดียวกับที่ใช้วิเคราะห์ log ส่วน `deque(maxlen=n)` ถูกอธิบายว่า "Bounded length deques provide functionality similar to the tail filter in Unix. They are also useful for tracking transactions and other pools of data where only the most recent activity is of interest" ซึ่งเป็นรากฐานของ sliding-window burst detection และเอกสารยังมีสูตร `tail(filename, n=10)` ที่คืน `deque(f, n)` ด้วย `defaultdict` และ `namedtuple` อยู่ในหน้าเดียวกัน ([Python docs: collections](https://docs.python.org/3/library/collections.html))

เอกสาร `csv` ระบุว่า `DictReader` "maps the information in each row to a dict whose keys are given by the optional fieldnames parameter" และย้ำว่าควรเปิดไฟล์ด้วย `newline=''` เสมอ เพราะ module จัดการ universal newline เอง ([Python docs: csv](https://docs.python.org/3/library/csv.html)) เอกสาร `logging` ให้ระดับ DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50 และแนะนำ `logging.getLogger(__name__)` ([Python docs: logging](https://docs.python.org/3/library/logging.html)) เอกสาร `argparse` เรียกตัวเองว่า "the default recommended standard library module for implementing basic command line applications" และมีจุดสำคัญสำหรับหลักสูตรปี 2026 คือ **`argparse.FileType` ถูกทำเครื่องหมาย "Deprecated since version 3.14"** โดยแนะนำให้เปิดไฟล์หลัง parse ภายใน `with` แทน ([Python docs: argparse](https://docs.python.org/3/library/argparse.html)) ส่วน `json`, `pathlib`, `datetime` อยู่ในขอบเขตเดียวกัน ([json](https://docs.python.org/3/library/json.html), [pathlib](https://docs.python.org/3/library/pathlib.html), [datetime](https://docs.python.org/3/library/datetime.html)) แต่บันทึกการค้นคว้าไม่ได้ดึงถ้อยคำเฉพาะของสามหน้านี้มา

หนังสือและหลักสูตรต้นฉบับที่กำหนดมาตรฐานการสอน Python ด้านนี้มีสี่เล่ม/หลักสูตร **Automate the Boring Stuff with Python, 3rd Edition** ของ Al Sweigart (No Starch Press, 20 พฤษภาคม 2025, ISBN 9781718503403, 672 หน้า) มีบทที่ตรงกับ SOC โดยตรง ได้แก่ Ch 9 Text Pattern Matching with Regular Expressions, Ch 10 Reading and Writing Files, Ch 12 Designing and Deploying Command Line Programs, Ch 16 SQLite Databases, Ch 18 CSV, JSON, and XML Files และ Ch 19 Keeping Time, Scheduling Tasks, and Launching Programs โดยฉบับออนไลน์เปิดให้อ่านฟรีภายใต้ CC BY-NC-SA 3.0 ([automatetheboringstuff.com](https://automatetheboringstuff.com/); [Bookshop.org](https://bookshop.org/p/books/automate-the-boring-stuff-with-python-3rd-edition-al-sweigart/07df7b58a1c84fa2); [i-programmer](https://i-programmer.info/book-watch-archive/18069-automate-the-boring-stuff-with-python-3rd-ed-no-starch-press.html)) **SANS SEC573** โดย Mark Baggett (SANS Faculty Fellow และ CTO ของ Internet Storm Center) เป็นเกณฑ์มาตรฐานวิชาชีพ ปัจจุบันใช้ชื่อ "SEC573: AI-Powered Security Automation: Building Tools with Python, LLMs, and MCP" ความยาว 6 วัน หรือ 36 ชั่วโมงแบบ self-paced, **128 hands-on labs**, เตรียมสอบ GIAC GPYC และระบุชัดว่า "There is no aspect of programming or Python that must be understood before attending this course" โดยหัวข้อ section ครอบคลุม Essential Skills Workshop, Essentials Knowledge Workshop, Automated Defense with AI (รวม "Finding the Right Data with Regular Expressions" และ "Log Parsing and Data Analysis for AI Agents"), Automated Forensics with AI, Automated Offense with AI และ CTF ชื่อเดิม "Automating Information Security with Python" ยังพบในหน้า event ช่วง 2017–2021 ([SANS SEC573](https://www.sans.org/sec573); [SANS 2018 event page](https://www.sans.org/event/sans-2018/course/automating-information-security-with-python); [SANS.edu profile](https://www.sans.edu/profiles/mark-baggett)) **Python for Cybersecurity: Using Python for Cyber Offense and Defense** ของ Howard E. Poston III (Wiley, มี.ค. 2022, ISBN 978-1-119-85064-9, 240 หน้า) จัดบทตามกลุ่ม tactic ของ MITRE ATT&CK โดยแต่ละบทครอบคลุม technique และ "Python-based defenses against them" ([Wiley](https://www.wiley.com/en-us/Python+for+Cybersecurity%3A+Using+Python+for+Cyber+Offense+and+Defense-p-9781119850649); [O'Reilly c01](https://www.oreilly.com/library/view/python-for-cybersecurity/9781119850649/c01.xhtml)) และ **Cybersecurity Ops with bash** ของ Paul Troncone & Carl Albing (O'Reilly, เม.ย. 2019, 303 หน้า) เป็นจุดเปรียบเทียบ "ทำด้วย shell ก่อน แล้วค่อย Python" โดยส่วน defensive ครอบคลุม data collection/processing/analysis (counting occurrences, histograms, uniqueness, identifying anomalies ด้วย `sort`/`uniq`) และ real-time log monitoring ([O'Reilly](https://oreilly.com/library/view/cybersecurity-ops-with/9781492041306); [TOC](https://libexplorer.upnm.edu.my/home/Record/54874/TOC)) แหล่งต้นฉบับอีกชิ้นที่ให้ idiom สำคัญคือ **"Generator Tricks for Systems Programmers"** ของ David Beazley (PyCon'08, 13 มีนาคม 2008) ซึ่งมีไฟล์ `follow.py` ("following a log-file in real-time like tail -f in Unix") และ `bytesgen.py` (รวม bytes ใน Apache log ด้วย generator expression) ([dabeaz.com/generators2](https://www.dabeaz.com/generators2))

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

สิ่งที่น่าสนใจคือ **สามแหล่งอิสระ** คือ syllabus SEC573, รายชื่อบทของ Sweigart และเอกสาร stdlib บรรจบกันที่ชุด module เดียวกัน (`re`, file I/O, `csv`/`json`, `collections`, `argparse`, `logging`, `datetime`/`pathlib`) โดยมี `pandas` เป็นชั้น third-party หลักสำหรับข้อมูลตาราง และ `pySigma`, `python-evtx`/`evtx`, `drain3`, `zat`, `msticpy` เป็นส่วนเสริมเฉพาะทางที่ชุมชนอ้างถึงบ่อยที่สุด ชุมชนที่ยืนยันแนวทางนี้ได้แก่ webcast ของ Black Hills Information Security "Log File Frequency Analysis with Python" (Joff Thyer, พ.ค. 2017) ซึ่ง "discuss using Python regular expressions, and dictionaries to extract useful data for frequency analysis" ([BHIS](https://www.blackhillsinfosec.com/?p=5933)) และ ISC diary "Continuous Monitoring for Random Strings" (Mark Baggett, 7 ธ.ค. 2015) ที่แนะนำ `freq.py` (ให้คะแนนความถี่คู่ตัวอักษรเพื่อตรวจ string สุ่ม/DGA) และ `freq_server.py` (web API แบบ multithread สำหรับ log pipeline) ซึ่ง Justin Henderson นำไปต่อกับ Logstash/ELK ([ISC diary 20451](https://isc.sans.edu/diary/Continuous+Monitoring+for+Random+Strings/20451); [MarkBaggett/freq](https://github.com/MarkBaggett/MarkBaggett/tree/master/freq)) รายการ **awesome-threat-detection** ของ 0x4D31 (≈4.8k ดาว) เป็นดัชนีชุมชนที่ชี้ไปยัง SigmaHQ/sigma, zeek/zeek, SuperCowPowers/zat ("with Pandas, scikit-learn, Kafka and Spark"), SuperCowPowers/data_hacking, microsoft/msticpy ("a library for InfoSec investigation and hunting in Jupyter Notebooks"), matanolabs/matano และซีรีส์ "Threat Hunting with Jupyter Notebooks" ของ SpecterOps ([awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection)) บทความ Infosec Institute วาง Python scripting เป็นทักษะแกนของ cybersecurity และอ้าง learning path ของ Poston ([infosecinstitute.com](https://infosecinstitute.com/resources/professional-development/python-scripting-tool-cybersecurity/)) ข้อสังเกตเชิงหลักสูตรคือการเปลี่ยนชื่อ SEC573 ในปี 2025–26 ทำให้หน้า syllabus ปัจจุบันเน้น MCP/LLM agents ขณะที่พื้นฐาน regex/log parsing ยังอยู่ใน section 3 และราคาที่พบในหนึ่ง listing คือ **$8,780 USD** ทำให้ SEC573 เหมาะเป็น "จุดอ้างอิง" มากกว่าวิชาบังคับก่อน ([SANS SEC573](https://www.sans.org/sec573))

### ตัวอย่างโค้ด

**ตัวอย่าง 1.1 — parse Nginx/Apache combined log ด้วย regex + Counter (top IPs, top 404 paths, อัตรา 404 ต่อ IP)** — *illustrative, อิงจาก documented APIs*: รูปแบบ nginx `combined` ([nginx docs](https://nginx.org/en/docs/http/ngx_http_log_module.html)); named groups/`groupdict()` ([re docs](https://docs.python.org/3/library/re.html)); `Counter.most_common` ([collections docs](https://docs.python.org/3/library/collections.html))
```python
import re, sys
from collections import Counter, defaultdict

COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')

hits, errs, paths_404, uas = Counter(), Counter(), Counter(), Counter()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = COMBINED.match(line)
    if not m:
        continue
    r = m.groupdict()
    hits[r["ip"]] += 1
    uas[r["ua"]] += 1
    if r["status"] == "404":
        errs[r["ip"]] += 1
        paths_404[r["path"]] += 1

print("Top talkers:", hits.most_common(5))
print("Top 404 paths:", paths_404.most_common(5))
print("Rare user agents:", [ua for ua, n in uas.items() if n == 1][:10])
for ip, total in hits.most_common():
    rate = errs[ip] / total
    if total >= 50 and rate > 0.5:          # scanner heuristic: many requests, >50% 404
        print(f"SCANNER? {ip} {errs[ip]}/{total} = {rate:.0%}")
```

**ตัวอย่าง 1.2 — streaming log watcher แบบ `tail -f` ด้วย generator พร้อม alert แบบ live** — idiom `follow()` มาจาก David Beazley, PyCon'08 "Generator Tricks for Systems Programmers" (`follow.py`: "following a log-file in real-time like tail -f") ([dabeaz.com/generators2](https://www.dabeaz.com/generators2)); โค้ดด้านล่างเป็นการเขียนใหม่ของ idiom นั้น (ไฟล์ต้นฉบับดึงไม่สำเร็จ) บวกการตรวจ rate ด้วย `deque` ([collections docs](https://docs.python.org/3/library/collections.html))
```python
import os, re, sys, time
from collections import deque

def follow(path, poll=0.5):
    """Yield new lines as they are appended; survives truncation/logrotate by reopening."""
    f = open(path, encoding="utf-8", errors="replace"); f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line; continue
        time.sleep(poll)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_ino != inode or st.st_size < f.tell():      # rotated or truncated
            f.close(); f = open(path, encoding="utf-8", errors="replace")
            inode = os.fstat(f.fileno()).st_ino

FAILED = re.compile(r"Failed password for (?:invalid user )?\S+ from (\S+)")
window = deque()                                             # (time, ip) of recent failures
for line in follow(sys.argv[1]):
    m = FAILED.search(line)
    if not m:
        continue
    now = time.time(); window.append((now, m.group(1)))
    while window and now - window[0][0] > 60:
        window.popleft()
    n = sum(1 for _, ip in window if ip == m.group(1))
    if n >= 5:
        print(f"[ALERT] {m.group(1)}: {n} failed logins in 60s", flush=True)
```

**ตัวอย่าง 1.3 — โครง CLI สำหรับนักวิเคราะห์ด้วย argparse + logging + csv/json** — *illustrative, อิงจาก documented APIs*: พื้นฐาน argparse และคำแนะนำให้เปิดไฟล์หลัง parse (FileType deprecated ใน 3.14) ([argparse docs](https://docs.python.org/3/library/argparse.html)); `logging.getLogger(__name__)` และระดับ ([logging docs](https://docs.python.org/3/library/logging.html)); `csv.DictWriter` กับ `newline=''` ([csv docs](https://docs.python.org/3/library/csv.html)); `pathlib` ([pathlib docs](https://docs.python.org/3/library/pathlib.html))
```python
import argparse, csv, json, logging, sys
from collections import Counter
from pathlib import Path

log = logging.getLogger(__name__)

def main(argv=None):
    p = argparse.ArgumentParser(description="Count field values in JSON-lines logs")
    p.add_argument("paths", nargs="+", type=Path, help="one or more .jsonl files")
    p.add_argument("--field", default="source.ip", help="dotted field name (ECS style)")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--csv", type=Path, help="write results to CSV")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    counts = Counter()
    for path in a.paths:
        log.info("reading %s", path)
        with path.open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("bad JSON at %s:%d", path, n); continue
                for key in a.field.split("."):
                    ev = ev.get(key, {}) if isinstance(ev, dict) else {}
                if ev: counts[str(ev)] += 1
    for value, n in counts.most_common(a.top):
        print(f"{n:8d}  {value}")
    if a.csv:
        with a.csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["value", "count"]); w.writeheader()
            w.writerows({"value": v, "count": n} for v, n in counts.most_common())
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

ทั้งสามตัวอย่างใช้เฉพาะ standard library จึงเหมาะเป็น lab "fundamentals" ก่อนที่หัวข้อถัดไปจะเพิ่ม third-party package ทีละตัว ซึ่งสอดคล้องกับลำดับใน syllabus SEC573 และบทของ Sweigart

### เอกสารอ้างอิงประจำหัวข้อ

- Python docs: re — https://docs.python.org/3/library/re.html
- Python docs: collections — https://docs.python.org/3/library/collections.html
- Python docs: csv — https://docs.python.org/3/library/csv.html
- Python docs: logging — https://docs.python.org/3/library/logging.html
- Python docs: argparse — https://docs.python.org/3/library/argparse.html
- Python docs: json — https://docs.python.org/3/library/json.html
- Python docs: pathlib — https://docs.python.org/3/library/pathlib.html
- Python docs: datetime — https://docs.python.org/3/library/datetime.html
- Al Sweigart, Automate the Boring Stuff with Python (ฉบับออนไลน์ฟรี) — https://automatetheboringstuff.com/
- Bookshop.org listing, 3rd ed. — https://bookshop.org/p/books/automate-the-boring-stuff-with-python-3rd-edition-al-sweigart/07df7b58a1c84fa2
- i-programmer Book Watch, 3rd ed. — https://i-programmer.info/book-watch-archive/18069-automate-the-boring-stuff-with-python-3rd-ed-no-starch-press.html
- SANS SEC573 — https://www.sans.org/sec573
- SANS 2018 event page (ชื่อเดิม) — https://www.sans.org/event/sans-2018/course/automating-information-security-with-python
- SANS.edu profile: Mark Baggett — https://www.sans.edu/profiles/mark-baggett
- Wiley: Python for Cybersecurity (Poston) — https://www.wiley.com/en-us/Python+for+Cybersecurity%3A+Using+Python+for+Cyber+Offense+and+Defense-p-9781119850649
- O'Reilly: Python for Cybersecurity ch.1 — https://www.oreilly.com/library/view/python-for-cybersecurity/9781119850649/c01.xhtml
- O'Reilly: Cybersecurity Ops with bash — https://oreilly.com/library/view/cybersecurity-ops-with/9781492041306
- UPNM library TOC: Cybersecurity Ops with bash — https://libexplorer.upnm.edu.my/home/Record/54874/TOC
- David Beazley, Generator Tricks for Systems Programmers — https://www.dabeaz.com/generators2
- BHIS: Log File Frequency Analysis with Python — https://www.blackhillsinfosec.com/?p=5933
- ISC diary: Continuous Monitoring for Random Strings — https://isc.sans.edu/diary/Continuous+Monitoring+for+Random+Strings/20451
- MarkBaggett/freq — https://github.com/MarkBaggett/MarkBaggett/tree/master/freq
- 0x4D31/awesome-threat-detection — https://github.com/0x4D31/awesome-threat-detection
- Infosec Institute: Python scripting as a cybersecurity tool — https://infosecinstitute.com/resources/professional-development/python-scripting-tool-cybersecurity/

---

## 2. Log Analysis Automation: มาตรฐานรูปแบบ log กำหนด parser และสี่ idiom ตรวจจับที่ชุมชนใช้ซ้ำ

### แหล่งต้นฉบับ

นักวิเคราะห์ต้องอ่าน log ได้อย่างน้อยห้ารูปแบบและเข้าใจสอง schema สำหรับ normalization เอกสารต้นฉบับชิ้นแรกคือ **RFC 5424 "The Syslog Protocol"** (R. Gerhards, มี.ค. 2009, Proposed Standard ซึ่ง obsolete RFC 3164 ที่เป็นเพียง Informational บรรยาย BSD syslog ที่พบในทางปฏิบัติ) นิยาม `SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]` และ `HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID` โดย **PRI = Facility × 8 + Severity** (facility 0–23 เช่น 4 = security/auth, 16–23 = local0–7; severity 0 Emergency … 7 Debug), TIMESTAMP แบบ RFC 3339 ที่บังคับ "T", ความยาวสูงสุด APP-NAME ≤48, PROCID ≤128, MSGID ≤32 ตัวอักษร และตัวอย่าง `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8` ซึ่ง PRI 34 = facility 4×8 + severity 2 ([RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)) รูปแบบ web log อ้างอิงจาก mod_log_config ของ Apache ที่กำหนด Common Log Format `"%h %l %u %t \"%r\" %s %b"` และ combined format ที่เพิ่ม `%{Referer}i` และ `%{User-agent}i` ([mod_log_config](https://web.mit.edu/manual/mod/mod_log_config.html)) และจาก nginx ซึ่งกำหนด `log_format combined '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent";'` ไว้ล่วงหน้าเสมอและเป็นค่า default ของ `access_log` พร้อม `escape=json` (1.11.8+) และ `escape=none` (1.13.10+) ([nginx ngx_http_log_module](https://nginx.org/en/docs/http/ngx_http_log_module.html)) สำหรับ **Windows EVTX** เอกสาร de facto คือ "Windows XML Event Log (EVTX) format" ของ Joachim Metz ในโครงการ libyal/libevtx: ไฟล์เริ่มด้วย signature `ElfFile\x00`, header 4096 ไบต์, chunk ขนาด 65536 ไบต์ที่มี header 512 ไบต์และ signature `ElfChnk\x00`, event record เริ่มด้วย `\x2a\x2a\x00\x00` และ payload เป็น Binary XML โดย template ของ provider อยู่ใน WEVT_TEMPLATE resource ใช้ตั้งแต่ Windows Vista (format 3.1) และ Windows 10 2004+ (3.2) ([libevtx EVTX format doc](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc); [evtxexport man page](https://manpages.opensuse.org/Leap-16.0/libevtx-tools/evtxexport.1.en.html)) และสำหรับ **ArcSight CEF** header หลัง syslog prefix มีเจ็ดช่องแยกด้วย pipe (Version | Device Vendor | Device Product | Device Version | Device Event Class ID | Name | Severity) ตามด้วย Extension แบบ key=value โดย pipe ใน header ต้อง escape ด้วย `\`, spec 1.2 ใช้ค่า Version เป็น "1" และ Implementation Standard v27 (ม.ค. 2024) มากับ SmartConnectors 24.1 ([CEF Implementation Standard PDF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf); [What is CEF?](https://microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm); [Filebeat CEF fields](https://www.elastic.co/jp/guide/en/beats/filebeat/current/exported-fields-cef.html))

Schema ปลายทางสองตัวคือ **Elastic Common Schema (ECS)** ซึ่ง "defines a common set of fields to be used when storing event data in Elasticsearch" เวอร์ชันเอกสารปัจจุบัน 9.5.0 มี field set เช่น Base, Event, Source/Destination, Client/Server, Host, User, User agent, URL, HTTP, Network, Process, File, Log, Threat, Rule และตั้งแต่ 18 เมษายน 2023 Elastic "is contributing ECS to OTel and committing to joint development of a common schema" คือกำลังรวมเข้ากับ OpenTelemetry Semantic Conventions ([ECS reference](https://www.elastic.co/docs/reference/ecs); [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference); [Elastic blog](https://www.elastic.co/blog/ecs-elastic-common-schema-otel-opentelemetry-announcement)) และ **OCSF** ซึ่ง "is a framework for creating schemas and it also delivers a cybersecurity event schema built with the framework" ประกอบด้วย categories, event classes, data types และ attribute dictionary ชอบ integer enum มากกว่า string, "agnostic to storage format", ใช้ semantic versioning, Apache-2.0, repo ≈910 ดาว, เวอร์ชัน stable ล่าสุด **1.9.0** (1.10.0-dev กำลังพัฒนา) เปิดตัวที่ Black Hat USA ส.ค. 2022 โดย AWS และ Splunk กับผู้ก่อตั้งอีก 16 ราย และเข้าร่วม Linux Foundation เมื่อ 19 พ.ย. 2024 โดย Broadcom บริจาค Symantec ICD schema เป็นรากฐาน ([ocsf-schema](https://github.com/ocsf/ocsf-schema); [schema.ocsf.io](https://schema.ocsf.io); [Tanium press release](https://www.tanium.com/press-releases/cybersecurity-and-technology-industry-leaders-launch-open-source-project); [Linux Foundation](https://www.linuxfoundation.org/press/open-cybersecurity-schema-framework-ocsf-joins-the-linux-foundation-to-optimize-critical-security-data)) กรอบธรรมาภิบาลคือ **NIST SP 800-92 Rev. 1 "Cybersecurity Log Management Planning Guide"** (initial public draft 11 ต.ค. 2023, Karen Scarfone & Murugiah Souppaya) ซึ่งเป็น "playbook" การวางแผนแทนฉบับ 2006 และระบุชัดว่า "Implementing log management technology and making use of log data are out of scope" โดย ณ เวลาค้นคว้ายังไม่พบฉบับ final ([CSRC SP 800-92r1 ipd](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd); [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92r1.ipd.pdf); [SP 800-92 (2006)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf))

งานวิชาการต้นฉบับของ log analysis สมัยใหม่มาจากกลุ่ม LogPAI และ University of Utah ได้แก่ **Drain** ("Drain: An Online Log Parsing Approach with Fixed Depth Tree", He, Zhu, Zheng, Lyu, ICWS 2017) ซึ่งเป็นอัลกอริทึมเบื้องหลัง Drain3 ([PDF](http://jiemingzhu.github.io/pub/pjhe_icws2017.pdf)), **"Experience Report: System Log Analysis for Anomaly Detection"** (He, Zhu, He, Lyu, ISSRE 2016, ได้รับ "ISSRE Most Influential Paper") ซึ่งเป็นรากของ loglizer ([loglizer README](https://github.com/logpai/loglizer)), **DeepLog** ("Anomaly Detection and Diagnosis from System Logs through Deep Learning", Du, Li, Zheng, Srikumar, ACM CCS 2017, หน้า 1285–1298) ที่ใช้ LSTM บนลำดับ log key บวก model ค่าพารามิเตอร์ต่อ template และรองรับ online incremental update ([PDF](https://users.cs.utah.edu/~lifeifei/papers/deeplog.pdf); [dblp](https://dblp.dagstuhl.de/rec/conf/ccs/Du0ZS17.html); [pypi deeplog](https://pypi.org/project/deeplog/)), **Spell** (TKDE 2018) และ **LogAnomaly** (IJCAI 2019) ([awesome-log-analysis](https://github.com/logpai/awesome-log-analysis)) และ **Loghub** ("A Large Collection of System Log Datasets for AI-driven Log Analytics", Zhu, He, He, Liu, Lyu, ISSRE 2023) ([loghub README](https://github.com/logpai/loghub)) สำหรับ beaconing งานต้นฉบับฝั่งอุตสาหกรรมคือ **"Identifying beaconing malware using Elastic"** (Joshi, Veasey, Chamberlain, 1 มี.ค. 2023) ที่เลือก bucketing แทน inter-arrival time เพราะวิธี interval "proves to be too inefficient to use on large datasets because the events can't be processed across multiple shards" ใช้ coefficient of variation ของขนาด byte, relative variance เทียบกับ Poisson ("its RV is 1") สำหรับคาบสั้น และ autocorrelation สำหรับคาบยาว โดยตั้งใจให้ "narrow a threat hunt's search space" ไม่ใช่ detector เดี่ยว ([Elastic Security Labs](https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic)) ส่วนเอกสาร `pandas.read_csv` ให้รายละเอียดที่กระทบการ parse log โดยตรง: `sep` ที่ยาวกว่า 1 ตัวอักษรและไม่ใช่ `\s+` จะถูกตีความเป็น regex และบังคับใช้ Python engine ขณะที่ "The C and pyarrow engines are faster, while the python engine is currently more feature-complete" ([pandas read_csv](https://pandas.pydata.org/docs/reference/api/pandas.read_csv.html))

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

ชุด tool ที่ชุมชนใช้แบ่งตามรูปแบบ log ได้ชัด สำหรับ EVTX มี **python-evtx** ของ Willi Ballenthin ("Pure Python parser for Windows Event Log files (.evtx)", ≈786 ดาว, 170 forks, Apache-2.0, ไม่มี dependency, มาพร้อม `evtx_dump.py`/`evtx_dump_json.py`; โครงสร้างได้แรงบันดาลใจจาก Parse-Evtx ของ Andreas Schuster และ parser C++ ของ Joachim Metz) และ **evtx/pyevtx-rs** ของ Omer Ben-Amram (Rust crate "implemented using 100% safe rust", Python binding ≈55 ดาว, `PyEvtxParser(path).records_json()`, `skip_errors=True`, wheels abi3 สำหรับ Python 3.10+) ซึ่งเป็นตัวเลือกที่เร็วกว่าสำหรับ production ([python-evtx](https://github.com/williballenthin/python-evtx); [pyevtx-rs](https://github.com/omerbenamram/pyevtx-rs); [docs.rs evtx](https://docs.rs/crate/evtx/latest/source/README.md); [PyPI evtx](https://pypi.org/project/evtx)) สำหรับ forensic timeline มี **Plaso/log2timeline** ("Super timeline all the things", ≈2.2k ดาว, Apache-2.0) ที่มี **59 parser และ 187 plugin** รวม `winevtx`, `text/syslog`, `text/apache_access`, `text/winiis`, `systemd_journal`, `jsonl` และ preset เช่น `linux`, `macos`, `win_gen` แต่ไม่มี parser สำหรับ nginx ([Plaso](https://github.com/log2timeline/plaso); [Plaso parsers and plugins](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html)) สำหรับ detection-as-code มี **pySigma** (≈604 ดาว, Python 3.11+, backend และ pipeline แยกเป็น plugin, แทน `sigmac` เดิม; `convert_rule` แปลงทีละ rule และ `backend_processing_pipeline` ใช้กับทุก rule) และ **sigma-cli** (≈220 ดาว; `sigma plugin install splunk`; `sigma convert -t splunk -p sysmon sigma/rules/windows/process_creation`; `sigma convert -t esql -p ecs_windows --output-dir translated_rules/ rules/`) ([pySigma](https://github.com/SigmaHQ/pySigma); [pySigma docs](https://sigmahq-pysigma.readthedocs.io/en/latest/); [Backends doc](https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html); [sigma-cli](https://github.com/SigmaHQ/sigma-cli); [pySigma-plugin-directory](https://github.com/SigmaHQ/pySigma-plugin-directory))

ฝั่ง ML/template mining ชุด LogPAI ครองพื้นที่: **Drain3** (≈904 ดาว; `add_log_message()` สำหรับ train, `match()` สำหรับ inference; persistence ไป Kafka/Redis/file; masking regex→label ก่อนเข้า Drain; default `sim_th=0.4`, `depth=4`, `max_children=100`; ผลลัพธ์มี `change_type`, `cluster_id`, `cluster_size`, `template_mined`; `extract_parameters(template, log_line, exact_matching=True)`), **loglizer** (≈1.4k ดาว; LR/Decision Tree/SVM แบบ supervised และ LOF, One-Class SVM, Isolation Forest, PCA, Invariants Mining, Clustering แบบ unsupervised), **loghub** (≈2.9k ดาว; 19 dataset จาก 16 ระบบ รวม HDFS, BGL, Thunderbird, Windows, Linux, Apache, OpenSSH) และ **awesome-log-analysis** (≈810 ดาว) ([Drain3](https://github.com/logpai/Drain3); [loglizer](https://github.com/logpai/loglizer); [loghub](https://github.com/logpai/loghub); [awesome-log-analysis](https://github.com/logpai/awesome-log-analysis)) ฝั่ง network มี **ZAT – Zeek Analysis Tools** (≈456 ดาว, 604 commits; `LogToDataFrame().create_dataframe(log_path)`; Spark/Kafka notebook; converter Parquet/Dask/Polars) ([zat](https://github.com/SuperCowPowers/zat); [zeek_to_pandas.py](https://raw.githubusercontent.com/SuperCowPowers/zat/main/examples/zeek_to_pandas.py)) และ **msticpy** ของ Microsoft สำหรับ Jupyter ([microsoft/msticpy](https://github.com/microsoft/msticpy)) ส่วน beacon scoring อ้าง **RITA/AC-Hunter** ของ Active Countermeasures (เขียนด้วย Go แต่เป็นแนวทางอ้างอิง: คะแนน 0–1 และ interval-dispersion breakdown; "All communications are scrutinized for repeating intervals and even attempts to skew the results"; jitter ถูก "normalized out" ด้วยการดูบล็อกเวลารายชั่วโมง/วัน) ([AC blog](https://www.activecountermeasures.com/threat-hunting-simplifying-the-beacon-analysis-process/); [Detecting Beacons With Jitter](https://www.activecountermeasures.com/detecting-beacons-with-jitter/); [BHIS: Zeek and RITA](https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/)) โดย arXiv 2026 ฉบับหนึ่งรายงานว่า RITA ให้คะแนน 0.0 ทั้ง 11 profile ที่ทดสอบ เพราะ "RITA requires a minimum connection count per pair to compute stable quartiles" ([arXiv 2609.19091](https://arxiv.org/pdf/2609.19091))

**สี่ idiom การตรวจจับ** ที่โค้ดชุมชนบรรจบกันคือ (1) นับ failed login ต่อ IP ในหน้าต่างเวลา ค่า default ราว **5 ครั้งใน 60–300 วินาที** เช่น Python Security Log Analyzer (5+/60 s), soc-log-analyzer (threshold 5 / window 300 s; severity MEDIUM ≥5, HIGH ≥15, CRITICAL ≥20; CLI `python analyzer.py --log /var/log/auth.log --threshold 3 --window 60`; มี `--year` เพราะ auth.log ไม่มีปี) และ auth-log-analyzer (≥5 medium, 15 high) ซึ่ง **ทั้งหมดเป็น repo งานอดิเรกที่มีดาวน้อย** จึงเป็นธรรมเนียม ไม่ใช่มาตรฐาน ([Neptunes22](https://github.com/Neptunes22/Python-Security-Log-Analyzer); [ihorpjp/soc-log-analyzer](https://github.com/ihorpjp/soc-log-analyzer); [Ronoh12](https://github.com/Ronoh12/auth-log-analyzer); [cipherssecurity](https://cipherssecurity.com/?p=17370)) (2) อัตรา 404 ต่อ IP และ top-N URL/user agent ด้วย `value_counts()` หรือ `Counter.most_common()` ตามบทเรียน pandas กับ Nginx log ([dev.to](https://dev.to/ksndeveloper/parsing-nginx-logs-using-python-1m6k); [gist](https://gist.github.com/ksn-developer/4072a9e092bccf68559c21f1c5ac2de2); [grokcode notebook](https://nbviewer.jupyter.org/github/grokcode/ipython-notebooks/tree/master/nginx-log-analysis.ipynb); [Koldunov Apache notebook](https://nbviewer.jupyter.org/github/koldunovn/nk_public_notebooks/tree/master/Apache_log.ipynb); [eddmann.com](https://eddmann.com/posts/processing-apache-and-nginx-access-logs/)) (3) beaconing ด้วยความสม่ำเสมอของ inter-arrival time (coefficient of variation ต่ำ; skill ชุมชนหนึ่งใช้ CV < 0.3 และต้องมี >10 intervals แต่ยืนยันจากแหล่งต้นทางไม่ได้) หรือ bucketed counts แบบ Elastic เมื่อข้อมูลใหญ่ ([community mirror](https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/detecting-beaconing-patterns-with-zeek/)) และ (4) คะแนนความหายาก/ความสุ่ม เช่น freq.py ที่ให้ "i9p5z3ac.q2mlktc.top" เป็น random และ "apple.com" เป็น normal ([ISC diary](https://isc.sans.edu/diary/Continuous+Monitoring+for+Random+Strings/20451)) นอกจากนี้ ISC guest diary ปี 2025 รายงาน script Python ที่ parse DShield honeypot JSON (top/bottom IP, suspicious file requests, credential attempts) ซึ่ง log ขนาดใหญ่ใช้เวลา ~13 นาที ([ISC diary 32038](https://isc.sans.edu/diary/Automated+Tools+to+Assist+with+DShield+Honeypot+Investigations+Guest+Diary/32038)) ข้อสรุปสำหรับการสอน: "Counter อย่างเดียว" จะ over-alert กับ IP ที่ส่งเสียงดังต่อเนื่อง หน้าต่างเวลาแบบ deque คือการพัฒนาที่สอนได้ และต้องมี regex ที่สองสำหรับบรรทัด "Invalid user"

### ตัวอย่างโค้ด

**ตัวอย่าง 2.1 — ตรวจ burst ของ failed login ใน Linux auth.log (sliding window ด้วย deque)** — *illustrative, อิงจาก documented APIs*: `deque` ("tracking ... only the most recent activity") ([collections docs](https://docs.python.org/3/library/collections.html)); รูปบรรทัด `Mar  1 02:11:01 server sshd[3821]: Failed password...` และ default 5-in-300s ([soc-log-analyzer](https://github.com/ihorpjp/soc-log-analyzer)); รุ่น 5-in-60s ([Neptunes22](https://github.com/Neptunes22/Python-Security-Log-Analyzer))
```python
import re, sys
from collections import defaultdict, deque
from datetime import datetime

FAILED = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: '
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)')
THRESHOLD, WINDOW = 5, 60          # 5 failures within 60 seconds
YEAR = datetime.now().year         # auth.log timestamps omit the year

recent = defaultdict(deque)        # ip -> timestamps of recent failures
alerted = set()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = FAILED.match(line)
    if not m:
        continue
    ts = datetime.strptime(f"{YEAR} {m['ts']}", "%Y %b %d %H:%M:%S")
    q = recent[m["ip"]]
    q.append(ts)
    while q and (ts - q[0]).total_seconds() > WINDOW:
        q.popleft()                # drop failures older than the window
    if len(q) >= THRESHOLD and m["ip"] not in alerted:
        alerted.add(m["ip"])
        print(f"BRUTE FORCE {m['ip']}: {len(q)} failures in {WINDOW}s, last user={m['user']}")
```

**ตัวอย่าง 2.2 — อ่าน Windows EVTX ด้วย python-evtx และดึง Event ID 4625 (failed logon)** — อิงจาก README ของ python-evtx (`evtx_dump.py`: วน `log.records()` แล้วพิมพ์ `record.xml()`) ([python-evtx](https://github.com/williballenthin/python-evtx)); การดึง field จาก XML เป็น illustrative
```python
import sys, re
from collections import Counter
import Evtx.Evtx as evtx          # pip install python-evtx

EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
IP  = re.compile(r'<Data Name="IpAddress">([^<]+)</Data>')
USR = re.compile(r'<Data Name="TargetUserName">([^<]+)</Data>')

by_ip, by_user = Counter(), Counter()
with evtx.Evtx(sys.argv[1]) as log:          # e.g. Security.evtx
    for record in log.records():
        xml = record.xml()
        m = EID.search(xml)
        if not m or m.group(1) != "4625":
            continue
        ip = IP.search(xml); user = USR.search(xml)
        by_ip[ip.group(1) if ip else "-"] += 1
        by_user[user.group(1) if user else "-"] += 1
print("4625 by source IP:", by_ip.most_common(10))
print("4625 by target user:", by_user.most_common(10))
```
ทางเลือกที่เร็วกว่า (Rust-backed) อิงจาก README ของ pyevtx-rs (`PyEvtxParser(path)`, `records_json()`, `skip_errors=True`) ([pyevtx-rs](https://github.com/omerbenamram/pyevtx-rs)):
```python
import json, sys
from collections import Counter
from evtx.parser import PyEvtxParser      # pip install evtx

parser = PyEvtxParser(sys.argv[1], skip_errors=True)
eids = Counter()
for rec in parser.records_json():
    ev = json.loads(rec["data"])["Event"]
    eids[str(ev["System"]["EventID"])] += 1   # EventID may be int or {"#text": ...}
print(eids.most_common(10))
```
(หมายเหตุ: EventID อาจ serialize เป็น dict ที่มี `#text` เมื่อมี attribute; ใน production ควรรองรับทั้งสองแบบ)

**ตัวอย่าง 2.3 — โหลด syslog (RFC 5424 และแบบดั้งเดิม) เข้า pandas แล้ว resample** — *illustrative, อิงจาก documented APIs*: layout ของ HEADER และ PRI = facility×8+severity ([RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)); `pandas.read_csv`/`to_datetime` ([pandas docs](https://pandas.pydata.org/docs/reference/api/pandas.read_csv.html))
```python
import re, sys
import pandas as pd

RFC5424 = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<ver>\d) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) '
    r'(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|\[.*?\]) ?(?P<msg>.*)$')
BSD = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) '
    r'(?P<app>[^\[:]+)(?:\[(?P<procid>\d+)\])?: (?P<msg>.*)$')

rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = RFC5424.match(line) or BSD.match(line)
    if m:
        rows.append(m.groupdict())
df = pd.DataFrame(rows)
if "pri" in df:
    pri = pd.to_numeric(df["pri"], errors="coerce")
    df["facility"], df["severity"] = pri // 8, pri % 8      # RFC 5424 §6.2.1
df["ts"] = pd.to_datetime(df["ts"], errors="coerce", utc=True, format="mixed")
df = df.dropna(subset=["ts"]).set_index("ts").sort_index()
print(df["app"].value_counts().head(10))
print(df[df.get("severity", 7) <= 3].resample("5min").size())   # error+ per 5 minutes
```

**ตัวอย่าง 2.4 — template mining ด้วย Drain3 พร้อม masking IP/ตัวเลข** — อิงจาก API ใน README ของ Drain3 (`TemplateMinerConfig`, `TemplateMiner`, `add_log_message`, key ผลลัพธ์ `change_type`/`cluster_id`/`template_mined`, `extract_parameters(template, line, exact_matching=True)`, ส่วน masking) ([Drain3](https://github.com/logpai/Drain3)); รายละเอียด config file เป็น illustrative
```python
import sys
from collections import Counter
from drain3 import TemplateMiner                      # pip install drain3
from drain3.template_miner_config import TemplateMinerConfig

cfg = TemplateMinerConfig()
cfg.drain_sim_th, cfg.drain_depth = 0.4, 4            # README defaults
cfg.masking_instructions = []                        # or cfg.load("drain3.ini") with [MASKING]
miner = TemplateMiner(config=cfg)

sizes = Counter()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    msg = line.split(": ", 1)[-1].rstrip()            # strip syslog header, keep message
    res = miner.add_log_message(msg)
    sizes[res["cluster_id"]] = res["cluster_size"]
    if res["change_type"] == "cluster_created":
        print(f"NEW TEMPLATE #{res['cluster_id']}: {res['template_mined']}")

print("\nRarest templates (candidate anomalies):")
for cid, n in sorted(sizes.items(), key=lambda kv: kv[1])[:5]:
    tmpl = next(c for c in miner.drain.clusters if c.cluster_id == cid).get_template()
    print(n, tmpl)
```

**ตัวอย่าง 2.5 — แปลง Sigma rule ด้วย pySigma (Splunk backend, Sysmon pipeline)** — *illustrative, อิงจาก documented APIs*: pySigma ติดตั้งด้วย `pip install pysigma` และ backend เป็น plugin แยก ([pySigma](https://github.com/SigmaHQ/pySigma)); `convert_rule` และ `backend_processing_pipeline` ([pySigma Backends doc](https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html)); คำสั่ง CLI เทียบเท่าคัดจาก README ของ [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
```python
# pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.sysmon import sysmon_pipeline

RULE = """
title: Suspicious whoami execution
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\whoami.exe'
  condition: sel
level: low
"""
rules = SigmaCollection.from_yaml(RULE)
backend = SplunkBackend(processing_pipeline=sysmon_pipeline())
for query in backend.convert(rules):
    print(query)
```
CLI เทียบเท่า (ตาม README): `sigma plugin install splunk`; `sigma convert -t splunk -p sysmon sigma/rules/windows/process_creation`; `sigma convert -t esql -p ecs_windows --output-dir translated_rules/ rules/` ([sigma-cli](https://github.com/SigmaHQ/sigma-cli))

**ตัวอย่าง 2.6 — Zeek conn.log → pandas ด้วย ZAT แล้วหา beacon candidates จากความสม่ำเสมอของ inter-arrival** — การเรียก ZAT มาจากตัวอย่าง `zeek_to_pandas.py` ของโครงการ (`LogToDataFrame().create_dataframe(log_path)`) ([zat example](https://raw.githubusercontent.com/SuperCowPowers/zat/main/examples/zeek_to_pandas.py)); heuristic CV-of-intervals สะท้อนแนวคิด "repeating intervals"/dispersion ของ RITA ([Active Countermeasures](https://www.activecountermeasures.com/threat-hunting-simplifying-the-beacon-analysis-process/)) และ skill ชุมชน ZAT (>10 intervals, CV ต่ำ) ([community mirror](https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/detecting-beaconing-patterns-with-zeek/)); threshold เป็น illustrative
```python
import sys
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame      # pip install zat

df = LogToDataFrame().create_dataframe(sys.argv[1])  # Zeek conn.log (TSV) -> DataFrame, ts index
df = df.reset_index().sort_values("ts")

rows = []
for (src, dst, port), g in df.groupby(["id.orig_h", "id.resp_h", "id.resp_p"]):
    if len(g) < 12:                                  # need enough connections for stats
        continue
    gaps = g["ts"].diff().dt.total_seconds().dropna()
    mean, std = gaps.mean(), gaps.std()
    cv = std / mean if mean else float("inf")        # coefficient of variation of intervals
    rows.append((src, dst, port, len(g), round(mean, 1), round(cv, 3),
                 round(g["orig_bytes"].std() / max(g["orig_bytes"].mean(), 1), 3)))

cols = ["src", "dst", "port", "conns", "mean_gap_s", "gap_cv", "bytes_cv"]
res = pd.DataFrame(rows, columns=cols)
beacons = res[(res.gap_cv < 0.3) & (res.bytes_cv < 0.5)].sort_values("gap_cv")
print(beacons.head(20).to_string(index=False))
```
ข้อควรระวังจาก Elastic: การตรวจแบบ interval "proves to be too inefficient to use on large datasets"; ที่ scale ให้ใช้ bucketed counts กับ relative variance (Poisson RV = 1) และ autocorrelation ([Elastic Security Labs](https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic))

**ตัวอย่าง 2.7 — access log → pandas: อัตรา 404 ต่อ IP, ปริมาณรายชั่วโมง, user agent หายาก** — *illustrative, อิงจาก documented APIs*: `sep` แบบ regex บังคับ Python engine และไม่สนใจ quoting ([pandas read_csv](https://pandas.pydata.org/docs/reference/api/pandas.read_csv.html)) จึง parse ด้วย `re` ก่อน (pattern จากตัวอย่าง 1.1) แล้วสร้าง DataFrame; การใช้ `value_counts()` เลียน notebook nginx ([grokcode notebook](https://nbviewer.jupyter.org/github/grokcode/ipython-notebooks/tree/master/nginx-log-analysis.ipynb), [dev.to tutorial](https://dev.to/ksndeveloper/parsing-nginx-logs-using-python-1m6k))
```python
import re, sys
import pandas as pd

PAT = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
                 r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')
recs = [m.groupdict() for m in map(PAT.match, open(sys.argv[1], errors="replace")) if m]
df = pd.DataFrame(recs)
df["time"] = pd.to_datetime(df["time"], format="%d/%b/%Y:%H:%M:%S %z")
df["status"] = df["status"].astype(int)

per_ip = df.groupby("ip").agg(total=("status", "size"),
                              n404=("status", lambda s: (s == 404).sum()),
                              uniq_paths=("path", "nunique"))
per_ip["rate404"] = per_ip.n404 / per_ip.total
print(per_ip[(per_ip.total >= 50) & (per_ip.rate404 > 0.5)].sort_values("rate404", ascending=False))

print(df.set_index("time").resample("1h").size().tail(24))       # hourly request volume
ua_counts = df["ua"].value_counts()
print(ua_counts[ua_counts == 1].head(15))                       # long-tail / rare user agents
print(df[df.status >= 500]["path"].value_counts().head(10))     # error hot spots
```

ทุก snippet การตรวจจับเปิดเผย threshold เป็นค่าคงที่ที่มีชื่อ เพราะไม่มี threshold ใด (5/60 s, 404 rate > 50%, CV < 0.3) ที่ถูกกำหนดเป็นมาตรฐานโดยแหล่งที่อ้าง ลำดับการสอนที่สมเหตุสมผลคือ raw text (syslog, combined log) → binary (EVTX) → vendor interchange (CEF) → normalization target (ECS/OCSF) เพราะ Sigma pipeline (เช่น `-p ecs_windows`) และ SIEM ต่าง ๆ อิงชื่อ field เหล่านี้

### เอกสารอ้างอิงประจำหัวข้อ

- RFC 5424 The Syslog Protocol — https://datatracker.ietf.org/doc/html/rfc5424
- Apache mod_log_config (MIT mirror) — https://web.mit.edu/manual/mod/mod_log_config.html
- nginx ngx_http_log_module — https://nginx.org/en/docs/http/ngx_http_log_module.html
- libevtx: Windows XML Event Log (EVTX) format — https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
- evtxexport man page — https://manpages.opensuse.org/Leap-16.0/libevtx-tools/evtxexport.1.en.html
- CEF Implementation Standard PDF (SmartConnectors 24.1) — https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
- What is CEF? — https://microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm
- Filebeat CEF exported fields — https://www.elastic.co/jp/guide/en/beats/filebeat/current/exported-fields-cef.html
- ECS reference — https://www.elastic.co/docs/reference/ecs
- ECS field reference — https://www.elastic.co/docs/reference/ecs/ecs-field-reference
- Elastic blog: ECS → OTel — https://www.elastic.co/blog/ecs-elastic-common-schema-otel-opentelemetry-announcement
- ocsf/ocsf-schema — https://github.com/ocsf/ocsf-schema
- schema.ocsf.io — https://schema.ocsf.io
- Tanium press release (OCSF launch) — https://www.tanium.com/press-releases/cybersecurity-and-technology-industry-leaders-launch-open-source-project
- Linux Foundation press release (OCSF) — https://www.linuxfoundation.org/press/open-cybersecurity-schema-framework-ocsf-joins-the-linux-foundation-to-optimize-critical-security-data
- NIST SP 800-92 Rev.1 ipd — https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
- NIST SP 800-92r1 ipd PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92r1.ipd.pdf
- NIST Log management project — https://csrc.nist.gov/projects/log-management
- NIST SP 800-92 (2006) — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf
- Drain (ICWS 2017) PDF — http://jiemingzhu.github.io/pub/pjhe_icws2017.pdf
- DeepLog (CCS 2017) PDF — https://users.cs.utah.edu/~lifeifei/papers/deeplog.pdf
- DeepLog dblp — https://dblp.dagstuhl.de/rec/conf/ccs/Du0ZS17.html
- PyPI deeplog — https://pypi.org/project/deeplog/
- Elastic Security Labs: Identifying beaconing malware — https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic
- arXiv 2609.19091 — https://arxiv.org/pdf/2609.19091
- pandas read_csv — https://pandas.pydata.org/docs/reference/api/pandas.read_csv.html
- williballenthin/python-evtx — https://github.com/williballenthin/python-evtx
- Alpine py3-evtx — https://pkgs.alpinelinux.org/package/edge/community/x86/py3-evtx
- Debian python3-evtx — https://pkgdex.org/debian/sid/x86_64/main/python3-evtx_8.1.0-1.deb.html
- omerbenamram/pyevtx-rs — https://github.com/omerbenamram/pyevtx-rs
- docs.rs evtx README — https://docs.rs/crate/evtx/latest/source/README.md
- PyPI evtx — https://pypi.org/project/evtx
- log2timeline/plaso — https://github.com/log2timeline/plaso
- Plaso parsers and plugins — https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html
- SigmaHQ/pySigma — https://github.com/SigmaHQ/pySigma
- pySigma docs — https://sigmahq-pysigma.readthedocs.io/en/latest/
- pySigma Backends doc — https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
- pySigma-plugin-directory — https://github.com/SigmaHQ/pySigma-plugin-directory
- SigmaHQ/sigma-cli — https://github.com/SigmaHQ/sigma-cli
- logpai/Drain3 — https://github.com/logpai/Drain3
- logpai/loglizer — https://github.com/logpai/loglizer
- logpai/loghub — https://github.com/logpai/loghub
- logpai/awesome-log-analysis — https://github.com/logpai/awesome-log-analysis
- SuperCowPowers/zat — https://github.com/SuperCowPowers/zat
- zat zeek_to_pandas.py — https://raw.githubusercontent.com/SuperCowPowers/zat/main/examples/zeek_to_pandas.py
- microsoft/msticpy — https://github.com/microsoft/msticpy
- Active Countermeasures: Simplifying the beacon analysis process — https://www.activecountermeasures.com/threat-hunting-simplifying-the-beacon-analysis-process/
- Active Countermeasures: Detecting Beacons With Jitter — https://www.activecountermeasures.com/detecting-beacons-with-jitter/
- BHIS: Detecting Malware Beacons With Zeek and RITA — https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/
- Neptunes22/Python-Security-Log-Analyzer — https://github.com/Neptunes22/Python-Security-Log-Analyzer
- ihorpjp/soc-log-analyzer — https://github.com/ihorpjp/soc-log-analyzer
- Ronoh12/auth-log-analyzer — https://github.com/Ronoh12/auth-log-analyzer
- cipherssecurity tutorial — https://cipherssecurity.com/?p=17370
- dev.to: Parsing Nginx logs using Python — https://dev.to/ksndeveloper/parsing-nginx-logs-using-python-1m6k
- gist ksn-developer — https://gist.github.com/ksn-developer/4072a9e092bccf68559c21f1c5ac2de2
- nbviewer grokcode nginx-log-analysis — https://nbviewer.jupyter.org/github/grokcode/ipython-notebooks/tree/master/nginx-log-analysis.ipynb
- nbviewer koldunovn Apache_log — https://nbviewer.jupyter.org/github/koldunovn/nk_public_notebooks/tree/master/Apache_log.ipynb
- eddmann.com: Processing Apache and Nginx access logs — https://eddmann.com/posts/processing-apache-and-nginx-access-logs/
- Community mirror: detecting beaconing patterns with Zeek — https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/detecting-beaconing-patterns-with-zeek/
- ISC diary 32038: DShield honeypot tooling — https://isc.sans.edu/diary/Automated+Tools+to+Assist+with+DShield+Honeypot+Investigations+Guest+Diary/32038

---

## 3. Security Automation Scripts: เอกสาร stdlib คือแนวปฏิบัติด้านความปลอดภัยของ script เอง

### แหล่งต้นฉบับ

แหล่งต้นฉบับของหัวข้อนี้แทบทั้งหมดเป็นเอกสาร Python อย่างเป็นทางการที่บอกตรง ๆ ว่าอะไรปลอดภัยและอะไรไม่ปลอดภัย เอกสาร `subprocess` ระบุใน "Security Considerations" ว่า "Unlike some other popen functions, this library will not implicitly choose to call a system shell… If the shell is invoked explicitly, via shell=True, it is the application's responsibility to ensure that all whitespace and metacharacters are quoted appropriately to avoid shell injection vulnerabilities… it is possible to use shlex.quote()" และแนะนำ `run()` สำหรับทุกกรณีที่รองรับ โดย `check=True` จะ raise `CalledProcessError` เมื่อ exit code ไม่เป็นศูนย์, `timeout` จะ kill child แล้ว raise `TimeoutExpired`, และ `capture_output=True` + `text=True` เก็บ stdout/stderr เป็น str พร้อม caveat บน Windows ว่า batch file อาจถูกเปิดใน shell ไม่ว่าจะส่ง argument อย่างไร (gh-114539) ([subprocess – Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations); [subprocess.run](https://docs.python.org/3/library/subprocess.html#subprocess.run)) สำหรับ integrity check เอกสาร `hashlib` ให้ `hashlib.file_digest(fileobj, digest, /)` ("Added in version 3.11") ที่ต้องเปิดไฟล์แบบ binary และ "may bypass Python's I/O and use the file descriptor from fileno() directly" และทุก constructor รับ keyword `usedforsecurity=True` ตั้งแต่ 3.9 ([hashlib](https://docs.python.org/3/library/hashlib.html#hashlib.file_digest)) ส่วน `hmac.compare_digest(a, b)` "uses an approach designed to prevent timing analysis by avoiding content-based short circuiting behaviour" และเอกสารแนะนำให้ใช้แทน `==` "to reduce the vulnerability to timing attacks" โดย `hmac.new()` บังคับ `digestmod` ตั้งแต่ 3.8 ([hmac](https://docs.python.org/3/library/hmac.html)) สำหรับ TLS เอกสาร `ssl` ระบุว่า `ssl.create_default_context()` ให้ "a higher security level than when calling the SSLContext constructor directly" ตั้ง `CERT_REQUIRED` และโหลด CA default ขณะที่ `SSLSocket.getpeercert()` คืน dict ที่มี `notBefore`/`notAfter` ในรูป `'Nov 22 08:15:19 2013 GMT'` ("If the certificate was not validated, the dict is empty") และ `ssl.cert_time_to_seconds()` parse รูปแบบนั้นซึ่ง "must use GMT (RFC 5280)" ([ssl](https://docs.python.org/3/library/ssl.html#ssl.create_default_context))

ด้าน HTTP เอกสาร Requests เตือนว่า "By default, requests do not time out unless a timeout value is set explicitly. Without a timeout, your code may hang for minutes or more" รองรับ tuple `timeout=(3.05, 27)` แยก connect/read, ตรวจ TLS โดย default และ `verify=False` "will make your application vulnerable to man-in-the-middle (MitM) attacks" และยังเตือนว่า "Storing sensitive username and password information in an environment variable or a version-controlled file is a security risk and is highly discouraged" (ในบริบท proxy credentials) ([Requests Advanced Usage – Timeouts](https://requests.readthedocs.io/en/latest/user/advanced/#timeouts); [SSL Cert Verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification); [Proxies](https://requests.readthedocs.io/en/latest/user/advanced/#proxies)) ขณะที่ HTTPX ตรงข้าม: "The default behavior is to raise a TimeoutException after 5 seconds of network inactivity" และ "careful to enforce timeouts everywhere by default" ([HTTPX Timeouts](https://www.python-httpx.org/advanced/timeouts/)) ด้านการตั้งค่า/secret เอกสาร pydantic-settings อธิบาย `class Settings(BaseSettings)` ที่อ่าน field จาก environment variable, `env_prefix`, ชื่อ env ไม่สนตัวพิมพ์โดย default, รองรับ `env_file='.env'` ซึ่ง "environment variables will always take priority over values loaded from a dotenv file", `secrets_dir='/var/run'` สำหรับ secret-per-file แบบ Docker และ `SecretStr` สำหรับ field อ่อนไหว ([Pydantic Settings docs](https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/)) ด้าน scheduling เอกสาร `schedule` นิยามตัวเองว่า "Python job scheduling for humans… In-process scheduler for periodic jobs. No extra processes needed!" และระบุชัดว่า **ไม่** รองรับ job persistence, exact timing, concurrent execution หรือ localization ([schedule docs](https://schedule.readthedocs.io/en/stable/)) ส่วน APScheduler 3.x มี `BlockingScheduler`/`BackgroundScheduler`, trigger `date`/`interval`/`cron`, job store `MemoryJobStore` (default) / `SQLAlchemyJobStore` (แนะนำ PostgreSQL) / `MongoDBJobStore` และ `misfire_grace_time`/`coalesce` สำหรับ run ที่ล่าช้าหรือซ้ำ ([APScheduler 3.x User Guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html)) สำหรับ baseline ของการตั้งค่า **CIS Benchmarks** ให้ "prescriptive configuration recommendations for more than 25+ vendor product families" จาก "consensus-based effort of cybersecurity experts globally" พร้อม CIS-CAT Pro Assessor และ Build Kits ([CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)) ส่วน scanner wrapper ต้นฉบับคือ **python-nmap** (PyPI, GPL-3.0, Alexandre Norman, **v0.7.1 ปล่อย 26 ต.ค. 2021** และไม่มี release ใหม่ตั้งแต่นั้น; ต้องมี nmap binary) และ **python-libnmap** (≈493 ดาว, Apache-2.0; module process/parse (XML)/report/diff/plugins) ([python-nmap on PyPI](https://pypi.org/project/python-nmap/); [python-libnmap](https://github.com/savon-noir/python-libnmap); [libnmap parser docs](https://libnmap.readthedocs.io/en/latest/parser.html))

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

บทความผู้ปฏิบัติที่ตรงหัวข้อที่สุดในปี 2026 คือ TechTarget "Boost SOC efficiency with Python security automation" (Damon Garn, 17 มี.ค. 2026) ซึ่งระบุ use case ของ Python ใน SOC ว่า automate host isolation, "configure routers and firewalls to block IPs or domains", สร้าง Jira ticket และ scheduled threat hunt บน SIEM/EDR แนะนำ library `requests`, `pandas`, `re`, `scapy`, `paramiko`, `python-nmap`, `elasticsearch`/`opensearch-py` และย้ำว่า "Be sure to run these scripts in test environments before deploying them to production systems" และ "Plan to standardize the installation, including version control" ([TechTarget](https://www.techtarget.com/searchsecurity/tip/Boost-SOC-efficiency-with-Python-security-automation)) หนังสือที่ชุมชนอ้างถึงมี **Black Hat Python, 2nd Edition** (Justin Seitz & Tim Arnold, No Starch, เม.ย. 2021, 216 หน้า, ISBN 9781718501126; "All of the code in this edition has been updated to Python 3.x"; เนื้อหา offensive: sniffer, credential theft, fuzzer, trojan, Volatility) ([No Starch Press](https://nostarch.com/black-hat-python2E)) ซึ่งเป็นชื่อที่รู้จักมากที่สุดแต่เป็นฝั่ง offense, **Python for Cybersecurity** ของ Poston (ATT&CK-structured, มี defense) และ **Security Automation with Python** ของ Corey Charles Sr. (Packt, ก.พ. 2025, ISBN 9781805125105) ที่เน้น "vulnerability management and scaling security workflows" การเชื่อม Python กับ Nessus และกรอบ NIST 800-53/FedRAMP ([Packt](https://www.packtpub.com/product/security-automation-with-python/9781805125105); [O'Reilly](https://www.oreilly.com/library/view/-/9781805125105/)) โดยสำหรับ module blue-team Poston และ Charles ใกล้เคียงกว่า Black Hat Python รายการ **awesome-cybersecurity-blueteam** ของ fabacab (≈5.6k ดาว, CC BY 4.0) มีหมวด Automation and Convention, SOAR, DevSecOps, Threat intelligence, Incident Response tools, Threat hunting และระบุ Python tool เช่น MultiScanner, DShell, python-dshield, python-sandboxapi, python-stix2, Forager, GRR Rapid Response ([awesome-cybersecurity-blueteam](https://github.com/fabacab/awesome-cybersecurity-blueteam)) และรายชื่ออ่านของ defender มักวาง *Blue Team Field Manual* (Alan J White) และ *PTFM* (Tim Bryant) ซึ่งไม่ใช่ Python เคียงข้างกัน ([SimeonOnSecurity](https://simeononsecurity.com/articles/essential-books-cybersecurity-it-professionals/)) ข้อสังเกตเชิงปฏิบัติ: `schedule` เพียงพอสำหรับ demo ในห้องเรียน แต่ APScheduler หรือ cron/systemd timer เหมาะกับ production เพราะมี persistence และ misfire handling ที่ `schedule` บอกเองว่าไม่มี; python-nmap ไม่มี release ตั้งแต่ ต.ค. 2021 ดังนั้น `xml.etree.ElementTree` บน output `nmap -oX` หรือ parser ของ libnmap ปลอดภัยกว่าในระยะยาว และทักษะการ parse XML นี้ถ่ายโอนไปยัง .nessus และ OpenVAS XML ได้โดยตรง สำหรับ idempotency ไม่มีเอกสารทางการใดเสนอ library ทั่วไป การออกแบบจึงใช้ hash-compare-then-act, "upsert" ลง local state store หรือ watermark แบบ `lastModStartDate` ตามที่ NVD แนะนำ

### ตัวอย่างโค้ด

**ตัวอย่าง 3.1 — SHA-256 file-integrity baseline** — *illustrative*; อิงจาก [hashlib.file_digest](https://docs.python.org/3/library/hashlib.html#hashlib.file_digest) และ [hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest); ต้องใช้ Python 3.11+
```python
import hashlib, hmac, json, sys
from pathlib import Path

def sha256_of(path: Path) -> str:
    with path.open("rb") as f:                     # binary mode is required by file_digest
        return hashlib.file_digest(f, "sha256").hexdigest()

def build_baseline(root: Path, out: Path) -> None:
    baseline = {str(p): sha256_of(p) for p in root.rglob("*") if p.is_file()}
    out.write_text(json.dumps(baseline, indent=2, sort_keys=True))

def verify(root: Path, baseline_file: Path) -> int:
    baseline = json.loads(baseline_file.read_text())
    changed = 0
    for rel, expected in baseline.items():
        p = Path(rel)
        if not p.exists():
            print(f"MISSING  {rel}"); changed += 1; continue
        actual = sha256_of(p)
        if not hmac.compare_digest(actual, expected):   # constant-time compare
            print(f"MODIFIED {rel}"); changed += 1
    new = {str(p) for p in root.rglob("*") if p.is_file()} - set(baseline)
    for rel in sorted(new):
        print(f"NEW      {rel}"); changed += 1
    return changed

if __name__ == "__main__":
    mode, root, store = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    if mode == "init":
        build_baseline(root, store)
    else:
        sys.exit(1 if verify(root, store) else 0)   # non-zero exit = drift detected
```

**ตัวอย่าง 3.2 — ตรวจวันหมดอายุ TLS certificate** — *illustrative*; อิงจาก [ssl.create_default_context / getpeercert / cert_time_to_seconds](https://docs.python.org/3/library/ssl.html)
```python
import socket, ssl, sys
from datetime import datetime, timezone

def days_until_expiry(host: str, port: int = 443, timeout: float = 5.0) -> int:
    ctx = ssl.create_default_context()             # CERT_REQUIRED + hostname check
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()              # dict is empty if not validated
    not_after = cert["notAfter"]                    # e.g. 'Nov 22 08:15:19 2013 GMT'
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    return (expires - datetime.now(timezone.utc)).days

if __name__ == "__main__":
    warn_days = 30
    rc = 0
    for host in sys.argv[1:]:
        try:
            d = days_until_expiry(host)
            status = "WARN" if d < warn_days else "OK"
            print(f"{status:4} {host:40} {d:4d} days left")
            rc |= d < warn_days
        except (ssl.SSLError, socket.error) as e:   # expired/untrusted certs raise here
            print(f"FAIL {host:40} {e}"); rc = 1
    sys.exit(rc)
```

**ตัวอย่าง 3.3 — parse Nmap XML ด้วย ElementTree** — *illustrative*; โครงสร้าง `nmap -oX` (host/status/address/ports/port/state/service) ตาม Nmap XML DTD ที่ https://nmap.org/book/nmap-dtd.html ซึ่ง **ไม่ได้ดึงมาตรวจในรอบนี้**
```python
import sys
import xml.etree.ElementTree as ET

def parse_nmap_xml(path: str):
    root = ET.parse(path).getroot()                       # <nmaprun>
    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") == "ipv4"), "?")
        for port in host.findall("./ports/port"):
            state = port.find("state").get("state")
            if state != "open":
                continue
            svc = port.find("service")
            yield {
                "host": addr,
                "proto": port.get("protocol"),
                "port": int(port.get("portid")),
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            }

if __name__ == "__main__":
    # generate input with: nmap -sV -oX scan.xml 192.0.2.0/28   (authorised targets only)
    for row in parse_nmap_xml(sys.argv[1]):
        print(f"{row['host']:15} {row['proto']}/{row['port']:<5} {row['service']:12} "
              f"{row['product']} {row['version']}")
```

**ตัวอย่าง 3.3b — แบบเดียวกันด้วย python-nmap** — การเรียกคัดตรงจาก [python-nmap PyPI](https://pypi.org/project/python-nmap/); ต้องมี nmap binary
```python
import nmap

nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-443')          # runs nmap under the hood
print(nm.command_line())
for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            print(host, proto, port, nm[host][proto][port]['state'])
print(nm.csv())
```

**ตัวอย่าง 3.4 — scheduled job ด้วย `schedule` และการเรียก subprocess อย่างปลอดภัย** — ดัดแปลงจาก [schedule docs](https://schedule.readthedocs.io/en/stable/) และ [subprocess docs](https://docs.python.org/3/library/subprocess.html)
```python
import logging, subprocess, time, schedule

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("soc.jobs")

def run_integrity_check():
    try:
        result = subprocess.run(
            ["python3", "fim.py", "verify", "/etc", "baseline.json"],  # list form, shell=False (default)
            capture_output=True, text=True, check=True, timeout=300)
        log.info("FIM OK: %s", result.stdout.strip()[:200])
    except subprocess.CalledProcessError as e:      # non-zero exit = drift detected
        log.warning("FIM drift (rc=%s): %s", e.returncode, e.stdout.strip()[:500])
    except subprocess.TimeoutExpired:
        log.error("FIM check timed out")

schedule.every(6).hours.do(run_integrity_check)
schedule.every().day.at("07:00").do(lambda: log.info("daily KEV/cert checks go here"))

while True:                 # schedule has no persistence; use APScheduler/cron for production
    schedule.run_pending()
    time.sleep(1)
```

**ตัวอย่าง 3.5 — secrets/config แบบมี type ด้วย pydantic-settings** — *illustrative*; อิงจาก [Pydantic Settings docs](https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/)
```python
from pydantic import SecretStr, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", env_file_encoding="utf-8")
    vt_api_key: SecretStr                     # read from SOC_VT_API_KEY (case-insensitive)
    abuseipdb_key: SecretStr
    slack_webhook: HttpUrl
    nvd_api_key: SecretStr | None = None
    cert_warn_days: int = 30

settings = Settings()                          # raises ValidationError if a required var is missing
print(settings.vt_api_key)                     # prints '**********' — SecretStr masks on repr/print
api_key = settings.vt_api_key.get_secret_value()
```

ตัวอย่าง 3.1, 3.2, 3.3 ไม่ต้องใช้ credential จึงเหมาะเป็น lab แรก ส่วน 3.4 และ 3.5 เป็น "plumbing" ที่ script ถัด ๆ ไปใช้ซ้ำ

### เอกสารอ้างอิงประจำหัวข้อ

- Python docs: subprocess – Security Considerations — https://docs.python.org/3/library/subprocess.html#security-considerations
- Python docs: subprocess.run — https://docs.python.org/3/library/subprocess.html#subprocess.run
- Python docs: hashlib.file_digest — https://docs.python.org/3/library/hashlib.html#hashlib.file_digest
- Python docs: hashlib — https://docs.python.org/3/library/hashlib.html
- Python docs: hmac — https://docs.python.org/3/library/hmac.html
- Python docs: ssl — https://docs.python.org/3/library/ssl.html#ssl.create_default_context
- Requests Advanced Usage – Timeouts — https://requests.readthedocs.io/en/latest/user/advanced/#timeouts
- Requests Advanced Usage – SSL Cert Verification — https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification
- Requests Advanced Usage – Proxies — https://requests.readthedocs.io/en/latest/user/advanced/#proxies
- HTTPX Timeouts — https://www.python-httpx.org/advanced/timeouts/
- Pydantic Settings docs — https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/
- schedule docs — https://schedule.readthedocs.io/en/stable/
- APScheduler 3.x User Guide — https://apscheduler.readthedocs.io/en/3.x/userguide.html
- CIS Benchmarks — https://www.cisecurity.org/cis-benchmarks
- python-nmap on PyPI — https://pypi.org/project/python-nmap/
- savon-noir/python-libnmap — https://github.com/savon-noir/python-libnmap
- libnmap parser docs — https://libnmap.readthedocs.io/en/latest/parser.html
- Nmap XML DTD (ไม่ได้ดึงมาตรวจ) — https://nmap.org/book/nmap-dtd.html
- TechTarget: Boost SOC efficiency with Python security automation — https://www.techtarget.com/searchsecurity/tip/Boost-SOC-efficiency-with-Python-security-automation
- No Starch Press: Black Hat Python 2E — https://nostarch.com/black-hat-python2E
- O'Reilly listing: Python for Cybersecurity — https://www.oreilly.com/library/view/-/9781119850649
- Eyrolles: Python for Cybersecurity — https://www.eyrolles.com/Informatique/Livre/python-for-cybersecurity-9781119850649/
- Packt: Security Automation with Python — https://www.packtpub.com/product/security-automation-with-python/9781805125105
- O'Reilly: Security Automation with Python — https://www.oreilly.com/library/view/-/9781805125105/
- fabacab/awesome-cybersecurity-blueteam — https://github.com/fabacab/awesome-cybersecurity-blueteam
- SimeonOnSecurity book list — https://simeononsecurity.com/articles/essential-books-cybersecurity-it-professionals/

---

## 4. API Integration for Security Tools: สามรูปแบบ auth ครอบคลุมทุก API ในขอบเขต

### แหล่งต้นฉบับ

มาตรฐานอินเทอร์เน็ตที่รองรับการเชื่อม API มีสามฉบับ **RFC 6585 §4** (Nottingham & Fielding, เม.ย. 2012) นิยามว่า "The 429 status code indicates that the user has sent too many requests in a given amount of time ('rate limiting')" การตอบ "MAY include a Retry-After header indicating how long to wait" และ "Responses with the 429 status code MUST NOT be stored by a cache" ([RFC 6585](https://www.rfc-editor.org/rfc/rfc6585)) **RFC 6749 §4.4** นิยาม Client Credentials Grant ว่าใช้เมื่อ "the client is requesting access to the protected resources under its control" โดย `grant_type` "REQUIRED. Value MUST be set to 'client_credentials'", client "MUST authenticate with the authorization server" และไม่ควรออก refresh token ขณะที่ **§2.3.1** ระบุว่า client_id/client_secret ควรส่งผ่าน HTTP Basic และการใส่ใน request body "is NOT RECOMMENDED" ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4); [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)) และ **OpenAPI Specification v3.2.1** (10 ก.ย. 2026) "defines a standard, programming language-agnostic interface description for HTTP APIs" รวม Security Scheme Object (§4.27) ([OpenAPI Specification](https://spec.openapis.org/oas/latest.html)) ฝั่ง library เอกสาร Requests อธิบาย `Session` ที่ "will use urllib3's connection pooling… the underlying TCP connection will be reused", ยอมรับว่า "By default, Requests does not retry failed connections" และให้สูตร mount `urllib3.util.Retry(total=3, backoff_factor=0.1, status_forcelist=[502, 503, 504])` ผ่าน `HTTPAdapter(max_retries=retries)` รวมถึง `requests.auth.AuthBase` สำหรับ custom auth, การ parse RFC 8288 `Link` header เป็น `r.links["next"]` และทางเลือก non-blocking (httpx, requests-futures, grequests) ([Requests Advanced Usage](https://requests.readthedocs.io/en/latest/user/advanced/); [Automatic Retries](https://requests.readthedocs.io/en/latest/user/advanced/#example-automatic-retries); [Custom Authentication](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication); [Link Headers](https://requests.readthedocs.io/en/latest/user/advanced/#link-headers); [Blocking Or Non-Blocking?](https://requests.readthedocs.io/en/latest/user/advanced/#blocking-or-non-blocking)) เอกสาร urllib3 ให้ default ของ `Retry` ที่สำคัญ: `total=10`, `backoff_factor=0` (ปิด backoff), `backoff_max=120`, **`allowed_methods` เฉพาะ verb ที่ idempotent** (`DELETE, GET, HEAD, OPTIONS, PUT, TRACE`), `respect_retry_after_header=True` และสูตร sleep "{backoff factor} * (2 ** ({number of previous retries}))" โดย Retry-After ถูกเคารพสำหรับ status 413, 429, 503 ([urllib3 util reference](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html))

เอกสาร API ทางการที่ SOC เชื่อมบ่อยที่สุดแยกเป็นห้ากลุ่ม **Vulnerability intelligence:** NVD CVE API 2.0 (base `https://services.nvd.nist.gov/rest/json/cves/2.0`, key ใน header `apiKey`, pagination `startIndex`/`resultsPerPage`/`totalResults`, incremental sync ด้วย `lastModStartDate`/`lastModEndDate`) มี rate limit สาธารณะ **5 request ต่อ 30 วินาทีแบบไม่มี key และ 50 เมื่อมี key** และ NVD ยังแนะนำให้ sleep ~6 วินาทีระหว่าง request ([NVD Developers – Start Here](https://nvd.nist.gov/developers/start-here); [NVD Vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities); [DEV Community](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p)) CISA KEV ให้ JSON/CSV/JSON Schema/license ที่ URL คงที่ มี **1,766 รายการ ณ 2026-11-01** และ schema ระบุ field เช่น `cveID` (pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`), `vendorProject`, `product`, `dateAdded`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse` ("Known"/"Unknown"), `forensicTriage` ("per BOD 26-04"), `cwes[]` โดยเกณฑ์การบรรจุคือมี CVE ID, "reliable evidence that the vulnerability has been actively exploited in the wild" และ "a clear remediation action" ([KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [KEV JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json); [CISA KEV overview](https://www.cisa.gov/known-exploited-vulnerabilities)) Tenable pyTenable (Python 3.10+, `TenableIO(access_key=..., secret_key=...)`) และ Greenbone python-gvm (≈126 ดาว, GPL-3.0, Python 3.11+, พูด GMP/OSP) ครอบคลุม scanner เชิงพาณิชย์/โอเพนซอร์ส ([pyTenable docs](https://pytenable.readthedocs.io/en/stable/); [python-gvm](https://github.com/greenbone/python-gvm)) **Threat intel/enrichment:** VirusTotal Public API "limited to 500 requests per day and a rate of 4 requests per minute" และ "must not be used in commercial products or services" ([VT Public vs Premium](https://docs.virustotal.com/reference/public-vs-premium-api); [vt-py quickstart](https://virustotal.github.io/vt-py/quickstart.html)); Shodan ใช้ `key` เป็น query parameter และหักเครดิตเมื่อใช้ filter หรืออ่านผลหลังหน้าแรก ([Shodan REST API](https://developer.shodan.io/api); [shodan-python tutorial](https://shodan.readthedocs.io/en/latest/tutorial.html)); AbuseIPDB v2 ใช้ header `Key` (ชอบมากกว่า query string เพราะ "server logs (like ours) will record them") มีโควตา CHECK ต่อวัน Standard 1,000 / Webmaster 3,000 / Supporter 5,000 / Basic 10,000 / Premium 50,000 และคืน 429 เมื่อเกิน ([AbuseIPDB docs](https://docs.abuseipdb.com/)); HIBP v3 บังคับ header `hibp-api-key` และ user agent ("Each request to the API must be accompanied by a user agent request header" ไม่งั้น 403) ขณะที่ Pwned Passwords `range/{5 chars}` แบบ k-anonymity "freely accessible without the need for a subscription and API key" ([HIBP API v3](https://haveibeenpwned.com/API/v3)) **SIEM/log:** Splunk SDK for Python (≈747 ดาว, ต้อง "Python 3.13 or newer", เชื่อมด้วย username/password, bearer `splunkToken` หรือ session key) ([splunk-sdk-python](https://github.com/splunk/splunk-sdk-python); [dev.splunk.com](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/)); elasticsearch-py (≈4.4k ดาว; `Elasticsearch("https://localhost:9200", ca_certs=..., api_key=os.environ["ELASTIC_API_KEY"])`; "Running Elasticsearch without security enabled is not recommended") ([elasticsearch-py](https://github.com/elastic/elasticsearch-py); [Connecting](https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting)); Wazuh API บน port 55000 ที่ "All API endpoints (except the login endpoint itself) require authentication using a JSON Web Token (JWT)" ผ่าน `POST /security/user/authenticate` แบบ basic auth แล้ว `Authorization: Bearer` ([Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)); และ Azure Monitor HTTP Data Collector API ที่ sign ด้วย HMAC-SHA256 `SharedKey` แต่ **deprecated: "Support ended… September 14, 2026, although ingestion continues to function. Migrate to the Logs ingestion API"** ([Azure Monitor Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)) **EDR/XDR:** CrowdStrike FalconPy (≈517 ดาว, Unlicense, Python 3.8–3.14, "completely abstracts token management") ([FalconPy](https://github.com/CrowdStrike/falconpy); [developer.crowdstrike.com](https://developer.crowdstrike.com/sdks/python/)) และ Microsoft Graph Security API (app-only สำหรับ "a SIEM scenario", ต้อง admin consent ต่อ tenant, `GET /security/alerts_v2` ต้อง `SecurityAlert.Read.All`, pagination ด้วย `@odata.nextLink`) กับ msgraph-sdk-python (≈634 ดาว, MIT) ([Graph Security authorization](https://learn.microsoft.com/en-us/graph/security-authorization); [List alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2); [msgraph-sdk-python](https://github.com/microsoftgraph/msgraph-sdk-python)) **Notification:** Slack SDK incoming webhook (`WebhookClient(url).send(text=..., blocks=[...])`; โดย default เปิดเฉพาะ `ConnectionErrorRetryHandler`; `RateLimitErrorRetryHandler` ต้องเพิ่มเองสำหรับ 429) ([Slack SDK Webhook](https://docs.slack.dev/tools/python-slack-sdk/webhook/))

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาวบอกเรื่องสำคัญหนึ่งอย่าง: ใน SOC Python "repository ที่ถูกอ้างมากที่สุด" คือ **SDK ของผู้ผลิตเอง** ไม่ใช่โครงการอิสระ ได้แก่ elastic/elasticsearch-py (≈4.4k), VirusTotal/vt-py (≈792, "The official Python 3 client library for VirusTotal"), splunk/splunk-sdk-python (≈747), microsoftgraph/msgraph-sdk-python (≈634), CrowdStrike/falconpy (≈517), MISP/PyMISP (≈494), savon-noir/python-libnmap (≈493), greenbone/python-gvm (≈126) และ Vehemont/nvdlib (≈118, MIT, "Built in rate limiting according to NIST NVD recommendations", default 6 วินาทีระหว่าง request) ([vt-py](https://github.com/VirusTotal/vt-py); [PyMISP](https://github.com/MISP/PyMISP); [nvdlib](https://github.com/Vehemont/nvdlib); [nvdlib.com](https://nvdlib.com)) ทักษะที่ถ่ายโอนได้จึงคือการอ่าน README ของ SDK เคียงกับ REST reference ของผู้ผลิต รายการ awesome-cybersecurity-blueteam (≈5.6k) เป็นดัชนีหลัก และบทความ DEV Community "How to Scrape and Parse CVE Data from NVD API v2" (Ayi Nedjimi) เป็น walkthrough ภาคปฏิบัติของ pagination/rate limit ของ NVD 2.0 ที่ให้ค่า `resultsPerPage` สูงสุด 2000 ([DEV Community](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p)) การวิเคราะห์เชิงสังเคราะห์ของบันทึกคือ **สามรูปแบบ auth ครอบคลุมทุก API ในขอบเขต**: (1) static API key ใน header หรือ query parameter (VirusTotal, AbuseIPDB `Key`, HIBP `hibp-api-key`, NVD `apiKey`, Shodan `key=`, Tenable access/secret pair, MISP key, Elasticsearch `api_key`, และ Slack webhook ที่ "URL คือ secret"), (2) OAuth 2.0 client credentials → bearer token (FalconPy, Microsoft Graph ผ่าน `ClientSecretCredential` + scope `https://graph.microsoft.com/.default`) และญาติใกล้ชิดคือการแลก username/password เป็น JWT (Wazuh, Splunk session key) และ (3) HMAC-SHA256 request signing (Azure `SharedKey` ที่ `StringToSign = VERB + "\n" + Content-Length + "\n" + Content-Type + "\n" + "x-ms-date:" + date + "\n" + "/api/logs"`) บทเรียนที่ตามมา: key ใน header ปลอดภัยกว่าใน URL เพราะ proxy/server บันทึก URL (AbuseIPDB ระบุชัด); OAuth2 เพิ่มความซับซ้อน (token cache/expiry/refresh) ที่ SDK ทางการจัดการให้ จึงควรเขียน raw `POST /token` ในชั้นเรียนครั้งเดียวแล้วใช้ SDK ใน production; HMAC พบน้อยที่สุด (ตัวอย่างหลักถูก deprecate แล้ว) แต่ยังควรสอนเพราะแสดงให้เห็นว่า clock skew (`x-ms-date`) และ canonicalization แบบ byte-for-byte สำคัญอย่างไร และเพราะ `urllib3.Retry` retry เฉพาะ idempotent verb โดย default การ retry POST (เช่น webhook alert) ต้อง opt-in ผ่าน `allowed_methods` และทำให้ POST idempotent เอง (เช่น ใส่ dedup key อย่าง alert ID ใน payload) KEV เป็น integration แรกที่ง่ายที่สุดสำหรับนักเรียน: ไม่ต้อง auth, มี JSON Schema, field คงที่, ขนาดเล็ก และนำไปใช้ได้ทันที (filter vendor + dueDate)

### ตัวอย่างโค้ด

**ตัวอย่าง 4.1 — requests.Session กับ urllib3 Retry/backoff ที่เคารพ Retry-After** — ดัดแปลงจาก [Requests: Example Automatic Retries](https://requests.readthedocs.io/en/latest/user/advanced/#example-automatic-retries) และ [urllib3.util.Retry](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html)
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

def make_session(user_agent: str = "soc-automation/1.0") -> requests.Session:
    retries = Retry(
        total=5,
        backoff_factor=1,                 # sleeps 0s,2s,4s,8s,16s (factor*2**n), capped by backoff_max=120
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods={"GET", "HEAD"},  # retry idempotent verbs only
        respect_retry_after_header=True,  # default; honours Retry-After on 413/429/503
        raise_on_status=False,
    )
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

if __name__ == "__main__":
    with make_session() as s:
        r = s.get("https://httpbin.org/status/503", timeout=(3.05, 27))  # always set a timeout
        print(r.status_code)
```

**ตัวอย่าง 4.2 — query NVD CVE API 2.0 พร้อม pagination และ rate limiting** — *illustrative*; อิงจาก limit ใน [NVD Developers](https://nvd.nist.gov/developers/start-here) และ [DEV Community NVD v2 walkthrough](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p)
```python
import os, time, requests

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")                       # free key: 50 req/30s instead of 5
SLEEP = 0.7 if API_KEY else 6.5                           # NVD asks for ~6s sleeps without key

def iter_cves(**params):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    start = 0
    while True:
        q = dict(params, startIndex=start, resultsPerPage=2000)   # 2000 is the max page size
        r = requests.get(NVD, headers=headers, params=q, timeout=60)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", "30"))); continue
        r.raise_for_status()
        data = r.json()
        yield from data.get("vulnerabilities", [])
        start += data["resultsPerPage"]
        if start >= data["totalResults"]:
            break
        time.sleep(SLEEP)

if __name__ == "__main__":
    # incremental sync: only CVEs modified in a window (ISO-8601 with offset)
    for item in iter_cves(lastModStartDate="2026-10-25T00:00:00.000+00:00",
                          lastModEndDate="2026-11-01T00:00:00.000+00:00",
                          cvssV3Severity="CRITICAL"):
        cve = item["cve"]
        print(cve["id"], cve["descriptions"][0]["value"][:80])
```

**ตัวอย่าง 4.3 — ค้นหา file hash บน VirusTotal ด้วย vt-py** — ดัดแปลงจาก [vt-py quickstart](https://virustotal.github.io/vt-py/quickstart.html); โควตาตาม [VT Public API](https://docs.virustotal.com/reference/public-vs-premium-api)
```python
import os, sys, vt

def lookup(sha256: str) -> dict:
    with vt.Client(os.environ["VT_API_KEY"]) as client:       # context manager closes the client
        try:
            f = client.get_object(f"/files/{sha256}")
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                return {"sha256": sha256, "known": False}
            raise
        stats = f.last_analysis_stats                           # {'malicious': 62, 'undetected': 2, ...}
        return {"sha256": f.sha256, "known": True, "size": f.size,
                "type": f.type_tag, "malicious": stats["malicious"],
                "suspicious": stats["suspicious"], "undetected": stats["undetected"]}

if __name__ == "__main__":
    # Public API: 4 requests/minute, 500/day, non-commercial use only
    for h in sys.argv[1:]:
        print(lookup(h))
```

**ตัวอย่าง 4.4 — ดึง CISA KEV feed แล้ว filter ตาม vendor / due date** — *illustrative*; field ตาม [KEV JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json); URL feed ตาม [KEV catalog page](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
```python
import sys, requests
from datetime import date

KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def load_kev() -> dict:
    r = requests.get(KEV_JSON, timeout=30,
                     headers={"User-Agent": "soc-kev-check/1.0"})
    r.raise_for_status()
    return r.json()

def filter_kev(catalog: dict, vendors: set[str], ransomware_only: bool = False):
    for v in catalog["vulnerabilities"]:
        if v["vendorProject"].lower() not in vendors:
            continue
        if ransomware_only and v.get("knownRansomwareCampaignUse") != "Known":
            continue
        yield v

if __name__ == "__main__":
    cat = load_kev()
    print(f"KEV {cat['catalogVersion']} released {cat['dateReleased']} count={cat['count']}")
    today = date.today().isoformat()
    for v in filter_kev(cat, {x.lower() for x in sys.argv[1:]} or {"microsoft"}):
        overdue = "OVERDUE" if v["dueDate"] < today else ""
        print(f"{v['cveID']:16} {v['product'][:28]:28} added={v['dateAdded']} "
              f"due={v['dueDate']} ransomware={v['knownRansomwareCampaignUse']} {overdue}")
```

**ตัวอย่าง 4.5 — ส่ง alert เข้า Slack ผ่าน incoming webhook พร้อม retry เมื่อ 429** — ดัดแปลงจาก [Slack SDK Webhook docs](https://docs.slack.dev/tools/python-slack-sdk/webhook/)
```python
import os
from slack_sdk.webhook import WebhookClient
from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler

webhook = WebhookClient(os.environ["SLACK_WEBHOOK_URL"])     # the URL *is* the secret
webhook.retry_handlers.append(RateLimitErrorRetryHandler(max_retry_count=2))  # retry on HTTP 429

def alert(title: str, detail: str, severity: str = "high") -> None:
    response = webhook.send(
        text=f"[{severity.upper()}] {title}",                 # fallback text for notifications
        blocks=[{
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*{title}*\nSeverity: `{severity}`\n{detail}"},
        }],
    )
    assert response.status_code == 200
    assert response.body == "ok"

if __name__ == "__main__":
    alert("Certificate expiring", "vpn.example.com expires in 12 days")
```

**ตัวอย่าง 4.6 — ตรวจ IP reputation กับ AbuseIPDB** — *illustrative*; อิงจาก [AbuseIPDB docs](https://docs.abuseipdb.com/)
```python
import os, sys, requests

def check_ip(ip: str, max_age_days: int = 90) -> dict:
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},  # key in header, not URL
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        timeout=15,
    )
    if r.status_code == 429:                           # daily CHECK quota exceeded (1,000/day on Standard)
        raise RuntimeError("AbuseIPDB quota exceeded; retry tomorrow")
    r.raise_for_status()
    d = r.json()["data"]
    return {"ip": ip, "score": d["abuseConfidenceScore"], "reports": d["totalReports"],
            "tor": d["isTor"], "usage": d.get("usageType"), "cc": d.get("countryCode")}

if __name__ == "__main__":
    for ip in sys.argv[1:]:
        res = check_ip(ip)
        flag = "BLOCK?" if res["score"] >= 75 else ""
        print(f"{res['ip']:16} score={res['score']:3} reports={res['reports']:4} tor={res['tor']} {flag}")
```

**ตัวอย่าง 4.7 — ตรวจ Pwned Passwords แบบ k-anonymity สำหรับ account-hygiene audit** — *illustrative*; อิงจาก [HIBP API v3](https://haveibeenpwned.com/API/v3)
```python
import hashlib, requests

def pwned_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",   # no API key needed
                     headers={"User-Agent": "soc-password-audit/1.0"},     # UA is mandatory on HIBP APIs
                     timeout=10)
    r.raise_for_status()
    for line in r.text.splitlines():
        sfx, count = line.split(":")
        if sfx == suffix:
            return int(count)
    return 0

if __name__ == "__main__":
    for pw in ["Password123", "correct horse battery staple"]:
        print(f"{pw!r}: seen {pwned_count(pw)} times in breaches")
```

**ตัวอย่าง 4.8 — OAuth2 client credentials ผ่าน SDK: CrowdStrike FalconPy และ Microsoft Graph** — verbatim/ดัดแปลงจาก [FalconPy README](https://github.com/CrowdStrike/falconpy), [msgraph-sdk-python README](https://github.com/microsoftgraph/msgraph-sdk-python), [List alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2)
```python
import asyncio, os
from falconpy import Hosts
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient

# CrowdStrike: SDK performs the OAuth2 client-credentials flow and refreshes tokens
hosts = Hosts(client_id=os.getenv("FALCON_CLIENT_ID"),
              client_secret=os.getenv("FALCON_CLIENT_SECRET"))
SEARCH_FILTER = "hostname-search-string"
hosts_search_result = hosts.query_devices_by_filter(filter=f"hostname:*'*{SEARCH_FILTER}*'")
print(hosts_search_result["status_code"], hosts_search_result["body"].get("resources", [])[:5])

# Microsoft Graph Security: app-only token via Entra ID, scope .default
credentials = ClientSecretCredential(os.environ["TENANT_ID"], os.environ["CLIENT_ID"],
                                     os.environ["CLIENT_SECRET"])
graph_client = GraphServiceClient(credentials=credentials,
                                  scopes=["https://graph.microsoft.com/.default"])

async def high_alerts():
    result = await graph_client.security.alerts_v2.get()     # needs SecurityAlert.Read.All
    for a in (result.value or []):
        if a.severity and a.severity.value == "high":
            print(a.created_date_time, a.service_source, a.title)

asyncio.run(high_alerts())
```

**ตัวอย่าง 4.9 — HMAC-SHA256 SharedKey signing สำหรับ Azure Monitor custom logs** — `build_signature` คัดตรงจาก [Azure Monitor HTTP Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api); API นี้ deprecated (support สิ้นสุด 14 ก.ย. 2026) — แสดงเพื่อสอน HMAC pattern
```python
import base64, datetime, hashlib, hmac, json, requests

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

def post_data(customer_id, shared_key, body, log_type):
    method, content_type, resource = 'POST', 'application/json', '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(customer_id, shared_key, rfc1123date, len(body), method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'
    headers = {'content-type': content_type, 'Authorization': signature,
               'Log-Type': log_type, 'x-ms-date': rfc1123date}
    response = requests.post(uri, data=body, headers=headers, timeout=30)
    print('Accepted' if 200 <= response.status_code <= 299 else f"Response code: {response.status_code}")

body = json.dumps([{"host": "web01", "check": "cert_expiry", "days_left": 12}])
# post_data(WORKSPACE_ID, SHARED_KEY, body, "SocAutomation")
```

**ตัวอย่าง 4.10 — Wazuh API: basic-auth → JWT แล้วเรียกด้วย Bearer** — *illustrative*; อิงจาก [Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
```python
import os, requests
from requests.auth import HTTPBasicAuth

BASE = os.getenv("WAZUH_API", "https://localhost:55000")
CA = os.getenv("WAZUH_CA_BUNDLE", False)          # path to the API cert; False only in a lab

def get_token() -> str:
    r = requests.post(f"{BASE}/security/user/authenticate",
                      auth=HTTPBasicAuth(os.environ["WAZUH_USER"], os.environ["WAZUH_PASS"]),
                      params={"raw": "true"}, verify=CA, timeout=10)
    r.raise_for_status()
    return r.text                                  # JWT; re-authenticate when it expires

def agents_status(token: str) -> dict:
    r = requests.get(f"{BASE}/agents/summary/status",
                     headers={"Authorization": f"Bearer {token}"}, verify=CA, timeout=10)
    r.raise_for_status()
    return r.json()["data"]

if __name__ == "__main__":
    print(agents_status(get_token()))              # e.g. {'active': 12, 'disconnected': 1, ...}
```

ทุก snippet ที่เรียก network ตั้ง `timeout=` เสมอ เพราะเอกสาร requests ระบุว่าไม่มี default timeout ตัวอย่าง 4.4 และ 4.7 ไม่ต้องใช้ credential; 4.2, 4.3, 4.6 แนะนำ key-in-header และ quota handling; 4.8, 4.9, 4.10 ครอบคลุม OAuth2, HMAC และ JWT exchange ตามลำดับ

### เอกสารอ้างอิงประจำหัวข้อ

- RFC 6585 — https://www.rfc-editor.org/rfc/rfc6585
- RFC 6749 §4.4 Client Credentials Grant — https://www.rfc-editor.org/rfc/rfc6749#section-4.4
- RFC 6749 §2.3.1 — https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
- OpenAPI Specification (latest, v3.2.1) — https://spec.openapis.org/oas/latest.html
- Requests Advanced Usage — https://requests.readthedocs.io/en/latest/user/advanced/
- Requests: Example Automatic Retries — https://requests.readthedocs.io/en/latest/user/advanced/#example-automatic-retries
- Requests: Custom Authentication — https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication
- Requests: Link Headers — https://requests.readthedocs.io/en/latest/user/advanced/#link-headers
- Requests: Blocking Or Non-Blocking? — https://requests.readthedocs.io/en/latest/user/advanced/#blocking-or-non-blocking
- urllib3 util reference (Retry) — https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
- NVD Developers – Start Here — https://nvd.nist.gov/developers/start-here
- NVD Developers – Vulnerabilities — https://nvd.nist.gov/developers/vulnerabilities
- DEV Community: NVD API v2 walkthrough — https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p
- Vehemont/nvdlib — https://github.com/Vehemont/nvdlib
- nvdlib.com — https://nvdlib.com
- CISA KEV Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV overview — https://www.cisa.gov/known-exploited-vulnerabilities
- KEV JSON schema — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
- pyTenable docs — https://pytenable.readthedocs.io/en/stable/
- greenbone/python-gvm — https://github.com/greenbone/python-gvm
- python-gvm docs — https://greenbone.github.io/python-gvm/
- VirusTotal Public vs Premium API — https://docs.virustotal.com/reference/public-vs-premium-api
- VirusTotal/vt-py — https://github.com/VirusTotal/vt-py
- vt-py quickstart — https://virustotal.github.io/vt-py/quickstart.html
- Shodan REST API — https://developer.shodan.io/api
- shodan-python tutorial — https://shodan.readthedocs.io/en/latest/tutorial.html
- AbuseIPDB docs — https://docs.abuseipdb.com/
- HIBP API v3 — https://haveibeenpwned.com/API/v3
- MISP/PyMISP — https://github.com/MISP/PyMISP
- splunk/splunk-sdk-python — https://github.com/splunk/splunk-sdk-python
- dev.splunk.com Python SDK — https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/
- elastic/elasticsearch-py — https://github.com/elastic/elasticsearch-py
- Elasticsearch Python client – Connecting — https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting
- Wazuh API Getting Started — https://documentation.wazuh.com/current/user-manual/api/getting-started.html
- Azure Monitor HTTP Data Collector API — https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
- CrowdStrike/falconpy — https://github.com/CrowdStrike/falconpy
- developer.crowdstrike.com Python SDK — https://developer.crowdstrike.com/sdks/python/
- Microsoft Graph Security authorization — https://learn.microsoft.com/en-us/graph/security-authorization
- Microsoft Graph: List alerts_v2 — https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2
- microsoftgraph/msgraph-sdk-python — https://github.com/microsoftgraph/msgraph-sdk-python
- Slack SDK Webhook — https://docs.slack.dev/tools/python-slack-sdk/webhook/
- fabacab/awesome-cybersecurity-blueteam — https://github.com/fabacab/awesome-cybersecurity-blueteam

---

## 5. Threat Intelligence Automation: STIX 2.1 + TAXII 2.1 คือชุดทักษะเดียวที่ครอบทั้ง IOC exchange และ ATT&CK mapping

### แหล่งต้นฉบับ

มาตรฐานการแลกเปลี่ยน CTI ที่ใช้จริงคือ OASIS **STIX 2.1** (เอกสารปัจจุบัน "STIX Version 2.1 Errata 01", 2 เม.ย. 2025, บรรณาธิการ Rich Piazza (MITRE), Emily Ratliff (IBM), Stephan Relitz (Peraton), Christian Studer (CIRCL)) ซึ่งนิยาม **18 SDOs** (Attack Pattern, Campaign, Course of Action, Grouping, Identity, Indicator, Infrastructure, Intrusion Set, Location, Malware, Malware Analysis, Note, Observed Data, Opinion, Report, Threat Actor, Tool, Vulnerability), **2 SROs** (Relationship, Sighting) และ **18 SCOs** (Artifact, Autonomous System, Directory, Domain Name, Email Address, Email Message, File, IPv4/IPv6 Address, MAC Address, Mutex, Network Traffic, Process, Software, URL, User Account, Windows Registry Key, X.509 Certificate) ([OASIS STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)) เอกสาร library stix2 เสริมว่าสำหรับ Indicator "`pattern` and `pattern_type` are required and cannot be set automatically", `valid_from` จำเป็นแต่ default เป็นเวลาปัจจุบัน, Malware ต้องมี `is_family`, Relationship ต้องมี `relationship_type`/`source_ref`/`target_ref` และ Bundle ตั้ง `type`/`id`/`spec_version` อัตโนมัติ ([stix2 docs: Creating STIX Content](https://stix2.readthedocs.io/en/latest/guide/creating.html)) ชั้นขนส่งคือ **TAXII 2.1** (OASIS Standard, 10 มิ.ย. 2021) "an application layer protocol for the communication of cyber threat information" บน HTTPS ด้วย media type `application/taxii+json;version=2.1` มี Discovery endpoint `/taxii2/`, API Roots, Collections, Objects ใน envelope, endpoint ต้องลงท้ายด้วย `/`, และ filter/pagination ด้วย `added_after`, `limit`, `next`, `more`, `match[type]`, `match[id]`, `match[spec_version]`, `match[version]` ([OASIS TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)) **MITRE ATT&CK เองเผยแพร่เป็น STIX 2.1** ที่ github.com/mitre-attack/attack-stix-data (≈707 ดาว; `enterprise-attack/enterprise-attack.json` บวกไฟล์ตามเวอร์ชัน) และให้บริการผ่าน TAXII 2.1 server สาธารณะ `https://attack-taxii.mitre.org` (API root `/api/v21/` ที่ "always serves STIX content from the latest ATT&CK release", root แบบ pin `/api/v21/attack-<x.y>`, collection ID ของ Enterprise `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019`, และ **rate limit 50 request ต่อ 10 นาทีต่อ IP**) ([ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/); [attack-stix-data](https://github.com/mitre-attack/attack-stix-data); [attack-workbench-taxii-server USAGE.md](https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md))

กรอบวิเคราะห์ต้นฉบับมีสามชิ้น **Intrusion Kill Chain** ของ Lockheed Martin ("Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains", Hutchins, Cloppert, Amin; PDF สร้าง 24 ต.ค. 2010; ตีพิมพ์ใน *Leading Issues in Information Warfare & Security Research* vol. 1, 2011) นิยามเจ็ดเฟสจบที่ "Actions on Objectives", Courses of Action Matrix (Detect/Deny/Disrupt/Degrade/Deceive/Destroy ต่อเฟส) และ indicator สามชนิด: Atomic (IP, email, vulnerability ID), Computed (hash, regex) และ Behavioral ([Lockheed Martin PDF](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf); [connections-qj.org](https://connections-qj.org/article/intelligence-driven-computer-network-defense-informed-analysis-adversary-campaigns-and); [securityandtechnology.org mirror](https://securityandtechnology.org/wp-content/uploads/2020/07/lm-white-paper-intel-driven-defense.pdf)) **Diamond Model** (Caltagirone, Pendergast, Betz, 61 หน้า, 2013, "Approved for public release") นิยาม event เป็นหน่วยอะตอมที่มี core feature สี่อย่าง (adversary, infrastructure, capability, victim) และ meta-feature (Timestamp, Phase, Result, Direction, Methodology, Resources) ที่เชื่อม event เป็น activity thread/group ([DTIC ADA586960](https://apps.dtic.mil/sti/pdfs/ADA586960.pdf); [activeresponse.org mirror](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)) และ **Pyramid of Pain** ของ David J. Bianco (1 มี.ค. 2013, อัปเดต 17 ม.ค. 2014 เพิ่มชั้น Hash Values) ที่เรียงหกชั้นจาก Hash Values, IP Addresses, Domain Names, Network & Host Artifacts, Tools ไปถึง TTPs ด้วยวิทยานิพนธ์ว่ายิ่งตรวจจับชั้นสูง ยิ่งแพงสำหรับฝ่ายโจมตี ([detect-respond.blogspot.com](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)) ด้านธรรมาภิบาล **NIST SP 800-150 "Guide to Cyber Threat Information Sharing"** (Johnson, Badger, Waltermire, Snyder, Skorupka; ต.ค. 2016; DOI 10.6028/NIST.SP.800-150) นิยาม cyber threat information ว่า "any information that can help an organization identify, assess, monitor, and respond to cyber threats" ([NIST CSRC SP 800-150](https://csrc.nist.gov/pubs/sp/800/150/final); [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf)) และ **FIRST TLP 2.0** (มีผล ส.ค. 2022) กำหนด TLP:RED, AMBER, AMBER+STRICT, GREEN, CLEAR พร้อมสีฟอนต์ #FF2B2B/#FFC000/#33FF00/#FFFFFF บนพื้น #000000 ([FIRST TLP](https://www.first.org/tlp/)) วงจรข่าวกรองหกเฟส (Direction, Collection, Processing, Analysis, Dissemination, Feedback) ถูกสอนใน SANS FOR578 "Cyber Threat Intelligence" (Rebekah Brown & Robert M. Lee, GIAC GCTI, 6 วัน, 20 labs; โครง: Requirements/"Traditional Intelligence Cycle" → Intrusion Analysis (Kill Chain, Diamond, ATT&CK) → Collection Sources → Analysis (MISP, biases, ACH) → Dissemination (YARA, STIX/TAXII) → Capstone) และโดย Recorded Future (โพสต์ 15 ม.ค. 2020 อัปเดต 5 ก.พ. 2024) ซึ่งอธิบาย Processing ว่าแปลงข้อมูลเป็นรูปแบบใช้งานได้ "by people or machines, such as extracting indicators for security tools" ([SANS FOR578](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/); [Recorded Future](https://www.recordedfuture.com/blog/threat-intelligence-lifecycle-phases); [CSO Online](https://www.csoonline.com/article/575001/dissecting-threat-intelligence-lifecycle-problems.html/amp/)) หนังสืออ้างอิงคือ *Intelligence-Driven Incident Response*, 2nd ed. (Brown & Roberts, O'Reilly, มิ.ย. 2023) และ *Practical Threat Intelligence and Data-Driven Threat Hunting* (Costa-Gazcón, Packt, ก.พ. 2021) ([O'Reilly IDIR](https://www.oreilly.com/library/view/intelligence-driven-incident-response/9781098120672/); [O'Reilly PTI](https://oreilly.com/library/view/practical-threat-intelligence/9781838556372)) ส่วนรูปแบบเก่าที่ชุมชนยังจัดหมวดไว้คือ STIX 2.0, CybOX, OpenIOC, MAEC, IODEF (RFC 5070), VERIS ([awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)) สำหรับหลักสูตร Python มาตรฐานภาคปฏิบัติคือ STIX 2.1 + TAXII 2.1 เท่านั้น; CybOX ถูกหลอมเข้า STIX 2 เป็น SCO แล้ว

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

ดัชนีชุมชนที่ถูกอ้างมากที่สุดคือ **hslatman/awesome-threat-intelligence** (≈10.8k ดาว, Apache-2.0, สร้าง 21 ธ.ค. 2015, ยังมี commit ปลายปี 2025) ซึ่งจัด MISP, OpenCTI, Yeti, IntelOwl ไว้ใน "Frameworks & Platforms" และ iocextract, IOC Finder, ThreatIngestor, msticpy ใน "Tools" ([awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence); [awesome.ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2Fhslatman%2Fawesome-threat-intelligence)) ชุด library หลักและผู้ดูแลมีดังนี้ (ดาวโดยประมาณ ณ 2026-11-01): **stix2** ("OASIS TC Open Repository: Python APIs for STIX 2", ≈440, `pip install stix2`, ผู้ดูแล Ratliff/Piazza/Dulaunoy/Studer) และ **taxii2-client** (≈129; `taxii2client.v21.Server/ApiRoot/Collection`, `collection.get_objects()`, `add_objects(bundle)`, `as_pages(..., per_request=50)`) ([cti-python-stix2](https://github.com/oasis-open/cti-python-stix2); [cti-taxii-client](https://github.com/oasis-open/cti-taxii-client)); **mitreattack-python** (≈755; `MitreAttackData` รับ path หรือ `stix2.MemoryStore`; `get_techniques(include_subtechniques, remove_revoked_deprecated)`, `get_object_by_attack_id(attack_id, stix_type)` ที่ต้องระบุ type เพราะ ID ไม่ unique ข้ามประเภท, `get_groups_using_technique`) ([mitreattack-python](https://github.com/mitre-attack/mitreattack-python); [docs](https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html)) ขณะที่ **pyattck** ของ Swimlane (≈480, v7.1.1) **ถูก archive เมื่อ 17 มี.ค. 2026** จึงควรสอนเป็น legacy ([pyattck](https://github.com/swimlane/pyattck)); **PyMISP** (≈494, 2-clause BSD, Python 3.10+, extras `pymisp[virustotal,email]`; `examples/last.py` ใช้ `misp.search(publish_timestamp=..., limit=..., page=..., pythonify=True)`) ([PyMISP](https://github.com/MISP/PyMISP); [README](https://pymisp.readthedocs.io/en/latest/README.html); [last.py](https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py)); **pycti** ของ OpenCTI/Filigran ซึ่ง repo เดี่ยว `client-python` (≈145) **ถูก archive 5 ธ.ค. 2025** และย้ายเข้า monorepo ของ opencti โดย `indicator.create(name, pattern_type="stix", pattern="[domain-name:value = '...']", x_opencti_main_observable_type, valid_from, update=True, markingDefinitions=[...])` ([client-python](https://github.com/OpenCTI-Platform/client-python); [OpenCTI docs](https://docs.opencti.io/latest/development/python/)); **OTX-Python-SDK** (≈402; `OTXv2("API_KEY")`, `getsince()/getsince_iter()`, `get_pulse_indicators`, `get_indicator_details_full`; ภายในใช้ urllib3 Retry 5 ครั้ง backoff 1 บน 429/500/502/503/504; README ยังใช้ `print` แบบ Python 2) ([OTX-Python-SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK); [OTXv2.py](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py)); **iocextract** ของ InQuest (≈581; "Defanged Indicator of Compromise (IOC) Extractor"; refang `hxxp://example[.]com`, `[.]`, `(.)`, `_dot_`, `_at_` ฯลฯ; refang ได้เฉพาะ URL/email/IPv4; CLI `iocextract --input FILE --extract-urls --refang`) และ **ioc-finder** ของ fhightower (≈184; grammar-based ไม่ใช่ regex; `find_iocs(text)` คืน dict ที่มี `domains`, `urls` และรองรับ `included_ioc_types`) ([iocextract](https://github.com/InQuest/iocextract); [ioc-finder](https://github.com/fhightower/ioc-finder); [ioc-finder docs](https://hightower.space/ioc-finder/)); **ThreatIngestor** ของ InQuest (≈932; YAML config, source plugin RSS/Twitter/GitHub/sitemap/SQS, operator plugin CSV/MISP/ThreatKB/SQS/MySQL/SQLite) และ fork **iocingestor** ที่ใช้ ioc-finder และเน้น MISP ([ThreatIngestor](https://github.com/InQuest/ThreatIngestor); [iocingestor](https://pypi.org/project/iocingestor/)); **msticpy** ของ MSTIC (≈2.0k; Python 3.10+; README แจ้งว่าการเผยแพร่บน PyPI หยุดชั่วคราวและแนะนำติดตั้งจาก git; TI providers VirusTotal, OTX, RiskIQ, IBM XForce, Sentinel TI, GreyNoise, CrowdSec, AbuseIPDB, ScanMalware, IntSights บวก pseudo-provider TOR exit nodes, Open Page Rank, IP Quality Score, BinaryEdge ตั้งค่าใน `msticpyconfig.yaml` โดยแนะนำ environment variable/Azure Key Vault แทน plaintext; `mp.TILookup().lookup_ioc(...)`/`lookup_iocs(data=df)`) ([msticpy](https://github.com/microsoft/msticpy); [TI Providers](https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html)) แพลตฟอร์มปลายทางที่มีดาวมากกว่า library มาตรฐานคือ **IntelOwl** (≈4.8k, AGPL-3.0, client `pyintelowl`) และ **Yeti** (≈2.0k, Apache-2.0, "Forensics Intelligence platform and pipeline for DFIR teams") ([IntelOwl](https://github.com/intelowlproject/IntelOwl); [Yeti](https://github.com/yeti-platform/yeti)) ผู้ดูแลที่ซ้อนทับกันมาก (CIRCL ทั้งใน stix2 และ MISP; MITRE ทั้งใน stix2 และ mitreattack-python) คือเหตุผลที่ STIX 2.1 ทำงานร่วมกันได้ราบรื่นระหว่าง MISP, OpenCTI และ ATT&CK tooling

ด้าน feed ฟรีและ enrichment API: **abuse.ch** ย้าย URLhaus ไปอยู่หลัง `Auth-Key` ที่ขอฟรีได้จาก https://auth.abuse.ch/ โดย endpoint เช่น `GET https://urlhaus-api.abuse.ch/v1/urls/recent/` (สูงสุด 1000, 3 วันล่าสุด), dump ที่ datalake.abuse.ch รายชั่วโมง/รายวัน, feed regenerate ทุก 5 นาที ("Please do not fetch it more often than every 5 minutes") และ export URL มี key ฝังอยู่ (`.../v2/files/exports/YOUR-AUTH-KEY-HERE/recent.csv`) ขณะที่ **URL เดิม `urlhaus.abuse.ch/downloads/csv_recent/` คืน HTTP 410 Gone เมื่อ 2026-11-01** ([URLhaus API docs](https://urlhaus-api.abuse.ch/); [URLhaus feeds](https://urlhaus.abuse.ch/api/); [csv_recent (410)](https://urlhaus.abuse.ch/downloads/csv_recent/)) Feodo Tracker ยังให้ `ipblocklist_recommended.txt|.json`, `ipblocklist.csv|.json|.txt` และ `ipblocklist_aggressive` (เตือนว่า "will cause false positives") โดยไม่ระบุ auth แต่หน้าเว็บบอกว่า dataset "currently empty" ([Feodo Tracker blocklist](https://feodotracker.abuse.ch/blocklist/)) แค็ตตาล็อก feed default ของ MISP มี **108 feed จาก 52 ผู้ให้บริการ** (18 MISP-format, 47 CSV, 43 free-text) เช่น CIRCL OSINT และ Botvrij.eu พร้อม URL ของ SSLBL, Feodo, URLhaus MISP, ThreatFox MISP ([MISP feeds](https://www.misp-project.org/feeds/)) และข้อจำกัดโควตาที่พบ (VT 4/นาที 500/วัน รีเซ็ต 00:00 UTC; AbuseIPDB 1,000/วัน; MITRE TAXII 50/10 นาที) ทำให้ caching, de-duplication และ batching เป็น "ข้อกำหนดการออกแบบ" ไม่ใช่ optimization ([VT quota consumption](https://docs.virustotal.com/docs/quota-consumption); [VT quotas handled](https://docs.virustotal.com/docs/consumption-quotas-handled)) ไม่พบตัวเลข rate limit ทางการของ OTX ([Graylog community](https://community.graylog.org/t/no-longer-receiving-results-after-using-my-otx-api-key/12267)) ฝั่ง SANS งานใกล้เคียงที่สุดคือ white paper "Automated Network Defense through Threat Intelligence and Knowledge Management" (Christopher O'Brien, ม.ค. 2016) ที่โต้ว่า automation ของ TI "need not be prescriptive nor expensive" ([SANS 36572](https://www.sans.org/white-papers/36572)) และ CTI Summit 2024 มี talk "OSINTer - Automating the CTI heavylifting the open source way!" กับ "Intellimation" ([SANS CTI Summit 2024 summary](https://sans.org/blog/a-visual-summary-of-sans-cti-summit-2024)) ส่วน webcast "Agentic CTI Automation For Fun and Profit" ของ Rebekah Brown และ session ปี 2026 "CTI in the AI Arms Race" ชี้ทิศทาง LLM-assisted pipeline ([SANS webcast](https://www.sans.org/webcasts/agentic-cti-automation-for-fun-and-profit); [SANS 2026 session](https://www.sans.org/webcasts/cti-ai-arms-race-building-resilient-adaptive-intelligence-platforms-2026)) การ map ขั้น automation เข้ากับวงจรข่าวกรอง: Collection = TAXII `added_after` + `as_pages`, OTX `getsince()`, ThreatIngestor source plugin, MISP `search(publish_timestamp=...)`; Processing = refang/extract (iocextract), normalize เป็น STIX 2.1 (stix2); Analysis/enrichment = msticpy TILookup, AbuseIPDB `abuseConfidenceScore`, ATT&CK lookup; Dissemination = ThreatIngestor operator, pycti `indicator.create` พร้อม TLP marking, TAXII `add_objects` Pyramid of Pain บวก taxonomy indicator ของ kill chain ให้เหตุผลกับ pipeline สองชั้น: feed IOC แบบ atomic/computed ราคาถูกสำหรับ block และข่าวกรองเชิงพฤติกรรมที่ map กับ ATT&CK สำหรับ detection engineering

### ตัวอย่างโค้ด

**ตัวอย่าง 5.1 — ดึงและ refang IOC จากรายงานด้วย iocextract** — การเรียกหลักและ defang handling จาก README ของ iocextract ([InQuest/iocextract](https://github.com/InQuest/iocextract)); การรวมสี่ฟังก์ชันเป็น script เดียวเป็น illustrative; `extract_urls(..., refang=True)` คัดจาก README ส่วนอีกสามชื่อฟังก์ชันสะท้อน CLI flag `--extract-ips`, `--extract-hashes`, `--extract-emails`
```python
# pip install iocextract
import iocextract

report = """
Phishing wave 2026-10: hxxp://login-update[.]example[.]com/portal
C2 observed at 185.220.101[.]4 and 45(.)155(.)205(.)233
Dropper md5 d41d8cd98f00b204e9800998ecf8427e sent from billing[@]evil-corp[.]biz
"""

iocs = {
    "urls":   sorted(set(iocextract.extract_urls(report, refang=True))),
    "ips":    sorted(set(iocextract.extract_ips(report, refang=True))),
    "hashes": sorted(set(iocextract.extract_hashes(report))),
    "emails": sorted(set(iocextract.extract_emails(report, refang=True))),
}
for kind, values in iocs.items():
    print(f"{kind:7s} ({len(values)}):")
    for v in values:
        print("   ", v)
```

**ตัวอย่าง 5.2 — grammar-based extraction ด้วย ioc-finder** — การใช้ `find_iocs` จาก [ioc-finder docs](https://hightower.space/ioc-finder/); การพิมพ์ทุก key เป็น illustrative (ยืนยันได้เฉพาะ key `domains` และ `urls`)
```python
# pip install ioc-finder
from ioc_finder import find_iocs

text = ("Actor used T1566.001 to deliver a loader from "
        "https://cdn.bad-example.net/a.exe (sha256 "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855). "
        "Exploited CVE-2024-3400 on 203.0.113.0/24.")

iocs = find_iocs(text)
for key, values in iocs.items():
    if values:                      # skip empty categories
        print(f"{key}: {values}")
# Restrict parsing to a few types to reduce noise:
subset = find_iocs(text, included_ioc_types=["urls", "ipv4s"])
print(subset)
```

**ตัวอย่าง 5.3 — สร้าง STIX 2.1 Indicator, Malware, Relationship และ Bundle** — pattern คัดจาก stix2 "Creating STIX Content" ([stix2 docs](https://stix2.readthedocs.io/en/latest/guide/creating.html)); `valid_from`, `indicator_types` และการเขียนไฟล์เพิ่มเข้ามา (illustrative; `indicator_types` ปรากฏในตัวอย่าง README ของ [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2))
```python
# pip install stix2
from datetime import datetime, timezone
from stix2 import Indicator, Malware, Relationship, Bundle

indicator = Indicator(
    name="File hash for malware variant",
    indicator_types=["malicious-activity"],
    pattern_type="stix",                       # required
    pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",  # required
    valid_from=datetime.now(timezone.utc),     # required; defaults to now if omitted
)
malware = Malware(name="Poison Ivy", is_family=False)   # is_family is required
relationship = Relationship(relationship_type="indicates",
                            source_ref=indicator.id,
                            target_ref=malware.id)
bundle = Bundle(indicator, malware, relationship)       # type/id/spec_version auto-set

print(bundle.serialize(pretty=True))
with open("bundle.json", "w") as fh:
    fh.write(bundle.serialize(pretty=True))
```

**ตัวอย่าง 5.4 — poll MITRE ATT&CK TAXII 2.1 server สาธารณะด้วย taxii2-client** — การใช้ `Collection`/`as_pages` จาก README ของ taxii2-client ([cti-taxii-client](https://github.com/oasis-open/cti-taxii-client)); URL server, API root และ collection ID ของ Enterprise จาก [USAGE.md](https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md); การประกอบเป็น illustrative; เคารพ limit 50 request / 10 นาที
```python
# pip install taxii2-client stix2
from taxii2client.v21 import Server, Collection, as_pages

server = Server("https://attack-taxii.mitre.org/taxii2/")
for root in server.api_roots:
    print("API root:", root.url)

ENTERPRISE = ("https://attack-taxii.mitre.org/api/v21/collections/"
              "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019/")
collection = Collection(ENTERPRISE)
print("Collection:", collection.title)

# Pull only attack-pattern objects, 100 per page (match[type] + limit per TAXII 2.1)
techniques = []
for envelope in as_pages(collection.get_objects, per_request=100, type="attack-pattern"):
    techniques.extend(envelope.get("objects", []))
    if len(techniques) >= 300:        # stay well under 50 req / 10 min
        break
print(len(techniques), "attack-pattern objects fetched")
for t in techniques[:5]:
    ext_id = next((r["external_id"] for r in t.get("external_references", [])
                   if r.get("source_name") == "mitre-attack"), "?")
    print(ext_id, "-", t["name"])
```

**ตัวอย่าง 5.5 — ค้นหา event/attribute ล่าสุดใน MISP ด้วย PyMISP** — constructor และ `search(publish_timestamp=..., limit=..., page=..., pythonify=True)` จาก [PyMISP examples/last.py](https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py); ตำแหน่ง API key จาก [PyMISP README](https://pymisp.readthedocs.io/en/latest/README.html); การวน `event.attributes` และ `controller="attributes"` เป็น illustrative
```python
# pip3 install pymisp
import os
from pymisp import PyMISP

misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"],
              ssl=True)                      # ssl=False only for lab instances

# Events published in the last 24 hours, as PyMISP objects
events = misp.search(publish_timestamp="24h", limit=20, page=1, pythonify=True)
print(len(events), "events")
for ev in events:
    print(ev.id, ev.info, ev.date)
    for attr in ev.attributes:
        if attr.to_ids:                      # only detection-grade attributes
            print("   ", attr.type, attr.value, attr.category)

# Attribute-level search for a single value (illustrative)
hits = misp.search(controller="attributes", value="185.220.101.4", pythonify=True)
for a in hits:
    print("seen in event", a.event_id, "as", a.type)
```

**ตัวอย่าง 5.6 — ดึง OTX pulse ที่แก้ไขตั้งแต่ timestamp แล้ว flatten indicator** — `OTXv2("API_KEY")`, `get_pulse_indicators`, `IndicatorTypes` จาก [OTX SDK README](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/README.md); ชื่อเมธอด `getsince_iter` จาก [OTXv2.py](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py); การประกอบเป็น illustrative และแก้ `print` จาก Python 2
```python
# pip install OTXv2
import os
from datetime import datetime, timedelta, timezone
from OTXv2 import OTXv2, IndicatorTypes

otx = OTXv2(os.environ["OTX_API_KEY"])      # free key from otx.alienvault.com
since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

rows = []
for pulse in otx.getsince_iter(since, limit=50):
    for ind in pulse.get("indicators", []):
        rows.append({
            "pulse": pulse["name"], "tlp": pulse.get("TLP"),
            "type": ind["type"], "indicator": ind["indicator"],
        })
print(len(rows), "indicators from pulses modified in the last 24h")

# Enrich one domain with OTX's own context
detail = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, "example.com")
general = detail.get("general", {})
print(general.get("pulse_info", {}).get("count"), "pulses reference example.com")
```

**ตัวอย่าง 5.7 — enrich IP ด้วย AbuseIPDB และ map technique เข้า ATT&CK ด้วย mitreattack-python** — รูป request/header/field ของ AbuseIPDB จาก [AbuseIPDB API docs](https://docs.abuseipdb.com/); `MitreAttackData` จาก [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html); ตำแหน่ง STIX 2.1 JSON จาก [attack-stix-data](https://github.com/mitre-attack/attack-stix-data); การรวมและ caching เป็น illustrative; Standard plan 1,000 check/วัน
```python
# pip install requests mitreattack-python
import os, json, time, functools, requests
from mitreattack.stix20 import MitreAttackData

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Accept": "application/json", "Key": os.environ["ABUSEIPDB_KEY"]}

@functools.lru_cache(maxsize=4096)            # never re-spend quota on the same IP
def check_ip(ip, max_age=90):
    r = requests.get(ABUSE_URL, headers=HEADERS,
                     params={"ipAddress": ip, "maxAgeInDays": max_age}, timeout=15)
    if r.status_code == 429:
        raise RuntimeError("AbuseIPDB daily quota exceeded")
    d = r.json()["data"]
    return {k: d.get(k) for k in ("ipAddress", "abuseConfidenceScore",
                                  "totalReports", "countryCode", "isp", "usageType")}

for ip in ["118.25.6.39", "185.220.101.4"]:
    print(json.dumps(check_ip(ip), indent=1)); time.sleep(1)

# ATT&CK: download https://raw.githubusercontent.com/mitre-attack/attack-stix-data/
#         master/enterprise-attack/enterprise-attack.json first
attack = MitreAttackData("enterprise-attack.json")
t = attack.get_object_by_attack_id("T1071.001", "attack-pattern")   # Web Protocols C2
print(attack.get_attack_id(t.id), t.name)
for entry in attack.get_groups_using_technique(t.id)[:5]:
    print("  used by", entry["object"].name)
```

**ตัวอย่าง 5.8 — ingest feed ของ abuse.ch ด้วย pandas และ de-duplicate indicator** — URL feed และการ regenerate ทุก 5 นาทีจาก [Feodo Tracker blocklist](https://feodotracker.abuse.ch/blocklist/); รูป export URL ที่มี Auth-Key จาก [URLhaus API page](https://urlhaus.abuse.ch/api/); การจัดการคอลัมน์เป็น illustrative เพราะยืนยัน CSV header ไม่ได้ จึงค้นหา column ตอน runtime; อย่า fetch บ่อยกว่าทุก 5 นาที
```python
# pip install pandas requests
import io, os, requests, pandas as pd

def fetch_abusech_csv(url):
    r = requests.get(url, timeout=30); r.raise_for_status()
    # abuse.ch CSVs carry '#' comment lines; the header row is itself commented
    lines = [l.lstrip("# ") for l in r.text.splitlines()
             if l.strip() and not l.startswith("##") and "abuse.ch" not in l]
    return pd.read_csv(io.StringIO("\n".join(lines)))

feodo = fetch_abusech_csv("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
print("Feodo columns:", list(feodo.columns)); print(len(feodo), "rows")

# URLhaus now requires a free Auth-Key embedded in the export URL
key = os.environ.get("ABUSECH_AUTH_KEY")
if key:
    urlhaus = fetch_abusech_csv(
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv")
    print("URLhaus columns:", list(urlhaus.columns))

# Normalise to one indicator table and de-duplicate
ip_col = next(c for c in feodo.columns if "ip" in c.lower())
ind = pd.DataFrame({"indicator": feodo[ip_col].astype(str).str.strip(),
                    "type": "ipv4-addr", "source": "feodotracker"})
before = len(ind)
ind = ind.drop_duplicates(subset=["indicator", "type"]).reset_index(drop=True)
print(f"{before} -> {len(ind)} after de-duplication")
ind.to_csv("indicators_dedup.csv", index=False)
```

**ตัวอย่าง 5.9 — สร้าง indicator ที่มี TLP marking ใน OpenCTI ด้วย pycti** — การติดตั้ง, constructor และ `indicator.create(...)` จาก [OpenCTI docs: Python library](https://docs.opencti.io/latest/development/python/); การ lookup marking เป็น illustrative (ตัวอย่างในเอกสารใช้ `TLP_GREEN_CTI["id"]` ที่ดึงไว้ก่อน)
```python
# pip3 install pycti
import os
from datetime import datetime, timezone
from pycti import OpenCTIApiClient

client = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"])

tlp_green = client.marking_definition.read(
    filters={"mode": "and", "filterGroups": [],
             "filters": [{"key": "definition", "values": ["TLP:GREEN"]}]})

indicator = client.indicator.create(
    name="C2 server of the new campaign",
    description="This is the C2 server of the campaign",
    pattern_type="stix",
    pattern="[domain-name:value = 'www.5z8.info']",
    x_opencti_main_observable_type="Domain-Name",
    valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    update=True,
    markingDefinitions=[tlp_green["id"]] if tlp_green else [],
)
print("created", indicator["standard_id"])
```

**ตัวอย่าง 5.10 — multi-provider enrichment ใน notebook ด้วย msticpy TILookup** — `TILookup`, `lookup_ioc`, `lookup_iocs(data=df)`, `result_to_df` และโครง `msticpyconfig.yaml` จาก [msticpy docs: TI Providers](https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html); ชื่อคอลัมน์ DataFrame เป็น illustrative
```python
# pip install msticpy   (or from GitHub while PyPI publishing is paused)
# msticpyconfig.yaml:
# TIProviders:
#   OTX:        {Args: {AuthKey: {EnvironmentVar: OTX_API_KEY}}, Primary: True, Provider: "OTX"}
#   AbuseIPDB:  {Args: {AuthKey: {EnvironmentVar: ABUSEIPDB_KEY}}, Primary: True, Provider: "AbuseIPDB"}
import pandas as pd
import msticpy as mp

mp.init_notebook()
ti = mp.TILookup()
print(ti.provider_status)                     # which providers loaded

single = mp.TILookup.result_to_df(ti.lookup_ioc("162.244.80.235"))
print(single[["Provider", "Severity", "Details"]])

df = pd.DataFrame({"IoC": ["162.244.80.235", "38.75.137.9"],
                   "IoCType": ["ipv4", "ipv4"]})
results = ti.lookup_iocs(data=df, ioc_col="IoC", ioc_type_col="IoCType")
print(results.groupby("Provider")["Severity"].value_counts())
```

ตัวอย่าง 5.1, 5.3, 5.4, 5.7 และ 5.8 ไม่ต้องใช้บัญชีแบบเสียเงิน (key ของ abuse.ch และ AbuseIPDB standard tier ฟรี; ATT&CK TAXII ไม่ต้อง auth) จึงเหมาะกับ lab ส่วน 5.5, 5.6, 5.9, 5.10 ต้องมี MISP/OpenCTI instance หรือ API key และควรเตือนนักเรียนว่า README ทางการของ OTX และ AbuseIPDB ยังเป็น Python 2

### เอกสารอ้างอิงประจำหัวข้อ

- OASIS STIX 2.1 — https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- OASIS TAXII 2.1 — https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
- stix2 docs: Creating STIX Content — https://stix2.readthedocs.io/en/latest/guide/creating.html
- attack.mitre.org: ATT&CK Data & Tools — https://attack.mitre.org/resources/attack-data-and-tools/
- mitre-attack/attack-stix-data — https://github.com/mitre-attack/attack-stix-data
- attack-workbench-taxii-server USAGE.md — https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md
- Lockheed Martin: Intelligence-Driven Computer Network Defense — https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf
- connections-qj.org listing — https://connections-qj.org/article/intelligence-driven-computer-network-defense-informed-analysis-adversary-campaigns-and
- BibSonomy entry — https://bibsonomy.org/bibtex/ce281b592eb8dc68cb35e45ff801bd3c
- securityandtechnology.org mirror — https://securityandtechnology.org/wp-content/uploads/2020/07/lm-white-paper-intel-driven-defense.pdf
- Diamond Model (DTIC ADA586960) — https://apps.dtic.mil/sti/pdfs/ADA586960.pdf
- Diamond Model (activeresponse.org mirror) — https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- David Bianco: The Pyramid of Pain — https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Sqrrl: A Framework for Cyber Threat Hunting Part 1 — https://www.threathunting.net/files/A%20Framework%20for%20Cyber%20Threat%20Hunting%20Part%201_%20The%20Pyramid%20of%20Pain%20_%20Sqrrl.pdf
- Bianco Speaker Deck — https://speakerdeck.com/davidjbianco/the-pyramid-of-pain-intel-driven-detection-and-response-to-increase-your-adversarys-cost-of-operations
- NIST SP 800-150 — https://csrc.nist.gov/pubs/sp/800/150/final
- NIST SP 800-150 PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf
- FIRST TLP — https://www.first.org/tlp/
- SANS FOR578 — https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/
- Recorded Future: 6 Phases of the Threat Intelligence Lifecycle — https://www.recordedfuture.com/blog/threat-intelligence-lifecycle-phases
- Recorded Future Intelligence Handbook 4th ed. — https://go.recordedfuture.com/hubfs/ebooks/intelligence-handbook-fourth-edition.pdf?hsLang=en
- CSO Online: threat intelligence lifecycle problems — https://www.csoonline.com/article/575001/dissecting-threat-intelligence-lifecycle-problems.html/amp/
- O'Reilly: Intelligence-Driven Incident Response 2e — https://www.oreilly.com/library/view/intelligence-driven-incident-response/9781098120672/
- Heidelberg library catalogue — https://katalog.ub.uni-heidelberg.de/titel/69152504
- wristers.nl listing — https://www.wristers.nl/boek/9781098120689
- O'Reilly: Practical Threat Intelligence — https://oreilly.com/library/view/practical-threat-intelligence/9781838556372
- Packt: Practical Threat Intelligence — https://packtpub.com/product/practical-threat-intelligence-and-data-driven-threat-hunting/9781838556372
- Lehmanns e-book listing — https://www.lehmanns.de/shop/mathematik-informatik/55989559-9781838551636-practical-threat-intelligence-and-data-driven-threat-hunting
- hslatman/awesome-threat-intelligence — https://github.com/hslatman/awesome-threat-intelligence
- awesome.ecosyste.ms (awesome-threat-intelligence) — https://awesome.ecosyste.ms/projects/github.com%2Fhslatman%2Fawesome-threat-intelligence
- oasis-open/cti-python-stix2 — https://github.com/oasis-open/cti-python-stix2
- oasis-open/cti-taxii-client — https://github.com/oasis-open/cti-taxii-client
- mitre-attack/mitreattack-python — https://github.com/mitre-attack/mitreattack-python
- mitreattack-python docs: MitreAttackData — https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html
- swimlane/pyattck (archived) — https://github.com/swimlane/pyattck
- MISP/PyMISP — https://github.com/MISP/PyMISP
- PyMISP README — https://pymisp.readthedocs.io/en/latest/README.html
- PyMISP examples/last.py — https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py
- OpenCTI-Platform/client-python (archived) — https://github.com/OpenCTI-Platform/client-python
- OpenCTI docs: Python library — https://docs.opencti.io/latest/development/python/
- AlienVault-OTX/OTX-Python-SDK — https://github.com/AlienVault-OTX/OTX-Python-SDK
- OTX SDK README — https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/README.md
- OTXv2.py source — https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py
- InQuest/iocextract — https://github.com/InQuest/iocextract
- fhightower/ioc-finder — https://github.com/fhightower/ioc-finder
- ioc-finder docs — https://hightower.space/ioc-finder/
- InQuest/ThreatIngestor — https://github.com/InQuest/ThreatIngestor
- PyPI iocingestor — https://pypi.org/project/iocingestor/
- microsoft/msticpy — https://github.com/microsoft/msticpy
- msticpy docs — https://msticpy.readthedocs.io/en/latest/
- msticpy docs: TI Providers — https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html
- intelowlproject/IntelOwl — https://github.com/intelowlproject/IntelOwl
- gittrend.io IntelOwl — https://gittrend.io/repo/intelowlproject/IntelOwl
- yeti-platform/yeti — https://github.com/yeti-platform/yeti
- URLhaus API docs — https://urlhaus-api.abuse.ch/
- URLhaus API/feeds page — https://urlhaus.abuse.ch/api/
- URLhaus csv_recent (410 Gone) — https://urlhaus.abuse.ch/downloads/csv_recent/
- Feodo Tracker blocklist — https://feodotracker.abuse.ch/blocklist/
- MISP feeds — https://www.misp-project.org/feeds/
- Graylog community (OTX rate limit) — https://community.graylog.org/t/no-longer-receiving-results-after-using-my-otx-api-key/12267
- AbuseIPDB API docs — https://docs.abuseipdb.com/
- VirusTotal: Public vs Premium API — https://docs.virustotal.com/reference/public-vs-premium-api
- VirusTotal: quota consumption — https://docs.virustotal.com/docs/quota-consumption
- VirusTotal: consumption quotas handled — https://docs.virustotal.com/docs/consumption-quotas-handled
- SANS white paper 36572 (O'Brien 2016) — https://www.sans.org/white-papers/36572
- GIAC research paper 36572 — https://www.giac.org/research-papers/36572
- SANS CTI Summit 2024 visual summary — https://sans.org/blog/a-visual-summary-of-sans-cti-summit-2024
- SANS CTI Summit 2025 visual summary — https://www.sans.org/blog/a-visual-summary-of-sans-cti-summit-2025
- SANS Threat Analysis Rundown CTI Summit preview — https://www.sans.org/blog/sans-threat-analysis-rundown-in-review-sans-cti-summit-preview
- GovEvents CTI Summit 2025 — https://govevents.com/event/9358
- SANS webcast: Agentic CTI Automation For Fun and Profit — https://www.sans.org/webcasts/agentic-cti-automation-for-fun-and-profit
- GovEvents: SANS 2025 CTI Survey webcast — https://govevents.com/pub/83651/cc54a
- SANS webcast: CTI in the AI Arms Race 2026 — https://www.sans.org/webcasts/cti-ai-arms-race-building-resilient-adaptive-intelligence-platforms-2026
- PyCon US 2022: Python for Threat Intelligence — https://pycon-archive.python.org/2022/schedule/presentation/43/index.html
- Torq blog: threat intelligence tools — https://torq.io/blog/threat-intelligence-tools/
- Tines blog: Pulsedive and Tines — https://www.tines.com/blog/streamlining-threat-intelligence-with-pulsedive-and-tines

---

## Module 6 — Security Automation Project

## 6. Security Workflow Automation: Gartner ประกาศ SOAR "obsolete" แต่ Python ยังเป็นภาษากลางของทุก playbook runtime

### แหล่งต้นฉบับ

คำว่า SOAR มีประวัติสามช่วง Gartner ได้รับเครดิตว่าบัญญัติ "security orchestration, automation and response" ราวเมษายน 2017 ในฐานะการบรรจบของสามหมวดผลิตภัณฑ์ คือ SIRP, SOA และ TIP โดยนิยามยุค 2022 ที่ถูกอ้างคือ "Solutions that combine incident response, orchestration and automation, and threat intelligence (TI) management capabilities in a single platform" ขณะที่ TechTarget ระบุว่าตัวย่อนี้ Gartner ใช้ครั้งแรกปี 2015 ในความหมาย "security operations, analytics and reporting" ก่อนนิยามใหม่ปี 2017 และรายงานต้นฉบับชื่อ "Innovation Insight for Security Orchestration, Automation and Response" ([D3 Security](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/); [TechTarget SOAR](https://www.techtarget.com/searchsecurity/definition/SOAR); [Swimlane](https://swimlane.com/?p=9805); [Solutions Review](https://solutionsreview.com/security-information-event-management/wp-json/wp/v2/posts/3178)) จุดหักเหคือ **Gartner "Hype Cycle for Security Operations, 2024" (29 ก.ค. 2024) จัด SOAR เป็น "obsolete before plateau"** และลด benefit rating เป็น "moderate" โดยอ้างทรัพยากรพัฒนาที่ต้องใช้ดูแล SOAR ซึ่ง Dark Reading รายงานว่าป้ายนี้ "created a kerfuffle" และ Gartner Peer Insights ติดป้ายหมวด SOAR ว่า "transitioning to Security Information and Event Management" (ผู้ผลิตบางรายระบุว่าป้ายมาจาก ITSM Hype Cycle 17 มิ.ย. 2024 แทน; เอกสาร Gartner เองอยู่หลัง paywall) ([Netenrich](https://netenrich.com/blog/a-strategic-perspective-of-gartner-hype-cycle-for-security-operations-2024); [Dark Reading](https://darkreading.com/cybersecurity-operations/soar-is-dead-long-live-soar); [Torq](https://torq.io/?p=9180); [Blink Ops](https://www.blinkops.com/blog/gartner-says-goodbye-to-soar-whats-next-for-security-operations); [Intezer](https://intezer.com/guides/soar-security/gartner-view-on-soar); [Gartner Hype Cycle abstract](https://www.gartner.com/en/documents/5622491); [Gartner glossary](https://www.gartner.com/en/information-technology/glossary/security-orchestration-automation-response-soar); [TechRepublic 2023 Market Guide](https://www.techrepublic.com/resource-library/whitepapers/2023-gartner-market-guide-for-security-orchestration-automation-and-response-solutions/))

กรอบ IR/SOC ที่เป็นทางการมีสี่ชิ้น **NIST SP 800-61 Rev. 3** "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile" (final 3 เม.ย. 2025; Nelson, Rekhi, Souppaya, Scarfone; แทน Rev. 2 ปี 2012; DOI 10.6028/NIST.SP.800-61r3) จัดโครงตาม CSF 2.0 Functions (Govern, Identify, Protect, Detect, Respond, Recover) แทนวงจรสี่เฟสของ Rev. 2 และ abstract ระบุว่าช่วย "prepare for incident responses, reduce the number and impact of incidents that occur, and improve the efficiency and effectiveness of their incident detection, response, and recovery activities" ([NIST CSRC](https://csrc.nist.gov/pubs/sp/800/61/r3/final); [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf); [NIST news](https://nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations); [Linford & Co](https://linfordco.com/blog/nist-sp-800-61/); [Tandem](https://tandem.app/blog/updated-nist-incident-response-guidance-sp-800-61-rev-3)) **SANS "Incident Handler's Handbook"** (Patrick Kral, 21 ก.พ. 2012) จำกัดขอบเขตที่ "the six phases of the incident handling process" และนิยาม incident (อ้าง Bejtlich 2005) ว่า "any violation of policy, law, or unacceptable act that involves information assets" ([SANS 33901](https://www.sans.org/white-papers/33901/)) **MITRE "11 Strategies of a World-Class Cybersecurity Operations Center"** (2nd ed., Knerler, Parker, Zimmerman; มี.ค. 2022; ดาวน์โหลดฟรี ~452 หน้า) ซึ่งเรียก SOAR ว่า "indispensable capability" ตามบทวิจารณ์ของผู้ผลิต ([MITRE publication](https://www.mitre.org/news-insights/publication/11-strategies-world-class-cybersecurity-operations-center); [mitre.org/11strategies](https://www.mitre.org/11strategies); [BusinessWire](https://www.businesswire.com/news/home/20220329005299/en/MITRE-Publishes-11-Strategies-of-a-World-Class-Cybersecurity-Operations-Center); [D3 on MITRE](https://d3security.com/blog/why-mitre-calls-soar-indispensable-in-its-latest-book); [RSAC podcast](https://www.rsaconference.com/library/podcast/turn-it-up-to-11-csoc)) และสำหรับ playbook แบบ machine-readable **OASIS CACAO Security Playbooks v2.0** (Committee Specification 01, 27 พ.ย. 2023; บรรณาธิการ Bret Jordan, Allan Thomson; สนับสนุนโดย Cisco, Cyware, IBM, US NIST) นิยาม playbook ว่า "a workflow for security orchestration containing a set of steps" ด้วย `playbook-type-ov` (notification, detection, investigation, prevention, mitigation, remediation, attack, engagement), `workflow-step-type-enum` (start, end, action, playbook-action, parallel, if-condition, while-condition, switch-condition) และ command type (manual, bash, caldera, elastic, http-api, jupyter, kestrel, openc2-http, powershell, ssh, sigma, yara) serialize เป็น JSON (RFC 8259) ลายเซ็นด้วย JCS (RFC 8785) และใช้ STIX 2.1 Identity/Relationship ซ้ำ ([OASIS CACAO v2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html); [CS01 announcement](https://www.oasis-open.org/?p=10546); [approval release](https://www.oasis-open.org/?p=10491)) ฐานปรัชญาของการแจ้งเตือนคือ Google SRE Book ch. 6 "Monitoring Distributed Systems" (2017): "Every page should be actionable", "Every page response should require intelligence", "Pages should be about a novel problem or an event that hasn't been seen before" และคำถามทดสอบ rule "Does this rule detect an otherwise undetected condition that is urgent, actionable, and actively or imminently user-visible?" ([SRE Book ch.6](https://sre.google/sre-book/monitoring-distributed-systems/)) นัยต่อหลักสูตร: NIST 800-61r3 ทำให้วงจรสี่เฟสเป็น "legacy framing" ขณะที่ PICERL หกเฟสของ SANS ยังเป็นโมเดลปฏิบัติที่สอนกันมากที่สุด และคำศัพท์ step/command ของ CACAO (if-condition, parallel, http-api, sigma, yara) เป็นภาษากลางที่ดีสำหรับสอนโครงสร้าง playbook ก่อนแตะ editor ของผู้ผลิต

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

**Python คือภาษากลางของการขยาย SOAR** ทุกแพลตฟอร์มในขอบเขตมี entry point Python ที่มีเอกสาร โดยรูปร่างเดียวกันคือ "ฟังก์ชัน Python ใน sandbox ที่รับ dict input และคืน dict/result object" ต่างกันเพียง entry guard และ result wrapper จำนวนดาวจาก GitHub REST API (`stargazers_count`, 2026-11-01): **n8n** 209,280 ("Fair-code workflow automation platform with native AI capabilities"; Code node รัน JavaScript/Python, native Python stable ตั้งแต่ n8n 2 โดย Pyodide ถูกถอดใน 2.0, เข้าถึง `_items`/`_item` เท่านั้น, ทำ HTTP/filesystem ไม่ได้ และ import Python ไม่ได้บน Cloud) ([n8n-io/n8n](https://github.com/n8n-io/n8n); [docs.n8n.io Code node](https://docs.n8n.io/code/code-node/)); **Wazuh** 17,528 (custom active response script อ่าน JSON หนึ่งบรรทัดจาก stdin, dispatch ตาม `command` add/delete ด้วยค่าคงที่ `ADD_COMMAND=0`, `DELETE_COMMAND=1`, `CONTINUE_COMMAND=2`, `ABORT_COMMAND=3`, ส่ง `check_keys` แล้วดำเนินต่อเมื่อได้ `continue`, log ไป `/var/ossec/logs/active-responses.log`, ผูกใน ossec.conf ด้วย `<command>`/`<active-response>` เช่น `<rules_id>503</rules_id><timeout>60</timeout>`) ([wazuh/wazuh](https://github.com/wazuh/wazuh); [Wazuh custom AR docs](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)); **Sigma** 11,383 ("more than 3000 detection rules", folder rules/, rules-threat-hunting/, rules-emerging-threats/; DRL 1.1; เริ่มปี 2017 โดย Florian Roth และ Thomas Patzke) ([SigmaHQ/sigma](https://github.com/SigmaHQ/sigma); [CSO Online Sigma](https://www.csoonline.com/article/572973/sigma-rules-explained-when-and-how-to-use-them-to-log-events.html)); **awesome-incident-response** 9,521 (อัปเดต ต.ค. 2026) ([meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response)); **StackStorm** 6,554 ("IFTTT for Ops"; Python action = YAML metadata `runner_type: "python-script"` + class ที่ subclass `st2common.runners.base_action.Action` และคืน `(True, result)`/`(False, result)`) ([StackStorm/st2](https://github.com/StackStorm/st2); [docs.stackstorm.com/actions](https://docs.stackstorm.com/actions.html)); **Security Onion** 4,961 ([securityonion](https://github.com/Security-Onion-Solutions/securityonion)); **TheHive** 3,950 **แต่ repo สาธารณะถูก archive (push ล่าสุด 25 ก.ค. 2025) และ TheHive ปัจจุบันเป็นเชิงพาณิชย์ผ่าน StrangeBee** โดย thehive4py (244 ดาว) เป็น "the de facto Python API client of TheHive" (`TheHiveApi(url=..., apikey=...)`; `hive.alert.create({...})` ที่ต้องมี `type`, `source`, `sourceRef`, `title`, `description`; `hive.alert.promote_to_case(alert_id=...)`; `hive.alert.find(filters=Eq(...) | Eq(...))`) ([TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive); [TheHive4py](https://github.com/TheHive-Project/TheHive4py); [thehive4py docs](https://thehive-project.github.io/TheHive4py/latest/); [alert examples](https://thehive-project.github.io/TheHive4py/latest/examples/alert/); [docs.strangebee.com](https://docs.strangebee.com/)); **elastic/detection-rules** 2,946 (rule เป็น TOML, Python 3.12+, CLI `python -m detection_rules`; Elastic Security มี rule type Custom query, EQL, Threshold, Indicator match, New terms, ES|QL, ML และเก็บ alert ใน `.alerts-security.alerts-<space-id>` ด้วย field `kibana.alert.*`) ([detection-rules](https://github.com/elastic/detection-rules); [Create a detection rule](https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule); [alert schema 8.18](https://www.elastic.co/guide/en/security/8.18/alert-schema.html)); **Shuffle** 2,466 ("A general purpose security automation platform"; core AGPLv3, app/SDK MIT; สามวิธีสร้าง app: App Creator (OpenAPI), AI, และ Python "which makes it possible to connect literally any tool" โดย "Always prioritize using the App Creator when applicable"; Python app subclass `AppBase` กับ `__version__`, `app_name` ที่ต้องตรง `name` ใน api.yaml และ `__init__(self, redis, logger, console_logger=None)`; apps repo 130 ดาวมี 2500+ app generate จาก OpenAPI; `shuffle-sdk` บน PyPI) ([Shuffle/Shuffle](https://github.com/Shuffle/Shuffle); [python-apps](https://github.com/Shuffle/python-apps); [shuffle-docs apps.md](https://github.com/Shuffle/shuffle-docs/blob/master/docs/apps.md); [shuffler.io/docs/apps](https://shuffler.io/docs/apps); [shuffle-sdk PyPI](https://pypi.org/project/shuffle-sdk/0.0.8/)); **Cortex** 1,640 (analyzer เขียนได้ "in any programming language that is supported by Linux" แต่ "The Cortexutils library is in Python. It greatly facilitates analyzer development"; ต้องมี JSON service file และ requirements.txt; output `success: false` เมื่อผิดพลาด; summary สีตาม verdict safe/info/suspicious/malicious; เมธอด `get_param`, `get_data`, `report`, `summary`, `build_taxonomy`) กับ Cortex-Analyzers 494 และ cortexutils 8 ([Cortex](https://github.com/TheHive-Project/Cortex); [Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers); [cortexutils](https://github.com/TheHive-Project/cortexutils); [StrangeBee: How to Write an Analyzer](https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/); [TheHive blog](https://blog.thehive-project.org/tag/misp/page/4); [DeepWiki guide](https://deepwiki.com/TheHive-Project/Cortex-Analyzers/6-developer-guide)); **demisto/content (Cortex XSOAR)** 1,322 และ demisto-sdk 90 (script "written in Python or Javascript"; รันใน docker; convention `import demistomock as demisto`, `from CommonServerPython import *`, `main()` ที่ dispatch บน `demisto.command()`, `CommandResults(outputs_prefix, outputs_key_field, outputs, readable_output)` → `return_results()`, `return_error()`, `demisto.executeCommand(...)`, และ entry guard `if __name__ in ("__main__", "__builtin__", "builtins")`) ([demisto/content](https://github.com/demisto/content); [demisto-sdk](https://github.com/demisto/demisto-sdk); [XSOAR Script Code Snippets](https://cortex-docs.paloaltonetworks.com/python-development-quick-start-guide/cortex-xsoar-python-development-quick-start-guide/script-code-snippets); [Code Conventions](https://xsoar.pan.dev/docs/integrations/code-conventions); [Common Server Python](https://xsoar.pan.dev/docs/reference/api/common-server-python)); **Awesome-SOAR** 1,007 (push ล่าสุด ส.ค. 2024 จึงเป็นดัชนีประวัติศาสตร์) ([Awesome-SOAR](https://github.com/correlatedsecurity/Awesome-SOAR)); **ocsf-schema** 910; **SOCFortress CoPilot** 538 ([CoPilot](https://github.com/socfortress/CoPilot)) ฝั่งเชิงพาณิชย์ **Splunk SOAR** (เดิม Phantom) ทุก playbook นิยาม `on_start(container)` และ `on_finish(container, summary)`, `phantom.act()` เรียกได้จาก `on_start()` หรือ callback เท่านั้นและ "is not supported from within a custom function", หลาย `phantom.act()` ในฟังก์ชันเดียวรันแบบ parallel, action ที่ต้องมีผู้อนุมัติจะไม่รันจนได้รับอนุมัติ, และ tutorial ใช้ `"geolocate ip"` กับ `callback=geolocate_ip_cb` เพราะ action เป็น asynchronous ([Splunk SOAR Playbook API](https://help.splunk.com/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api); [Tutorial](https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial/playbook-api-tutorial/tutorial-create-a-simple-playbook-in-splunk-soar-cloud); [On-prem tutorial](https://help.splunk.com/en/splunk-soar/soar-on-premises/python-playbook-tutorial); [legacy custom function block](https://help.splunk.com/en/splunk-soar/soar-on-premises/build-playbooks/6.3.0/use-the-classic-playbook-editor-to-create-and-view-playbooks-to-automate-analyst-workflows/add-custom-code-to-your-splunk-soar-on-premises-playbook-with-the-legacy-custom-function-block-using-the-classic-playbook-editor)) และ **Tines** "Run Python Script" (input ผ่าน `input["<<object_name>>"]`, return value ต้องเป็น JSON object, dependency แบบ requirements.txt, timeout default 10 s สูงสุด 25 s, เดิมเฉพาะ python3.9 และ cloud-only; Tines Tunnel ให้รันในเครือข่ายตนเอง) ([Tines Run Python Script](https://www.tines.com/docs/actions/templates/templates/frequently-used-templates/run-python-script/); [Tines Tunnel](https://www.tines.com/stories/whats-new/execute-python-code-via-tines-tunnel/); [Tines how-to](https://tines.com/blog/python-tines-how-to-guide)) stack ที่เป็นโอเพนซอร์สทั้งหมดและ Python-first สำหรับ Module 6 คือ Wazuh/Elastic (detection) → webhook → FastAPI normalizer (OCSF) → dedupe/score → TheHive alert ผ่าน thehive4py → Cortex analyzer enrichment → Shuffle หรือ n8n workflow → Jira/TheHive case ซึ่งทุกข้อต่อมี Python API ทางการ และดาว 200k+ ของ n8n บวกท่าที "SOAR is obsolete" ของ Gartner แนะว่าหลักสูตรควรสอน workflow engine ทั่วไป (n8n, StackStorm) เคียงข้าง SOAR เฉพาะทาง และควรเป้าหมายไปที่ TheHive 5 (StrangeBee) กับ thehive4py 2.x ไม่ใช่ clone repo ที่ archive แล้ว

### ตัวอย่างโค้ด

**ตัวอย่าง 6.1 — สร้าง TheHive alert พร้อม observables แล้ว promote เป็น case (thehive4py)** — ดัดแปลงจาก [thehive4py alert examples](https://thehive-project.github.io/TheHive4py/latest/examples/alert/) และ [quickstart](https://thehive-project.github.io/TheHive4py/latest/); `pip install thehive4py`
```python
from thehive4py import TheHiveApi
from thehive4py.query.filters import Eq

hive = TheHiveApi(url="http://localhost:9000", apikey="h1v3b33")

alert = hive.alert.create(
    alert={
        "type": "siem",                      # required
        "source": "elastic-security",        # required
        "sourceRef": "rule-1234:host-77:1762000000",  # required, unique dedupe ref
        "title": "Suspicious PowerShell download cradle",
        "description": "EQL rule matched on host-77",
        "severity": 3,                       # 1 low .. 4 critical
        "tags": ["powershell", "t1059.001"],
        "observables": [
            {"dataType": "ip", "data": "1.2.3.4"},
            {"dataType": "domain", "data": "example.com"},
        ],
    }
)
print("alert id:", alert["_id"])

# Escalate: promote the alert to a case
case = hive.alert.promote_to_case(alert_id=alert["_id"])
print("case number:", case["number"])

# Find all open alerts tagged powershell
for a in hive.alert.find(filters=Eq(field="tags", value="powershell")):
    print(a["title"], a["status"])
```

**ตัวอย่าง 6.2 — Cortex analyzer ขั้นต่ำด้วย cortexutils** — *ILLUSTRATIVE, อิงจาก documented API*: ชื่อเมธอดจาก [StrangeBee, How to Write and Submit an Analyzer](https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/), [cortexutils repo](https://github.com/TheHive-Project/cortexutils) และบันทึกใน TheHive blog เรื่อง `summary()`/`build_taxonomy()` ([blog.thehive-project.org](https://blog.thehive-project.org/tag/misp/page/4)); ต้องคู่กับ JSON service file และ requirements.txt (`cortexutils`)
```python
#!/usr/bin/env python3
# File: IPReputation/ipreputation.py  (declared in "command" of the JSON service file)
import requests
from cortexutils.analyzer import Analyzer


class IPReputationAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        # read from "configurationItems" in the analyzer JSON definition
        self.api_key = self.get_param("config.api_key", None, "Missing api_key")

    def summary(self, raw):
        level = "malicious" if raw.get("score", 0) >= 70 else "safe"
        return {"taxonomies": [self.build_taxonomy(level, "IPRep", "Score", str(raw.get("score", 0)))]}

    def run(self):
        if self.data_type != "ip":
            self.error("This analyzer only supports the 'ip' data type")
        ip = self.get_data()
        r = requests.get(f"https://reputation.example/api/v1/ip/{ip}",
                         headers={"X-Api-Key": self.api_key}, timeout=10)
        if r.status_code != 200:
            self.error(f"Upstream error {r.status_code}")
        body = r.json()
        self.report({"ip": ip, "score": body.get("score", 0), "raw": body})


if __name__ == "__main__":
    IPReputationAnalyzer().run()
```

**ตัวอย่าง 6.3 — Splunk SOAR playbook: geolocate IP แล้วดำเนินการตามผล** — *ILLUSTRATIVE, อิงจาก documented API*: [Splunk SOAR Cloud tutorial](https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial/playbook-api-tutorial/tutorial-create-a-simple-playbook-in-splunk-soar-cloud) และ [Playbook automation API](https://help.splunk.com/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api); รันได้เฉพาะใน SOAR playbook runtime
```python
import phantom.rules as phantom
import json


def on_start(container):
    # collect2 pulls artifact fields: one parameter dict per artifact
    rows = phantom.collect2(container=container,
                            datapath=["artifact:*.cef.sourceAddress", "artifact:*.id"])
    parameters = [{"ip": r[0], "context": {"artifact_id": r[1]}} for r in rows if r[0]]
    if parameters:
        # actions run asynchronously; results arrive in the callback
        phantom.act("geolocate ip", parameters=parameters, callback=geolocate_ip_cb,
                    name="geolocate_ip_1")
    return


def geolocate_ip_cb(action=None, success=None, container=None, results=None, handle=None, **kwargs):
    if not success:
        phantom.debug("geolocate ip failed")
        return
    for result in results:
        for item in result.get("action_results", []):
            data = item.get("data", [{}])[0]
            country = data.get("country_name")
            phantom.debug(f"{item['parameter']['ip']} -> {country}")
            if country not in ("United States", "Thailand"):
                phantom.set_severity(container, "high")
                phantom.add_tags(container, tags="foreign-geo")
    return


def on_finish(container, summary):
    phantom.debug(json.dumps(summary, indent=2))
    return
```

**ตัวอย่าง 6.4 — โครง automation script ของ Cortex XSOAR** — ดัดแปลงจาก [XSOAR Script Code Snippets](https://cortex-docs.paloaltonetworks.com/python-development-quick-start-guide/cortex-xsoar-python-development-quick-start-guide/script-code-snippets) และ [Code Conventions](https://xsoar.pan.dev/docs/integrations/code-conventions); รันใน Python docker runtime ของ XSOAR
```python
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401


def score_alert(args: dict) -> CommandResults:
    severity = int(args.get("severity", 1))
    asset_criticality = int(args.get("asset_criticality", 1))   # 1..5
    ti_hits = int(args.get("ti_hits", 0))
    score = min(100, severity * 10 + asset_criticality * 8 + ti_hits * 15)
    verdict = "escalate" if score >= 60 else "auto-close"
    outputs = {"Score": score, "Verdict": verdict}
    return CommandResults(
        outputs_prefix="AlertTriage",
        outputs_key_field="Score",
        outputs=outputs,
        readable_output=tableToMarkdown("Alert triage", outputs),
    )


def main():
    try:
        res = score_alert(demisto.args())
        return_results(res)
        if res.outputs["Verdict"] == "auto-close":
            demisto.executeCommand("closeInvestigation", {"closeReason": "False Positive"})
    except Exception as e:
        return_error(f"Failed to execute ScoreAlert. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
```

**ตัวอย่าง 6.5 — Shuffle Python app (AppBase)** — ดัดแปลงจาก [Shuffle shuffle-docs/docs/apps.md](https://github.com/Shuffle/shuffle-docs/blob/master/docs/apps.md) (pattern class/`__init__` คัดจากเอกสาร) และ [shuffle-sdk บน PyPI](https://pypi.org/project/shuffle-sdk/0.0.8/); `pip install shuffle-sdk`; `app_name` ต้องตรง `name` ใน api.yaml ซึ่งประกาศแต่ละเมธอดเป็น action
```python
import json
import hashlib
from shuffle_sdk import AppBase   # older apps: from walkoff_app_sdk.app_base import AppBase


class AlertTools(AppBase):
    __version__ = "1.0.0"
    app_name = "alert_tools"  # this needs to match "name" in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """Each app should have this __init__ to set up Redis and logging."""
        super().__init__(redis, logger, console_logger)

    def fingerprint(self, alert_json, fields="rule_id,host,user"):
        """Build a dedupe key from selected alert fields (action exposed in api.yaml)."""
        alert = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
        parts = [str(alert.get(f, "")) for f in fields.split(",")]
        key = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        return {"fingerprint": key, "fields": parts}

    def risk_score(self, severity, asset_criticality="1", ti_hits="0"):
        score = int(severity) * 10 + int(asset_criticality) * 8 + int(ti_hits) * 15
        return {"score": min(score, 100), "escalate": score >= 60}


if __name__ == "__main__":
    AlertTools.run()
```

**ตัวอย่าง 6.6 — StackStorm Python action (เกือบ verbatim จากเอกสาร)** — ที่มา: [docs.stackstorm.com/actions.html](https://docs.stackstorm.com/actions.html); YAML metadata (`my_echo_action.yaml`): `name: "echo_action"`, `runner_type: "python-script"`, `entry_point: "my_echo_action.py"`, `parameters: {message: {type: string, required: true, position: 0}}`
```python
import sys

from st2common.runners.base_action import Action

class MyEchoAction(Action):
    def run(self, message):
        print(message)

        if message == 'working':
            return (True, message)
        return (False, message)
```

**ตัวอย่าง 6.7 — โครง Wazuh custom active response (ย่อจากตัวอย่างในเอกสาร)** — โครงสร้างและค่าคงที่จาก [Wazuh docs, Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html); deploy ไปที่ active-response/bin ของ agent และผูกผ่าน `<command>`/`<active-response>` ใน ossec.conf (เช่น `<rules_id>503</rules_id><timeout>60</timeout>`)
```python
#!/usr/bin/env python3
import sys, json, datetime
from pathlib import PureWindowsPath, PurePosixPath

LOG_FILE = "/var/ossec/logs/active-responses.log"
ADD_COMMAND, DELETE_COMMAND, CONTINUE_COMMAND, ABORT_COMMAND = 0, 1, 2, 3

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(f"{datetime.datetime.now()} {ar_name}: {msg}\n")

def main(argv):
    raw = sys.stdin.readline()
    data = json.loads(raw)
    command = {"add": ADD_COMMAND, "delete": DELETE_COMMAND}.get(data.get("command"), ABORT_COMMAND)
    alert = data.get("parameters", {}).get("alert", {})
    if command == ADD_COMMAND:
        keys = [alert.get("rule", {}).get("id")]
        keys_msg = json.dumps({"version": 1, "origin": {"name": argv[0], "module": "active-response"},
                               "command": "check_keys", "parameters": {"keys": keys}})
        write_debug_file(argv[0], keys_msg); print(keys_msg, flush=True)
        answer = json.loads(sys.stdin.readline()).get("command")
        if answer != "continue":
            write_debug_file(argv[0], "aborted by manager"); sys.exit(0)
        # --- the actual response goes here (e.g., block src_ip, isolate host) ---
        write_debug_file(argv[0], f"ADD for rule {keys[0]} src {alert.get('data', {}).get('srcip')}")
    elif command == DELETE_COMMAND:
        write_debug_file(argv[0], "DELETE: reverting action after timeout")
    else:
        write_debug_file(argv[0], "invalid command"); sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
```

runtime ของผู้ผลิต (Splunk SOAR, XSOAR, Shuffle, StackStorm, Wazuh) รันด้วย `python` เปล่าไม่ได้ นักเรียนต้องมีแพลตฟอร์ม ซึ่งทั้งหมดยกเว้น Splunk SOAR/XSOAR เป็นฟรี/โอเพนซอร์ส

### เอกสารอ้างอิงประจำหัวข้อ

- D3 Security: What's the Difference Between SOAR and SAO? — https://d3security.com/blog/whats-the-difference-between-soar-and-sao/
- TechTarget: SOAR definition — https://www.techtarget.com/searchsecurity/definition/SOAR
- secrss SOAR history — https://www.secrss.com/articles/24043
- Swimlane: Gartner Innovation Insight — https://swimlane.com/?p=9805
- Solutions Review: Gartner 2022 definition — https://solutionsreview.com/security-information-event-management/wp-json/wp/v2/posts/3178
- Solutions Review: 2019 Market Guide key findings — https://solutionsreview.com/security-information-event-management/key-findings-from-gartners-2019-market-guide-for-soar
- Wikipedia: Security orchestration — https://en.wikipedia.org/wiki/Security_orchestration
- Gartner glossary: SOAR — https://www.gartner.com/en/information-technology/glossary/security-orchestration-automation-response-soar
- TechRepublic: 2023 Gartner Market Guide for SOAR — https://www.techrepublic.com/resource-library/whitepapers/2023-gartner-market-guide-for-security-orchestration-automation-and-response-solutions/
- Netenrich: Gartner Hype Cycle for Security Operations 2024 — https://netenrich.com/blog/a-strategic-perspective-of-gartner-hype-cycle-for-security-operations-2024
- Dark Reading: SOAR Is Dead, Long Live SOAR — https://darkreading.com/cybersecurity-operations/soar-is-dead-long-live-soar
- Torq on Gartner — https://torq.io/?p=9180
- Blink Ops: Gartner says goodbye to SOAR — https://www.blinkops.com/blog/gartner-says-goodbye-to-soar-whats-next-for-security-operations
- Gartner Hype Cycle abstract — https://www.gartner.com/en/documents/5622491
- Intezer: Gartner's Changing Views on SOAR — https://intezer.com/guides/soar-security/gartner-view-on-soar
- NIST SP 800-61 Rev. 3 — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-61r3 PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
- NIST news: SP 800-61 revision — https://nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations
- NIST CSRC Incident Response project — https://csrc.nist.gov/projects/incident-response
- Linford & Co on SP 800-61 — https://linfordco.com/blog/nist-sp-800-61/
- Tandem on SP 800-61 Rev. 3 — https://tandem.app/blog/updated-nist-incident-response-guidance-sp-800-61-rev-3
- SANS Incident Handler's Handbook — https://www.sans.org/white-papers/33901/
- MITRE 11 Strategies publication page — https://www.mitre.org/news-insights/publication/11-strategies-world-class-cybersecurity-operations-center
- MITRE 11 Strategies short URL — https://www.mitre.org/11strategies
- BusinessWire: MITRE publishes 11 Strategies — https://www.businesswire.com/news/home/20220329005299/en/MITRE-Publishes-11-Strategies-of-a-World-Class-Cybersecurity-Operations-Center
- MITRE 11 Strategies highlights PDF — https://www.mitre.org/sites/default/files/2022-04/11-strategies-world-class-csoc-highlights.pdf
- D3 Security: Why MITRE calls SOAR indispensable — https://d3security.com/blog/why-mitre-calls-soar-indispensable-in-its-latest-book
- RSAC podcast: Turn it up to 11 — https://www.rsaconference.com/library/podcast/turn-it-up-to-11-csoc
- OASIS CACAO Security Playbooks v2.0 — https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html
- OASIS CACAO CS01 announcement — https://www.oasis-open.org/?p=10546
- OASIS CACAO approval release — https://www.oasis-open.org/?p=10491
- Google SRE Book ch.6 Monitoring Distributed Systems — https://sre.google/sre-book/monitoring-distributed-systems/
- thehive4py docs — https://thehive-project.github.io/TheHive4py/latest/
- thehive4py alert examples — https://thehive-project.github.io/TheHive4py/latest/examples/alert/
- TheHive-Project/TheHive (archived) — https://github.com/TheHive-Project/TheHive
- TheHive-Project/TheHive4py — https://github.com/TheHive-Project/TheHive4py
- docs.strangebee.com — https://docs.strangebee.com/
- TheHive-Project/Cortex — https://github.com/TheHive-Project/Cortex
- TheHive-Project/Cortex-Analyzers — https://github.com/TheHive-Project/Cortex-Analyzers
- TheHive-Project/cortexutils — https://github.com/TheHive-Project/cortexutils
- StrangeBee: How to Write and Submit an Analyzer — https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/
- docs.thehive-project.org mirror — https://docs.thehive-project.org/cortex/api/how-to-create-an-analyzer/
- DeepWiki Cortex-Analyzers developer guide — https://deepwiki.com/TheHive-Project/Cortex-Analyzers/6-developer-guide
- TheHive Project blog — https://blog.thehive-project.org/tag/misp/page/4
- Shuffle/Shuffle — https://github.com/Shuffle/Shuffle
- Shuffle/python-apps — https://github.com/Shuffle/python-apps
- Shuffle shuffle-docs apps.md — https://github.com/Shuffle/shuffle-docs/blob/master/docs/apps.md
- shuffler.io/docs/apps — https://shuffler.io/docs/apps
- shuffle-sdk PyPI — https://pypi.org/project/shuffle-sdk/0.0.8/
- Splunk SOAR Playbook automation API — https://help.splunk.com/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api
- Splunk SOAR On-prem Playbook API — https://docs.splunk.com/Documentation/SOARonprem/latest/PlaybookAPI/PlaybookAPI
- Splunk SOAR tutorial: Create a simple playbook — https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial/playbook-api-tutorial/tutorial-create-a-simple-playbook-in-splunk-soar-cloud
- Splunk SOAR Python Playbook Tutorial (On-prem) — https://help.splunk.com/en/splunk-soar/soar-on-premises/python-playbook-tutorial
- Splunk SOAR legacy custom function block — https://help.splunk.com/en/splunk-soar/soar-on-premises/build-playbooks/6.3.0/use-the-classic-playbook-editor-to-create-and-view-playbooks-to-automate-analyst-workflows/add-custom-code-to-your-splunk-soar-on-premises-playbook-with-the-legacy-custom-function-block-using-the-classic-playbook-editor
- demisto/content — https://github.com/demisto/content
- demisto/demisto-sdk — https://github.com/demisto/demisto-sdk
- XSOAR Script Code Snippets — https://cortex-docs.paloaltonetworks.com/python-development-quick-start-guide/cortex-xsoar-python-development-quick-start-guide/script-code-snippets
- xsoar.pan.dev Code Conventions — https://xsoar.pan.dev/docs/integrations/code-conventions
- xsoar.pan.dev Common Server Python — https://xsoar.pan.dev/docs/reference/api/common-server-python
- StackStorm/st2 — https://github.com/StackStorm/st2
- docs.stackstorm.com Actions — https://docs.stackstorm.com/actions.html
- Wazuh: Custom active response scripts — https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- wazuh/wazuh — https://github.com/wazuh/wazuh
- Tines: Run Python Script — https://www.tines.com/docs/actions/templates/templates/frequently-used-templates/run-python-script/
- Tines: Execute Python via Tines Tunnel — https://www.tines.com/stories/whats-new/execute-python-code-via-tines-tunnel/
- Tines: Python how-to guide — https://tines.com/blog/python-tines-how-to-guide
- docs.n8n.io Code node — https://docs.n8n.io/code/code-node/
- n8n-io/n8n — https://github.com/n8n-io/n8n
- Elastic: Create a detection rule — https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule
- Elastic Security alert schema (8.18) — https://www.elastic.co/guide/en/security/8.18/alert-schema.html
- elastic/detection-rules — https://github.com/elastic/detection-rules
- Elastic Python client getting started — https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started
- SigmaHQ/sigma — https://github.com/SigmaHQ/sigma
- SigmaHQ README (jsDelivr mirror) — https://cdn.jsdelivr.net/gh/sigmahq/sigma@master/README.md
- CSO Online: Sigma rules explained — https://www.csoonline.com/article/572973/sigma-rules-explained-when-and-how-to-use-them-to-log-events.html
- meirwah/awesome-incident-response — https://github.com/meirwah/awesome-incident-response
- awesome.ecosyste.ms (awesome-incident-response) — https://awesome.ecosyste.ms/projects/github.com%2Fmeirwah%2Fawesome-incident-response
- hevnsnt/Awesome_Incident_Response — https://github.com/hevnsnt/Awesome_Incident_Response
- Security-Onion-Solutions/securityonion — https://github.com/Security-Onion-Solutions/securityonion
- correlatedsecurity/Awesome-SOAR — https://github.com/correlatedsecurity/Awesome-SOAR
- socfortress/CoPilot — https://github.com/socfortress/CoPilot

---

## 7. Automated Alert Processing: pipeline เจ็ดขั้นที่ normalize → dedupe → enrich → score → route

### แหล่งต้นฉบับ

schema ต้นฉบับสำหรับ alert ที่ normalize แล้วคือ **OCSF "Detection Finding"** (class_uid **2004**, category Findings = category_uid 2; "A Detection Finding describes detections or alerts generated by security products using correlation engines, detection engines or other methodologies"; activity_id 0 Unknown, 1 Create, 2 Update, 3 Close, 99 Other; **required**: activity_id, category_uid, class_uid, finding_info, metadata, severity_id, time, type_uid; **recommended**: confidence_id, evidences, is_alert, message, observables, resources, status_code, status_detail, status_id, timezone_offset; schema เวอร์ชัน 1.9.0) โดย `type_uid = class_uid * 100 + activity_id` (เช่น 200401 = Detection Finding: Create) และ class เก่า "Security Finding" (class_uid 2001, OCSF 1.0.0) ถูกแทนในทางปฏิบัติ ([schema.ocsf.io/classes/detection_finding](https://schema.ocsf.io/classes/detection_finding); [Tenzir OCSF 1.4.0](https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding); [Tenzir OCSF 1.0.0 security_finding](https://docs.tenzir.com/reference/ocsf/1-0-0/classes/security_finding); [OCSF FAQ](https://docs.tenzir.com/reference/ocsf/faqs/when-should-i-use-a-finding-event-class)) ฝั่ง Elastic alert ถูกเก็บใน hidden index `.alerts-security.alerts-<space-id>` (8.x; 7.x ใช้ `.siem-signals-*`) ด้วย field `kibana.alert.*` เช่น `kibana.alert.rule.name`, `kibana.alert.severity` (low/medium/high/critical) และ Elastic แนะนำ `fields` แทน `_source` ใน search API ([Elastic alert schema 8.18](https://www.elastic.co/guide/en/security/8.18/alert-schema.html); [Elastic Python getting started](https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started)) ส่วนปลายทาง ticket เอกสาร `jira` ให้ `JIRA(basic_auth=('email', 'API token'))` (Cloud) หรือ `JIRA(token_auth='API token')` (self-hosted), `create_issue(project=..., summary=..., description=..., issuetype={'name': 'Bug'})` หรือ `create_issue(fields=issue_dict)`, `add_comment`, `transition_issue`, `search_issues('project=PROJ')` ([jira.readthedocs.io examples](https://jira.readthedocs.io/examples.html))

หลักฐานภาวะ alert overload ที่เป็นเหตุผลของหัวข้อนี้มาจากการสำรวจ Critical Start ปี 2019 (~50 SOC, Q2 2019): "70% of respondents investigate 10+ alerts each day (up from 45% last year)", "78% said it takes 10+ minutes to investigate each alert (up from 64%)", **เกือบครึ่งรายงานอัตรา false positive 50% ขึ้นไป** และ 38% ตอบสนองด้วยการจ้างเพิ่มหรือปิด feature ที่ alert มาก (สื่ออื่นรายงาน 79%/74% ซึ่งตัวเลขขัดแย้งกัน) ([Critical Start](https://criticalstart.com/resources/criticalstart-releases-third-annual-security-operations-center-soc-professional-survey); [Help Net Security 2019](https://www.helpnetsecurity.com/2019/08/29/soc-alert-overload/); [report PDF](https://www.criticalstart.com/wp-content/uploads/CS_MDR_Survey_Report.pdf); [Dark Reading](https://www.darkreading.com/analytics/overburdened-soc-analysts-shift-priorities/d/d-id/1335698)) และปี 2021 (100 SOC professionals): "Nearly 70% of respondents (68%) said that 25 to 75% of the alerts they investigate on a daily basis are false positives" ([Help Net Security 2021](https://www.helpnetsecurity.com/2021/03/11/alert-overload-still-plagues-cybersecurity-industry/)) SANS 2025 SOC Survey (สนับสนุนโดย Elastic) ตามสรุปของผู้ผลิต: "42% of SOCs use AI/ML tools 'out of the box' with no customization" และ "85% of SOCs primarily trigger incident response from endpoint alerts" ([Swimlane](https://swimlane.com/blog/global-soc-survey-insights/); [Torq](https://torq.io/blog/sans-2025-soc-survey); [Elastic landing](https://www.elastic.co/resources/security/report/2025-state-of-the-soc-survey); [PDF](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)) SANS "State of Automation in Security Operations" ระบุว่า IOC match ถูกยกเป็นประเภท alert ที่ triage นานที่สุดโดย 37% ([SANS](https://www.sans.org/white-papers/state-automation-security-operations-sans-survey/)) และ SANS/Rapid7 2025 Detection & Response survey ยืนยันความกังวลเรื่อง false positive และการเลื่อนไปสู่ automation ([Rapid7 PDF](https://www.rapid7.com/cdn/assets/blt2e3e3f0d1864c31f/6937f5fa43c2f8cbe153e2a5/Survey_Detection-Response_Rapid7_2025.pdf))

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

งานเขียนในอุตสาหกรรมบรรจบกันที่ pipeline เป็นขั้น ขั้น normalization: "without a reliable normalization layer, even high-quality detection logic will produce inconsistent results across heterogeneous enterprise environments" ([UnderDefense, เม.ย. 2026](https://underdefense.com/blog/ai-enabled-incident-triage/)) ขั้น dedupe: "Merge duplicate or overlapping alerts from multiple sources. A single login anomaly shouldn't generate three separate tickets" ([Dropzone AI](https://dropzone.ai/resource-guide/alert-triage-guide-2025)) และการออกแบบ dedupe key ตาม Vincent van Dijk (Security Scientist): key ("dedupe keys" หรือ "causal fingerprints") รวม source/destination IP หรือ hostname, port, protocol, event type/signature ID และบางครั้ง user/process/file hash ตรวจ "within a defined time window" (เช่น src/dst IP เดียวกันภายใน 5 นาที = event เดียวกัน) โดยเตือนว่า rule ที่ก้าวร้าวเกินจะสร้าง false negative "because it looked too much like something you've seen before" (ข้ออ้าง "up to 90% MTTC reduction" ของบทความนี้ไม่มีที่มา จึงถือเป็นการตลาด) ([Security Scientist](https://www.securityscientist.net/blog/12-questions-and-answers-about-alert-deduplication/)) ขั้น enrich: threat intelligence, asset inventory, user identity, historical incident records และขั้น score: composite score ที่แทน static vendor severity (alert "medium" บน crown-jewel asset สำคัญกว่า "high" บน test server) โดยการตัดสิน accept/override ของนักวิเคราะห์ "flow back into the system to improve future scoring accuracy" ([Deepwatch glossary](https://www.deepwatch.com/glossary/automated-incident-triage/); [NHI Mgmt Group glossary](https://nhimg.org/glossary/alert-management/); [D3 Event Pipeline](https://d3security.com/resources/event-pipeline-automate-handling-of-hundreds-of-alerts-per-minute/)) ตัวอย่างสาธารณะที่ชัดที่สุดของการ auto-close false positive อย่างปลอดภัยคือ Red Canary: alert "Not a Threat" จำนวนมากถูกจัดการด้วย "Workflow Rule", Alert Center ให้ suppress ตาม attribute ที่เลือกและใช้กับ alert อนาคต, และ "Agentic Tuning" แบบชั้น global/per-customer ที่ลูกค้า early-access เห็น false positive ด้าน identity ลดได้ถึง 80% โดย suppression ยังตรวจสอบย้อนหลังได้ ([Red Canary alert states](https://docs.redcanary.com/docs/alert-states); [Alert Center](https://redcanary.com/blog/alert-center/); [AI agentic tuning](https://redcanary.com/blog/product-updates/ai-agentic-tuning/)) เสียงจาก detection engineering เตือนว่าให้แก้ที่ต้นทาง: Panther ว่า "alert volume isn't a function of investigation speed; it's a function of detection quality" ([Panther](https://panther.com/blog/tuning-detections-without-a-backlog)); Expel ว่าการลด false positive ผ่าน detection engineering ให้ ROI สูงสุดต่อ alert fatigue ([Expel](https://expel.com/cyberspeak/how-to-implement-alert-fatigue-solutions/); [Expel: reduce false positives](https://expel.com/cyberspeak/reduce-false-positives-in-soc-operations/)); Target เล่าแนวทาง detection confidence ([Target Tech](https://tech.target.com/blog/boost_detection_confidence)); NHI Mgmt Group แนะให้เริ่ม automation จาก alert type ปริมาณสูงเมื่อ rule สะอาดและ enrichment เชื่อถือได้ และวัด suppression quality, alert recurrence, % ของ triage outcome ที่เปลี่ยน rule ([NHI: where to start](https://nhimg.org/community/cybersecurity-beyond-identity/soc-automation-and-detection-quality-where-should-teams-start/); [NHI FAQ](https://nhimg.org/faq/how-should-security-teams-turn-triage-outcomes-into-better-detections/)); Florian Roth (ผู้ร่วมสร้าง Sigma) ชี้ว่า rule "differ widely in purpose, quality, and how often they produce false positives" และ YARA Forge "core" คัดเฉพาะ rule คุณภาพสูง FP ต่ำ ([cyb3rops: YARA Forge](https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab)); งานวิชาการ "Decision-Aware Trust Signal Alignment for SOC Alert Triage" (arXiv 2601.04486) สรุปว่าคุณภาพ signal กำหนดคุณภาพ triage ([arXiv](https://arxiv.org/pdf/2601.04486)) และ BHIS มี slide "The Detection Engineering Process" (พ.ย. 2024) ([BHIS PDF](https://www.blackhillsinfosec.com/wp-content/uploads/2024/11/SLIDES_The-Detection-Engineering-Process.pdf)); แหล่งอื่นในหมวดนี้ได้แก่ Alex Teixeira (Detect FYI), zendannyy Substack, TryHackMe และ Elastic Security Labs ([ateixei.medium.com](https://ateixei.medium.com/about); [zendannyy](https://zendannyy.substack.com/p/detection-engineering-series-detections); [TryHackMe](https://tryhackme.com/resources/blog/how-detection-engineering-actually-works); [Elastic Security Labs](https://www.elastic.co/pt/security-labs/category/detection-engineering)) ข้ออ้างของผู้ผลิตว่า ">80% of alerts lead to dead ends, while fewer than 5% of rules generate most of the noise" ยังไม่ได้รับการยืนยัน ([AiStrike via Security Boulevard](https://securityboulevard.com/2026/03/aistrike-launches-continuous-detection-engineering-to-fix-alert-noise-at-the-source/))

**การออกแบบอ้างอิงที่สังเคราะห์ได้** จึงมีเจ็ดขั้น: (1) ingest ผ่าน webhook/queue; (2) normalize เป็น OCSF Detection Finding (field บังคับให้ schema ขั้นต่ำ); (3) fingerprint = hash(rule_id, entity หลักเช่น host/user/src_ip, dst) ใน sliding window (5–15 นาทีตามตัวอย่าง); (4) enrich (asset criticality, identity, TI reputation, disposition ก่อนหน้า); (5) score = base severity × asset criticality × TI confidence ± historical FP rate; (6) route: คะแนนต่ำกว่า threshold และ fingerprint known-benign → auto-close พร้อม audit trail, สูงกว่า → case/ticket; (7) บันทึก verdict ของนักวิเคราะห์แล้วป้อนกลับเป็น suppression/tuning กฎ SRE ("actionable", "requires intelligence", "novel") แปลเป็นเกณฑ์ auto-close ของ SOC ได้ตรงตัว: สิ่งใดที่ไม่ผ่านทั้งสามข้อควร suppress หรือ automate ไม่ใช่ page ไม่มีสเปก vendor-neutral หรือ peer-reviewed สำหรับสูตร scoring หรือ dedupe window — ตัวเลขทั้งหมด (5 นาที, 80%) มาจากผู้ผลิตรายเดียว

### ตัวอย่างโค้ด

**ตัวอย่าง 7.1 — FastAPI webhook receiver ที่ normalize alert ของผู้ผลิตเป็น OCSF Detection Finding** — *ILLUSTRATIVE*; field set ตาม required/recommended attributes ของ OCSF `detection_finding` (class_uid 2004, type_uid = class_uid*100 + activity_id) ที่ [schema.ocsf.io](https://schema.ocsf.io/classes/detection_finding) และ [Tenzir OCSF reference](https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding); `pip install fastapi uvicorn`
```python
import time, uuid
from fastapi import FastAPI, Request

app = FastAPI()
SEV = {"low": 2, "medium": 3, "high": 4, "critical": 5}   # OCSF severity_id

def to_ocsf(vendor: str, a: dict) -> dict:
    activity_id = 1                                       # 1 = Create
    return {
        "class_uid": 2004, "category_uid": 2, "activity_id": activity_id,
        "type_uid": 2004 * 100 + activity_id,              # 200401
        "time": int(time.time() * 1000),
        "severity_id": SEV.get(str(a.get("severity", "low")).lower(), 1),
        "metadata": {"version": "1.9.0", "product": {"vendor_name": vendor},
                     "uid": str(uuid.uuid4())},
        "finding_info": {"uid": str(a.get("id", uuid.uuid4())),
                         "title": a.get("rule_name") or a.get("title", "untitled"),
                         "analytic": {"name": a.get("rule_id", "unknown"), "type": "Rule"}},
        "is_alert": True, "status_id": 1,                  # 1 = New
        "message": a.get("description", ""),
        "observables": [{"name": "source.ip", "type_id": 2, "value": a["src_ip"]}]
                        if a.get("src_ip") else [],
        "unmapped": {k: v for k, v in a.items() if k not in
                     ("id", "severity", "rule_name", "title", "rule_id", "description", "src_ip")},
    }

@app.post("/webhook/{vendor}")
async def receive(vendor: str, request: Request):
    payload = await request.json()
    finding = to_ocsf(vendor, payload)
    # TODO: enqueue finding -> dedupe/score (Snippet 6) -> TheHive/Jira (Snippets 1, 8)
    return {"accepted": True, "type_uid": finding["type_uid"], "uid": finding["metadata"]["uid"]}
# run: uvicorn app:app --port 8080  ;  curl -XPOST localhost:8080/webhook/wazuh -d '{"severity":"high","rule_id":"5712","src_ip":"1.2.3.4"}' -H 'content-type: application/json'
```

**ตัวอย่าง 7.2 — sliding-window deduplication และ risk scoring (pure Python)** — *ILLUSTRATIVE*; การออกแบบอิงแนวทาง dedupe-key ใน [Security Scientist](https://www.securityscientist.net/blog/12-questions-and-answers-about-alert-deduplication/) และ pattern composite-scoring/feedback ใน [Deepwatch](https://www.deepwatch.com/glossary/automated-incident-triage/); ไม่มี dependency ภายนอก
```python
import hashlib, time
from collections import deque, defaultdict

WINDOW_SECONDS = 600          # 10-minute sliding window
ASSET_CRIT = {"dc01": 5, "web-prod": 4, "lab-vm": 1}

class Deduper:
    def __init__(self, window=WINDOW_SECONDS):
        self.window, self.seen = window, defaultdict(deque)   # fingerprint -> timestamps

    @staticmethod
    def fingerprint(a):
        key = f"{a['rule_id']}|{a.get('host','')}|{a.get('user','')}|{a.get('src_ip','')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def observe(self, a, now=None):
        now = now or time.time(); fp = self.fingerprint(a); q = self.seen[fp]
        while q and now - q[0] > self.window:      # evict old timestamps
            q.popleft()
        q.append(now)
        return fp, len(q)                           # count within window

def risk_score(a, repeats, fp_history):
    base = {"low": 10, "medium": 30, "high": 60, "critical": 85}[a["severity"]]
    score = base + 8 * ASSET_CRIT.get(a.get("host"), 2) + 15 * a.get("ti_hits", 0)
    score += min(10, 2 * (repeats - 1))             # burst bonus, capped
    score -= 25 * fp_history.get(a["rule_id"], 0)   # analyst FP rate 0..1 feedback
    return max(0, min(100, int(score)))

def route(a, score, repeats):
    if repeats > 1: return "merge-into-existing"
    if score < 25:  return "auto-close:known-benign"
    return "escalate:create-case" if score >= 60 else "queue:analyst-review"

if __name__ == "__main__":
    d, fp_rate = Deduper(), {"R-1001": 0.9}
    alerts = [{"rule_id": "R-1001", "host": "lab-vm", "user": "svc", "severity": "medium"},
              {"rule_id": "R-2002", "host": "dc01", "user": "admin", "severity": "high", "ti_hits": 1},
              {"rule_id": "R-2002", "host": "dc01", "user": "admin", "severity": "high", "ti_hits": 1}]
    for a in alerts:
        fp, n = d.observe(a); s = risk_score(a, n, fp_rate)
        print(fp, n, s, route(a, s, n))
```

**ตัวอย่าง 7.3 — อ่าน Elastic Security alert ด้วย elasticsearch-py แล้ว enrich ด้วย reputation lookup** — *ILLUSTRATIVE*; อิงจาก [Elastic Python client getting started](https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started) และ [Elastic Security alert schema](https://www.elastic.co/guide/en/security/8.18/alert-schema.html) (`.alerts-security.alerts-*`, `kibana.alert.*`, ใช้ `fields` ไม่ใช่ `_source`); `pip install elasticsearch requests`
```python
import os, requests
from elasticsearch import Elasticsearch

client = Elasticsearch(os.environ["ELASTIC_URL"], api_key=os.environ["ELASTIC_API_KEY"])

def fetch_open_alerts(size=50):
    resp = client.search(
        index=".alerts-security.alerts-default",
        size=size,
        query={"bool": {"filter": [
            {"term": {"kibana.alert.workflow_status": "open"}},
            {"range": {"@timestamp": {"gte": "now-15m"}}}]}},
        fields=["kibana.alert.rule.name", "kibana.alert.severity",
                "kibana.alert.risk_score", "host.name", "source.ip"],
        _source=False,
    )
    return [h["fields"] for h in resp["hits"]["hits"]]

def reputation(ip):
    # Replace with VirusTotal / AbuseIPDB / OTX; marked illustrative
    r = requests.get(f"https://reputation.example/api/v1/ip/{ip}",
                     headers={"X-Api-Key": os.environ.get("REP_KEY", "")}, timeout=10)
    return r.json().get("score", 0) if r.ok else 0

if __name__ == "__main__":
    for f in fetch_open_alerts():
        ip = (f.get("source.ip") or [None])[0]
        rep = reputation(ip) if ip else 0
        print(f["kibana.alert.rule.name"][0], f["kibana.alert.severity"][0],
              f.get("host.name", ["?"])[0], ip, "rep=", rep)
```

**ตัวอย่าง 7.4 — escalate เป็น Jira ticket ด้วย library jira** — ดัดแปลงจาก [jira.readthedocs.io examples](https://jira.readthedocs.io/examples.html); `pip install jira`
```python
import os
from jira import JIRA

jira = JIRA(server=os.environ["JIRA_URL"],
            basic_auth=(os.environ["JIRA_EMAIL"], os.environ["JIRA_API_TOKEN"]))  # Jira Cloud
# Self-hosted / Data Center alternative: JIRA(server=..., token_auth=os.environ["JIRA_PAT"])

def escalate(alert: dict, score: int):
    jql = f'project=SOC AND labels="fp-{alert["fingerprint"]}" AND statusCategory != Done'
    existing = jira.search_issues(jql)
    if existing:                                   # dedupe at the ticket layer too
        jira.add_comment(existing[0], f"Recurrence observed. Current score {score}.")
        return existing[0].key
    issue = jira.create_issue(fields={
        "project": {"key": "SOC"},
        "summary": f"[{alert['severity'].upper()}] {alert['rule_name']} on {alert['host']}",
        "description": f"Score: {score}\nFingerprint: {alert['fingerprint']}\n{alert['description']}",
        "issuetype": {"name": "Task"},
        "labels": ["soc-auto", f"fp-{alert['fingerprint']}"],
        "priority": {"name": "High" if score >= 60 else "Medium"},
    })
    return issue.key

if __name__ == "__main__":
    print(escalate({"fingerprint": "ab12cd34", "severity": "high", "rule_name": "Credential dumping",
                    "host": "dc01", "description": "LSASS access by procdump"}, 82))
```

ตัวอย่าง 7.1 → 7.2 → 6.1/7.4 ต่อกันเป็นโปรเจ็กต์ Module 6 ขั้นต่ำที่สมบูรณ์: webhook ingest + OCSF normalization, dedupe/score แล้วส่งเป็น case (TheHive) หรือ ticket (Jira) โดย Cortex (6.2) ให้ enrichment และ Wazuh/StackStorm/Shuffle (6.7/6.6/6.5) ให้ response action

### เอกสารอ้างอิงประจำหัวข้อ

- schema.ocsf.io: Detection Finding — https://schema.ocsf.io/classes/detection_finding
- Tenzir OCSF 1.4.0 detection_finding — https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding
- Tenzir OCSF 1.0.0 security_finding — https://docs.tenzir.com/reference/ocsf/1-0-0/classes/security_finding
- OCSF FAQ: when to use a finding class — https://docs.tenzir.com/reference/ocsf/faqs/when-should-i-use-a-finding-event-class
- ocsf/ocsf-schema — https://github.com/ocsf/ocsf-schema
- Elastic Security alert schema (8.18) — https://www.elastic.co/guide/en/security/8.18/alert-schema.html
- Elastic Python client getting started — https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started
- jira.readthedocs.io examples — https://jira.readthedocs.io/examples.html
- Critical Start 2019 SOC survey — https://criticalstart.com/resources/criticalstart-releases-third-annual-security-operations-center-soc-professional-survey
- Critical Start report PDF — https://www.criticalstart.com/wp-content/uploads/CS_MDR_Survey_Report.pdf
- Help Net Security 2019: SOC alert overload — https://www.helpnetsecurity.com/2019/08/29/soc-alert-overload/
- Dark Reading: Overburdened SOC analysts — https://www.darkreading.com/analytics/overburdened-soc-analysts-shift-priorities/d/d-id/1335698
- Help Net Security 2021: alert overload — https://www.helpnetsecurity.com/2021/03/11/alert-overload-still-plagues-cybersecurity-industry/
- Swimlane: SANS 2025 SOC survey insights — https://swimlane.com/blog/global-soc-survey-insights/
- Torq: SANS 2025 SOC survey — https://torq.io/blog/sans-2025-soc-survey
- Elastic: 2025 State of the SOC Survey — https://www.elastic.co/resources/security/report/2025-state-of-the-soc-survey
- SANS SOC Survey 2025 PDF — https://www.elastic.co/pdf/sans-soc-survey-2025.pdf
- Dropzone AI: 2025 SANS SOC survey infographic — https://content.dropzone.ai/2025-sans-soc-survey-infographic
- SANS: State of Automation in Security Operations — https://www.sans.org/white-papers/state-automation-security-operations-sans-survey/
- Rapid7/SANS 2025 Detection & Response survey PDF — https://www.rapid7.com/cdn/assets/blt2e3e3f0d1864c31f/6937f5fa43c2f8cbe153e2a5/Survey_Detection-Response_Rapid7_2025.pdf
- UnderDefense: AI-enabled incident triage — https://underdefense.com/blog/ai-enabled-incident-triage/
- Dropzone AI: Alert Triage Guide 2025 — https://dropzone.ai/resource-guide/alert-triage-guide-2025
- Security Scientist: 12 Q&A about alert deduplication — https://www.securityscientist.net/blog/12-questions-and-answers-about-alert-deduplication/
- Deepwatch glossary: Automated Incident Triage — https://www.deepwatch.com/glossary/automated-incident-triage/
- NHI Mgmt Group glossary: Alert management — https://nhimg.org/glossary/alert-management/
- D3 Security: Event Pipeline — https://d3security.com/resources/event-pipeline-automate-handling-of-hundreds-of-alerts-per-minute/
- Red Canary docs: Alert states — https://docs.redcanary.com/docs/alert-states
- Red Canary: Alert Center — https://redcanary.com/blog/alert-center/
- Red Canary: AI agentic tuning — https://redcanary.com/blog/product-updates/ai-agentic-tuning/
- Panther: Tuning detections without a backlog — https://panther.com/blog/tuning-detections-without-a-backlog
- Expel: How to implement alert fatigue solutions — https://expel.com/cyberspeak/how-to-implement-alert-fatigue-solutions/
- Expel: Reduce false positives in SOC operations — https://expel.com/cyberspeak/reduce-false-positives-in-soc-operations/
- Target Tech: Boost Detection Confidence — https://tech.target.com/blog/boost_detection_confidence
- NHI Mgmt Group: SOC automation and detection quality — https://nhimg.org/community/cybersecurity-beyond-identity/soc-automation-and-detection-quality-where-should-teams-start/
- NHI Mgmt Group FAQ: triage outcomes into detections — https://nhimg.org/faq/how-should-security-teams-turn-triage-outcomes-into-better-detections/
- arXiv 2601.04486 — https://arxiv.org/pdf/2601.04486
- Security Boulevard: AiStrike — https://securityboulevard.com/2026/03/aistrike-launches-continuous-detection-engineering-to-fix-alert-noise-at-the-source/
- cyb3rops: Introducing YARA Forge — https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab
- Alex Teixeira about — https://ateixei.medium.com/about
- zendannyy Substack: Detections → Alerts — https://zendannyy.substack.com/p/detection-engineering-series-detections
- TryHackMe: How detection engineering actually works — https://tryhackme.com/resources/blog/how-detection-engineering-actually-works
- Elastic Security Labs: detection engineering — https://www.elastic.co/pt/security-labs/category/detection-engineering
- BHIS: The Detection Engineering Process (slides) — https://www.blackhillsinfosec.com/wp-content/uploads/2024/11/SLIDES_The-Detection-Engineering-Process.pdf

---

## 8. Automated Reporting: 69% ของ SOC ยังรายงานด้วยมือ และ stack pandas → Jinja2 → WeasyPrint ตอบโจทย์ได้ทุก format

### แหล่งต้นฉบับ

เนื้อหาที่รายงานของ SOC "ควรมี" กำหนดโดยเอกสารมาตรฐานสี่กลุ่ม **NIST SP 800-61 Rev. 3** (final 3 เม.ย. 2025) แทนวงจรสี่เฟสของ Rev. 2 ด้วยโมเดลที่อิงหก CSF 2.0 Functions โดย Table 1 map เฟสเดิมเข้า Function, Table 2 เป็น "CSF 2.0 Community Profile part 1: Preparation and Lessons Learned", Table 3 เป็น "part 2: Incident Response" และข้อแนะนำเรียงตาม subcategory เช่น GV.OC-03 (ข้อผูกพันทางกฎหมายรวม "notifications, data breach reporting"), ID.IM-03 (การปรับปรุงที่พบ "when creating follow-up reports for incidents or holding 'lessons learned'" sessions) และ RS.MA-02 ("Incident reports are triaged and validated") ([SP 800-61r3 PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf); [CSRC record](https://csrc.nist.gov/pubs/sp/800/61/r3/final); [NIST CSF 2.0 PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)) **SOC-CMM "Metrics 101"** (©2024, 21 หน้า) ระบุว่า "the SOC-CMM model includes the reporting and communication aspect, in the SOC-CMM process domain", ว่าสำหรับผู้บริหาร "metrics that provide an indication of risk within the organisation are most fitting" และ "Many operational metrics (like number of incidents) lack the right context to be meaningful to higher management" โดยนิยามแต่ละ metric ด้วย Type ($, %, #, timing, trend, KPI/KRI), Level (L1→L3), Target และ Differentiation และมี metric ด้านรายงานโดยตรง เช่น "% Completeness of shift [handover]" (L1), "% Reporting requirements met in a timely manner — the percentage of reportable incidents (i.e. legal obligation to report) reported within the obligatory time window" (L2, target 100%) และ "# Number of incidents incorrectly escalated" (L2, target 0) ([SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)) **MITRE 11 Strategies** Strategy 10 "Measure Performance to Improve Performance" (หน้า 301–318 ตาม awesome-soc) เป็นฐานของ SOC metric reporting ([MITRE 11 Strategies](https://www.mitre.org/11strategies); [awesome-soc](https://github.com/cyb3rxp/awesome-soc)) และฝั่งวัฒนธรรม post-incident คือ Google SRE "Postmortem Culture: Learning from Failure" ([SRE book](https://sre.google/sre-book/postmortem-culture/)) บวก SANS incident-handling forms (เช่น IH-Identification) และ playbook "SANS – Lessons Learned" ของ XSOAR ที่เข้ารหัสหกเฟสของ Kral ([SANS IH-Identification form](https://www.sans.org/media/score/incident-forms/IH-Identification.pdf); [XSOAR playbook](https://demisto.pan.dev/docs/reference/playbooks/sans---lessons-learned)) และ template รายงาน IR ของ Lenny Zeltser ที่จัดตาม "high-level categories in anticipation of what the report's readers expect to see" ([zeltser.com](https://zeltser.com/incident-response-report-template)) ด้านหลักฐาน compliance PCI DSS v4.0.1 Requirement 10.4.1 กำหนด daily review ของ log บางหมวด (10.4.1.1 บังคับใช้ automated mechanism ตั้งแต่ 31 มี.ค. 2025 ตามแหล่งทุติยภูมิ) และ 12.10.2 ให้ทดสอบ IR plan ทุก 12 เดือน ([PCI SSC document library](https://www.pcisecuritystandards.org/document_library/); [Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/04/01/); [RSI Security](https://blog.rsisecurity.com/tracking-and-monitoring-under-pci-dss-requirement-10/)) และ ISO/IEC 27001:2022 clause 9.1 (monitoring, measurement, analysis, evaluation) เป็นฐาน ISMS (iso.org คืน 403 ต่อการดึงอัตโนมัติ) ([ISO/IEC 27001](https://www.iso.org/standard/27001))

หลักฐานที่ทรงพลังที่สุดสำหรับโปรเจ็กต์รายงานอัตโนมัติคือ **SANS 2025 SOC Survey** (ครั้งที่ 9, Christopher Crowley, ผู้ตอบจาก 57 ประเทศ): "**69% of SOCs still rely on manual or mostly manual processes to report metrics**", SOC ทั่วไป "Reports metrics manually, even though nearly half say it's too time-consuming. Automation remains limited", "42% of SOC staff don't know the SOC's budget", "42% of SOCs dump all incoming data into a SIEM, often without a retrieval or management plan" ([SANS SOC Survey 2025 PDF](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)) และ Gartner มีซีรีส์ "The Journey to SOC: Step 3 Building Reporting and Maturity Roadmaps" (24 เม.ย. 2025) กับ "A Journey Guide to Building a Security Operations Center" (Shoard & Ahlm, 13 มี.ค. 2025) ([Red Canary-hosted Gartner guide](https://redcanary.com/resources/guides/gartner-journey-guide-building-soc); [Gartner abstract](https://www.gartner.com/en/documents/6389843))

เอกสาร library ที่เป็น stack มาตรฐาน: **Jinja2** (Pallets; repo ≈11.8k ดาว) ([Jinja2 docs](https://jinja.palletsprojects.com/en/stable/)); **WeasyPrint** ("The awesome document factory", HTML/CSS → PDF; ≈9.8k ดาว, push ล่าสุด 30 ต.ค. 2026) ([WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/); [GitHub](https://github.com/Kozea/WeasyPrint)); **ReportLab** (User Guide PDF เป็น reference ของ `canvas`, `platypus`, `SimpleDocTemplate`, `Table`) ([docs.reportlab.com](https://docs.reportlab.com/); [User Guide PDF](https://www.reportlab.com/docs/reportlab-userguide.pdf)); **Pandoc** (`pandoc report.md -o report.pdf` ต้องมี engine ผ่าน `--pdf-engine`) ([Pandoc MANUAL](https://pandoc.org/MANUAL.html)); **python-docx** (≈5.8k) และ **python-pptx** (≈3.6k) ([python-docx docs](https://python-docx.readthedocs.io/en/latest/); [GitHub](https://github.com/python-openxml/python-docx); [python-pptx docs](https://python-pptx.readthedocs.io/en/latest/); [GitHub](https://github.com/scanny/python-pptx)); **matplotlib** (≈23.4k), **plotly.py** (≈18.9k), **pandas**, **Streamlit** (≈46.2k, push ล่าสุด 1 พ.ย. 2026) ([matplotlib](https://matplotlib.org/stable/); [plotly](https://plotly.com/python/); [pandas](https://pandas.pydata.org/docs/); [Streamlit](https://docs.streamlit.io/)) ฝั่ง SIEM: Kibana สร้างรายงานด้วย `POST /api/reporting/generate/<exportType>?jobParams=<rison>` ต้องมี header `kbn-xsrf`, ใช้ API key ได้, คืน 200 เมื่อ job ถูก *queue* "even if the job somehow fails later", ต้องมี RAM ≥2 GB และเอกสารเตือนว่าเป็น internal API "not guaranteed to be supported across future versions of Kibana" ([Elastic: Automating report generation](https://www.elastic.co/docs/explore-analyze/report-and-share/automating-report-generation); [Kibana legacy guide](https://www.elastic.co/guide/en/kibana/current/automating-report-generation.html); [Reporting integration](https://www.elastic.co/pt/guide/en/kibana/current/reporting-integration.html)); Grafana มี `POST /api/reports` (ต้อง `reports:create`, Bearer service-account token; body มี `name`, `recipients`, `schedule`, `dashboards[].dashboard.uid`, `formats[]` pdf/csv/image) แต่ "only available in Grafana Enterprise" และ "is not stabilized yet and may change without prior notice" ([Grafana Reporting HTTP API](https://grafana.com/docs/grafana/next/developers/http_api/reporting/); [v12.4](https://grafana.com/docs/grafana/v12.4/developer-resources/api-reference/http-api/reporting.md)) **ATT&CK Navigator Layer Format v4.5** กำหนด field บังคับ `name` และ `domain` (`enterprise-attack`/`mobile-attack`/`ics-attack`), `versions.layer` "Must be '4.5'", `versions.navigator` "Must be at least '4.9.0'", `techniques[]` ที่มี `techniqueID` ("T####" หรือ "T####.###"), `tactic`, `score` (ไม่ใส่ = ไม่มี gradient), `color`, `comment`, `enabled`, `showSubtechniques`, และ `gradient` default แดง→เขียว 0–100 ([Layer format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md); [Navigator app](https://mitre-attack.github.io/attack-navigator/); [GitHub ≈2.5k](https://github.com/mitre-attack/attack-navigator)) ด้านคะแนนช่องโหว่ **CVSS v4.0** (FIRST) มีสี่ metric group (Base, Threat, Environmental, Supplemental) และ nomenclature CVSS-B/BT/BE/BTE ที่ "should be used wherever a numerical CVSS value is displayed or communicated" โดย Supplemental metrics "do not modify the final score" ([CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document); [Sysdig](https://www.sysdig.com/blog/cvss-version-4-0-whats-new); [Qualys](https://blog.qualys.com/product-tech/2023/11/02/cvss-v4-is-now-live-and-what-do-you-need-to-know)) และ **EPSS REST API** `https://api.first.org/data/v1/epss` (สถานะ BETA; พารามิเตอร์ `cve` คั่นด้วย comma **สูงสุด 2000 ตัวอักษร**, `date`, `days`, `epss-gt/lt`, `percentile-gt/lt`, `scope=time-series`; ผลลัพธ์ `data[].cve/epss/percentile/date`) ซึ่งทดสอบสดเมื่อ 2026-11-01 ได้ `epss 0.99999`, `percentile 1.0` สำหรับ CVE-2021-44228 และ CVE-2024-3400 ([FIRST API: GET /epss](https://api.first.org/epss/); [live call](https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400&pretty=true); [EPSS](https://www.first.org/epss/); [probability vs percentile](https://www.first.org/epss/articles/prob_percentile_bins))

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

ระบบนิเวศ Jupyter สำหรับรายงานด้านความปลอดภัยนำโดย **msticpy** (≈2.0k; เดิมสำหรับ Azure Sentinel ปัจจุบันมี provider สำหรับ Splunk, M365 Defender, Microsoft Graph, Sumo Logic และ OTRF Security Datasets) และงานของ Open Threat Research (Roberto Rodriguez): **OTRF/ThreatHunter-Playbook** (≈4.7k, "community-driven, open-source project to share detection logic, adversary tradecraft" ที่ map กับ ATT&CK) และ **infosec-jupyter-book** (≈134, push ล่าสุด ต.ค. 2020, เว็บไซต์ยังอยู่) ([msticpy docs](https://msticpy.readthedocs.io/); [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook); [infosec-jupyter-book](https://github.com/OTRF/infosec-jupyter-book); [infosecjupyterbook.com](https://infosecjupyterbook.com/)) และ **mitreattack-python** (≈755) กับ **attack-stix-data** (≈707) เป็นแหล่ง technique universe สำหรับ coverage report ([mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/); [attack-stix-data](https://github.com/mitre-attack/attack-stix-data); [ATT&CK resources](https://attack.mitre.org/resources/)) ข้อสรุปเชิงออกแบบ: เพราะ Kibana reporting เป็น internal และ Grafana `/api/reports` เป็น Enterprise-only และ "not stabilized" โปรเจ็กต์ของหลักสูตรจะพกพาได้มากกว่าหากดึงข้อมูลดิบ (Elasticsearch query, SIEM export) เข้า pandas แล้ว render ด้วย Jinja2 + WeasyPrint โดยใช้ SIEM API เป็น integration เสริม; Navigator layer JSON คือภาษากลางของ coverage report (DeTT&CT, Splunk Detection Studio และ script ทำมือล้วนออก format นี้) จึงสอน schema v4.5 ครั้งเดียวคุ้มทั้ง module; และขีดจำกัด 2000 ตัวอักษรของ EPSS คือราว 130 CVE ต่อ call จึงต้อง batch สำหรับ scan export ขนาดใหญ่ taxonomy รายงานที่ใช้ได้จริงในหลักสูตรคือ (1) shift handover (SOC-CMM "completeness of shift handover"), (2) weekly/monthly metrics (SOC-CMM L1; MITRE Strategy 10), (3) incident report/post-mortem (NIST RS.MA-02, ID.IM-03; SRE postmortem), (4) executive/board summary (metric เชิง risk ไม่ใช่ raw count) และ (5) regulatory/compliance evidence (GV.OC-03 breach-reporting deadline; PCI DSS 10.4.1; ISO 27001 9.1)

### ตัวอย่างโค้ด

**ตัวอย่าง 8.1 — รายงาน incident รายสัปดาห์: pandas → Jinja2 → HTML → PDF (WeasyPrint)** — *illustrative*; API ตาม [Jinja2 docs](https://jinja.palletsprojects.com/en/stable/) และ [WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/)
```python
import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

inc = pd.read_csv("incidents.csv", parse_dates=["opened", "closed"])
week = inc[inc["opened"] >= pd.Timestamp.now() - pd.Timedelta(days=7)]
summary = {
    "total": len(week),
    "by_severity": week["severity"].value_counts().to_dict(),
    "open": int((week["closed"].isna()).sum()),
    "mttr_h": round((week["closed"] - week["opened"]).dt.total_seconds().div(3600).median(), 1),
}
env = Environment(loader=FileSystemLoader("templates"),
                  autoescape=select_autoescape(["html"]))
html = env.get_template("weekly.html").render(
    summary=summary,
    rows=week.sort_values("severity").to_dict("records"),
    generated=pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"),
)
open("weekly_report.html", "w").write(html)
HTML(string=html, base_url=".").write_pdf("weekly_report.pdf")
print("wrote weekly_report.pdf", summary)
```
`templates/weekly.html` ขั้นต่ำ (syntax Jinja2 ตามเอกสาร):
```html
<h1>SOC Weekly Report – {{ generated }}</h1>
<p>Incidents: {{ summary.total }} (open: {{ summary.open }}), median MTTR {{ summary.mttr_h }} h</p>
<table>{% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.severity }}</td><td>{{ r.title }}</td></tr>{% endfor %}</table>
```

**ตัวอย่าง 8.2 — bar chart ของ alert ตาม severity (matplotlib)** — *illustrative*; API ตาม [matplotlib docs](https://matplotlib.org/stable/)
```python
import pandas as pd
import matplotlib
matplotlib.use("Agg")                      # headless for cron/CI
import matplotlib.pyplot as plt

alerts = pd.read_csv("alerts.csv")         # columns: alert_id, severity, rule, fired_at
order = ["critical", "high", "medium", "low", "informational"]
counts = alerts["severity"].str.lower().value_counts().reindex(order, fill_value=0)

fig, ax = plt.subplots(figsize=(7, 4))
bars = ax.bar(counts.index, counts.values)
ax.bar_label(bars)
ax.set_title("Alerts by severity – last 7 days")
ax.set_ylabel("Alert count")
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
fig.savefig("alerts_by_severity.png", dpi=150)   # embed in HTML/DOCX report
```

**ตัวอย่าง 8.3 — สร้างรายงาน incident แบบ DOCX (python-docx)** — *illustrative*; API ตาม [python-docx docs](https://python-docx.readthedocs.io/en/latest/)
```python
import pandas as pd
from docx import Document
from docx.shared import Inches

inc = pd.read_csv("incidents.csv")
doc = Document()
doc.add_heading("Monthly SOC Incident Report", level=0)
doc.add_paragraph(f"Period: {inc['opened'].min()} to {inc['opened'].max()}")
doc.add_heading("Executive summary", level=1)
doc.add_paragraph(
    f"{len(inc)} incidents handled; {int((inc['severity'] == 'critical').sum())} critical. "
    "Top compromise vector: " + inc["vector"].mode().iat[0] + "."
)
doc.add_picture("alerts_by_severity.png", width=Inches(5.5))
doc.add_heading("Incident register", level=1)
cols = ["id", "severity", "title", "status"]
table = doc.add_table(rows=1, cols=len(cols))
table.style = "Light Grid Accent 1"
for i, c in enumerate(cols):
    table.rows[0].cells[i].text = c.upper()
for _, r in inc[cols].iterrows():
    cells = table.add_row().cells
    for i, c in enumerate(cols):
        cells[i].text = str(r[c])
doc.save("soc_monthly_report.docx")
```

**ตัวอย่าง 8.4 — ATT&CK Navigator layer JSON จาก technique ที่ครอบคลุม** — *illustrative*; schema ตาม [Layer format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md) (บังคับ `name`, `domain`; `versions.layer` "4.5", `versions.navigator` ≥ "4.9.0"; technique `score`, `comment`; สี `gradient`)
```python
import json

# e.g. parsed from Sigma/Elastic rule tags -> {technique_id: number_of_rules}
covered = {"T1059.001": 4, "T1059.003": 2, "T1078.004": 1, "T1105": 3, "T1047": 1}

layer = {
    "name": "Detection coverage – 2026-W44",
    "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Number of active detection rules per technique (0 = gap)",
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 4},
    "legendItems": [{"label": "no rules", "color": "#ff6666"},
                    {"label": "4+ rules", "color": "#8ec843"}],
    "techniques": [
        {"techniqueID": tid, "score": min(n, 4),
         "comment": f"{n} rule(s)", "enabled": True, "showSubtechniques": True}
        for tid, n in covered.items()
    ],
    "hideDisabled": False,
    "sorting": 3,
}
with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
# Upload at https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer
```

**ตัวอย่าง 8.5 — ดึงคะแนน EPSS จาก FIRST API แล้วจัดลำดับช่องโหว่** — *illustrative*; endpoint และพารามิเตอร์ตาม [FIRST API docs: GET /epss](https://api.first.org/epss/) (`cve` คั่นด้วย comma ≤2000 ตัวอักษร; ผลลัพธ์ `data[].cve/epss/percentile/date`); ทดสอบสด 2026-11-01 ([example call](https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400&pretty=true)); nomenclature CVSS ตาม [CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document)
```python
import requests, pandas as pd

EPSS = "https://api.first.org/data/v1/epss"
vulns = pd.read_csv("scan_export.csv")          # columns: cve, cvss_base, asset, internet_facing

def epss_batch(cves, size=100):                 # keep the cve= parameter under 2000 chars
    rows = []
    for i in range(0, len(cves), size):
        r = requests.get(EPSS, params={"cve": ",".join(cves[i:i+size])}, timeout=30)
        r.raise_for_status()
        rows += r.json()["data"]
    return pd.DataFrame(rows).astype({"epss": float, "percentile": float})

scores = epss_batch(vulns["cve"].dropna().unique().tolist())
df = vulns.merge(scores, on="cve", how="left")
df["epss"] = df["epss"].fillna(0.0)
# Simple risk rank: likelihood (EPSS) x impact (CVSS-B / 10) x exposure multiplier
df["risk"] = df["epss"] * (df["cvss_base"] / 10) * df["internet_facing"].map({True: 2.0, False: 1.0})
top = df.sort_values("risk", ascending=False)
print(top[["cve", "asset", "cvss_base", "epss", "percentile", "risk"]].head(15).round(3))
top.to_csv("patch_priority.csv", index=False)
```

**ตัวอย่าง 8.6 (สั้น) — รายงาน Markdown เป็น PDF ผ่าน Pandoc** — *illustrative*; CLI ตาม [Pandoc manual](https://pandoc.org/MANUAL.html)
```python
import subprocess, pathlib
md = pathlib.Path("postmortem.md")
md.write_text("# Incident INC-2026-0412 post-mortem\n\n## Timeline\n\n- 09:12 alert fired\n- 09:20 acknowledged\n")
subprocess.run(["pandoc", str(md), "-o", "postmortem.pdf", "--pdf-engine=weasyprint"], check=True)
```

ตัวอย่าง 8.1–8.3 และ 8.6 ครอบคลุมทุก deliverable format ที่ SOC ต้องการ (HTML, PDF, DOCX); 8.4 ให้หลักฐาน detection-engineering (coverage layer); 8.5 ให้ส่วน vulnerability management ทุกชิ้นรับ input เป็น CSV จึงรันกับข้อมูลสังเคราะห์ได้ก่อนต่อ SIEM API

### เอกสารอ้างอิงประจำหัวข้อ

- NIST SP 800-61 Rev. 3 CSRC — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-61r3 PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
- NIST news release — https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations
- NIST CSF 2.0 PDF — https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- SOC-CMM Metrics 101 PDF — https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf
- MITRE 11 Strategies — https://www.mitre.org/11strategies
- cyb3rxp/awesome-soc — https://github.com/cyb3rxp/awesome-soc
- Google SRE Book: Postmortem Culture — https://sre.google/sre-book/postmortem-culture/
- SANS IH-Identification form — https://www.sans.org/media/score/incident-forms/IH-Identification.pdf
- XSOAR playbook: SANS – Lessons Learned — https://demisto.pan.dev/docs/reference/playbooks/sans---lessons-learned
- Lenny Zeltser: Report Template for Incident Response — https://zeltser.com/incident-response-report-template
- PCI SSC document library — https://www.pcisecuritystandards.org/document_library/
- Cloudaware: PCI DSS 4.0.1 §10.4.1 — https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/04/01/
- RSI Security: PCI DSS Requirement 10 — https://blog.rsisecurity.com/tracking-and-monitoring-under-pci-dss-requirement-10/
- ISO/IEC 27001 — https://www.iso.org/standard/27001
- SANS SOC Survey 2025 PDF (Elastic-hosted) — https://www.elastic.co/pdf/sans-soc-survey-2025.pdf
- Red Canary-hosted Gartner Journey Guide — https://redcanary.com/resources/guides/gartner-journey-guide-building-soc
- Gartner abstract 6389843 — https://www.gartner.com/en/documents/6389843
- Forrester ISMM blog — https://www.forrester.com/blogs/10-07-27-the_forrester_information_security_maturity_model/
- Jinja2 docs — https://jinja.palletsprojects.com/en/stable/
- GitHub API pallets/jinja — https://api.github.com/repos/pallets/jinja
- WeasyPrint docs — https://doc.courtbouillon.org/weasyprint/stable/
- Kozea/WeasyPrint — https://github.com/Kozea/WeasyPrint
- docs.reportlab.com — https://docs.reportlab.com/
- ReportLab User Guide PDF — https://www.reportlab.com/docs/reportlab-userguide.pdf
- Pandoc MANUAL — https://pandoc.org/MANUAL.html
- python-docx docs — https://python-docx.readthedocs.io/en/latest/
- python-openxml/python-docx — https://github.com/python-openxml/python-docx
- python-pptx docs — https://python-pptx.readthedocs.io/en/latest/
- scanny/python-pptx — https://github.com/scanny/python-pptx
- matplotlib docs — https://matplotlib.org/stable/
- matplotlib GitHub — https://github.com/matplotlib/matplotlib
- plotly python docs — https://plotly.com/python/
- plotly/plotly.py — https://github.com/plotly/plotly.py
- pandas docs — https://pandas.pydata.org/docs/
- Streamlit docs — https://docs.streamlit.io/
- streamlit/streamlit — https://github.com/streamlit/streamlit
- Elastic: Automating report generation — https://www.elastic.co/docs/explore-analyze/report-and-share/automating-report-generation
- Kibana legacy: automating report generation — https://www.elastic.co/guide/en/kibana/current/automating-report-generation.html
- Kibana Reporting integration — https://www.elastic.co/pt/guide/en/kibana/current/reporting-integration.html
- Grafana Reporting HTTP API (next) — https://grafana.com/docs/grafana/next/developers/http_api/reporting/
- Grafana v12.4 Reporting API — https://grafana.com/docs/grafana/v12.4/developer-resources/api-reference/http-api/reporting.md
- ATT&CK Navigator Layer format v4.5 — https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
- ATT&CK Navigator app — https://mitre-attack.github.io/attack-navigator/
- mitre-attack/attack-navigator — https://github.com/mitre-attack/attack-navigator
- mitreattack-python docs — https://mitreattack-python.readthedocs.io/en/latest/
- mitre-attack/attack-stix-data — https://github.com/mitre-attack/attack-stix-data
- ATT&CK resources — https://attack.mitre.org/resources/
- CVSS v4.0 Specification Document — https://www.first.org/cvss/v4.0/specification-document
- CVSS v4.0 landing — https://www.first.org/cvss/v4-0/
- Sysdig: CVSS 4.0 what's new — https://www.sysdig.com/blog/cvss-version-4-0-whats-new
- Qualys: CVSS v4 is now live — https://blog.qualys.com/product-tech/2023/11/02/cvss-v4-is-now-live-and-what-do-you-need-to-know
- FIRST API docs: GET /epss — https://api.first.org/epss/
- EPSS live call — https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400&pretty=true
- EPSS home — https://www.first.org/epss/
- EPSS: probability vs percentile — https://www.first.org/epss/articles/prob_percentile_bins
- msticpy docs — https://msticpy.readthedocs.io/
- microsoft/msticpy — https://github.com/microsoft/msticpy
- OTRF/ThreatHunter-Playbook — https://github.com/OTRF/ThreatHunter-Playbook
- OTRF/infosec-jupyter-book — https://github.com/OTRF/infosec-jupyter-book
- infosecjupyterbook.com — https://infosecjupyterbook.com/

---

## 9. Security Operations Optimization: SOC-CMM, MITRE Strategy 10 และ coverage สองแกนคือภาษาของการวัดผล

### แหล่งต้นฉบับ

กรอบวุฒิภาวะและ metric ที่เป็นทางการมีลำดับชั้นชัด **MITRE 11 Strategies of a World-Class Cybersecurity Operations Center** (มี.ค. 2022, Knerler, Parker, Zimmerman; ฉบับที่สองของ "10 Strategies") ระบุยุทธศาสตร์ทั้ง 11: 1 Know What You Are Protecting and Why; 2 Give the SOC the Authority to Do Its Job; 3 Build a SOC Structure to Match Your Organizational Needs; 4 Hire and Grow Quality Staff; 5 Prioritize Incident Response; 6 Illuminate Adversaries with Cyber Threat Intelligence; 7 Select and Collect the Right Data; 8 Leverage Tools to Support Analyst Workflow; 9 Communicate Clearly, Collaborate Often, Share Generously; **10 Measure Performance to Improve Performance**; 11 Turn up the Volume by Expanding SOC Functionality ([MITRE 11 Strategies](https://www.mitre.org/11strategies); [Highlights PDF](https://www.mitre.org/sites/default/files/2022-04/11-strategies-world-class-csoc-highlights.pdf); [MITRE press release](https://www.mitre.org/news-insights/news-release/mitre-publishes-11-strategies-world-class-cybersecurity-operations)) **SOC-CMM** "was launched in 2016 as the very first open standard for measuring and improving Security Operations Center maturity", "Originating from a master's thesis" ของ Rob van Os, ปัจจุบันเป็น "broader reference framework" ที่มี metrics suite, รายงานวุฒิภาวะประจำปี และ best practices; spreadsheet ปัจจุบันคือ **v2.4.2** (`soc-cmm-242-basic.xlsx`/`advanced.xlsx`, "All versions 2.x are compatible") มี mapping ไป NIST CSF (v2.3) และ "The CC BY-SA 4.0 licence applies to most SOC-CMM products" โดยหน้าแรกของ soc-cmm.com อ้างคำรับรองจากหนังสือ MITRE 11 Strategies ([SOC-CMM introduction](https://www.soc-cmm.com/introduction); [product page](https://www.soc-cmm.com/products/soc-cmm); [basic xlsx](https://www.soc-cmm.com/img/upload/files/62-soc-cmm-242-basic.xlsx); [advanced xlsx](https://www.soc-cmm.com/img/upload/files/63-soc-cmm-242-advanced.xlsx); [NIST CSF mapping](https://www.soc-cmm.com/img/upload/files/6-soc-cmm-23-nist-csf-mapping.xlsx); [soc-cmm.com](https://www.soc-cmm.com/); [SANS profile Rob van Os](https://www.sans.org/profiles/rob-van-os); [Blueprint podcast](https://sans.org/podcasts/blueprint/maturing-your-cyber-defense-with-rob-van-os)) แหล่งทุติยภูมิเห็นพ้องว่าห้าโดเมนคือ Business, People, Process, Technology, Services โดยทุกโดเมนได้คะแนนวุฒิภาวะ 0–5 และ Technology/Services ได้คะแนน capability 0–3 เพิ่ม ([andrews.hu](https://andrews.hu/en/blog/soc-cmm-model-security-operations-center-framework/); [CISO Tradecraft](https://cisotradecraft.substack.com/p/the-soc-assessment-tool-every-ciso); [2016 v1.1 guide](https://www.scribd.com/document/426096902/dd)) SOC-CMM ยังมี SOC-TOM, หน้า SOC metrics, benchmark, certification และ community ([SOC-TOM](https://soc-cmm.com/soc-tom/); [SOC metrics](https://www.soc-cmm.com/soc-metrics); [certification](https://certification.soc-cmm.com/); [community](https://soc-cmm.discourse.group/))

**SOC-CMM Metrics 101** ให้นิยาม metric ที่เป็นรูปธรรม ด้าน detection engineering: "% Percentage of false positives — The percentage of alerts that fired incorrectly" (L1, trend ลดลง), "% Percentage of benign positives — alerts that fired correctly but were not a security incident" (L1), "# Number of rule tunings applied" (L2), "# Number of rules effectively tuned — rules that have seen a significant decrease in false positives after tuning" (L3), "# Number of false negatives — incidents that did not yield a corresponding alert" (L3, target 0), "Time to develop new detections" (L2, target 1 สัปดาห์); ด้าน coverage: "% MITRE ATT&CK® coverage — The coverage of detection techniques against the organisation's MITRE ATT&CK® profile. Can be visualised using a heatmap" (L2) และ "% MITRE ATT&CK® visibility (data sources) … (see: DETT&CT)" (L2); ด้าน operations: "% Alerts not analysed", "Time to respond to call-out (acknowledge time)", "% Availability of SOC", "% Capacity of SOC", "% Turnover rate", "% Compromise vector" ฯลฯ และย้ำว่า "Your own targets should be set by the organisation and derived from mission, ambition, and goals as defined in the SOC charter" ([SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)) **SANS SOC Metrics Cheat Sheet** (Mark Orlando, 1 พ.ค. 2025) แนะให้สร้าง metric แบบ top-down จากพันธกิจองค์กรและ align กับ SOC-CMM ([SANS cheat sheet](https://www.sans.org/posters/soc-metrics-cheat-sheet)) ด้าน detection-engineering maturity มี **Kyle Bailey's Detection Engineering Maturity Matrix** (เม.ย. 2021, อัปเดต ก.ย. 2022; ระดับ Defined/Managed/Optimized; มิติ People, Process, Technology, Detection; ระบุเองว่า "needs to be updated to include AI") ([detectionengineering.io](https://detectionengineering.io/); [GitHub](https://github.com/k-bailey/detection-engineering-maturity-matrix/blob/main/index.md)) และ **Elastic DEBMM** (6 ก.ย. 2024; Ayenson, DeJesus, Bousseaden; ห้า tier 0–4 แต่ละเกณฑ์ให้คะแนน Initial/Repeatable/Defined/Managed/Optimized; Tier 2 มี "Continuously Tuning and Reducing False Positives", Tier 3 มี "Triaging False Negatives", "External Validation", "Advanced TTP Coverage") ([Elastic DEBMM](https://www.elastic.co/security-labs/elastic-releases-debmm)) แนวคิด SRE ที่นำมาใช้กับ SOC: "Eliminating Toil" นิยาม toil ว่า manual, repetitive, automatable, tactical, ไร้ค่ายั่งยืน และ scale เชิงเส้นกับการเติบโต โดย "Our SRE organization has an advertised goal of keeping operational work (i.e., toil) below 50% of each SRE's time" และ "Toil becomes toxic when experienced in large quantities" ([SRE: Eliminating Toil](https://sre.google/sre-book/eliminating-toil/); [SRE: SLOs](https://sre.google/sre-book/service-level-objectives/))

ตัวเลข benchmark ภายนอกเคลื่อนทุกปี **Mandiant M-Trends 2025** (ข้อมูล 2024): dwell time มัธยฐานโลก **11 วัน** (จาก 10 ในปี 2023; 16 ในปี 2022), 26 วันเมื่อหน่วยงานภายนอกแจ้ง, 5 วันเมื่อผู้โจมตีแจ้งเอง (ส่วนใหญ่ ransomware), 10 วันเมื่อตรวจพบเอง; **M-Trends 2026** (ข้อมูล 2025): **14 วัน**, และกรณี espionage/North-Korean IT-worker มัธยฐาน 122 วัน ([M-Trends 2025](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/); [M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026); [executive edition](https://cloud.google.com/security/resources/m-trends-executive-edition)) **Verizon 2025 DBIR**: >22,000 incident, 12,195 breach ยืนยัน; vulnerability exploitation เป็น initial access ~20% (+34% YoY), credential abuse 22%, phishing 16%; ransomware ใน 44% ของ breach; third-party 30%; ค่าไถ่มัธยฐาน $115,000; 64% ไม่จ่าย; **2026 DBIR**: 31% ของ breach เริ่มจาก software vulnerability (แซง stolen password), 48% เกี่ยวกับ ransomware "but payouts are shrinking", 15% ของ technique ได้แรงหนุนจาก generative AI ([Verizon 2025 DBIR release](https://verizon.com/about/news/2025-data-breach-investigations-report); [Tenable summary](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025); [Verizon DBIR hub](https://www.verizon.com/business/resources/reports/dbir/)) **Red Canary 2026 Threat Detection Report**: telemetry 305 PB จาก 1,700 องค์กรในปี 2025, 110,000 threat ยืนยัน (34,000 severity สูง), analytics map กับ ATT&CK เพื่อติดตามความชุก; top-10 technique (ข้อมูล 2025): T1078.004 Cloud Accounts, T1059.001 PowerShell, T1059.003 Windows Command Shell, T1530 Data from Cloud Storage, T1105 Ingress Tool Transfer, T1114.003 Email Forwarding Rule, T1047 WMI, T1204.004 Malicious Copy and Paste, T1564.008 Email Hiding Rules, T1027 Obfuscated Files or Information ([Red Canary methodology](https://redcanary.com/threat-detection-report/methodology/); [techniques](https://redcanary.com/threat-detection-report/techniques/); [2025 coverage](https://itbrief.com.au/story/red-canary-warns-of-surge-in-identity-ai-threats-for-2025)) **Expel** นิยาม service metric หลักว่า "the median time from alert arrival in Workbench to the first remediation action completed" และระบุ median analyst triage time 3 นาที ([Expel Service Review Dashboard Metrics](https://support.expel.io/hc/en-us/articles/7228662328083-Service-Review-Dashboard-Metrics); [Expel ATR 2025 PDF](https://expel.com/wp-content/uploads/2025/01/Expel-Annual-Threat-Report-2025-013025.pdf); [Expel blog](https://expel.com/blog/its-here-expels-2025-annual-threat-report/); [annual report hub](https://expel.com/annual-report/)) นัยสำคัญ: dwell time 10 → 11 → 14 วัน หมายความว่าหลักสูตรต้องสอนให้อ้างปีของฉบับและ breakdown ตามแหล่งค้นพบ ไม่ใช่ตัวเลขเดี่ยว และ MTTD/MTTR ไม่มีนิยามจากองค์กรมาตรฐานใด — SOC-CMM แยกเป็น "pickup time", "analysis time", "acknowledge time" และ Expel ใช้ "alert-to-first-remediation" ดังนั้นรายงานต้องระบุ event เริ่ม/หยุดนาฬิกาเสมอ

### งานเขียนและเครื่องมือยอดนิยมในชุมชน security

การวัด coverage ต่อ ATT&CK ทำบนสองแกน—*visibility* (data source ที่มี) และ *detection* (technique ที่มี rule)—ให้คะแนนต่อ technique แล้ว render เป็น Navigator heat-map **DeTT&CT** ("Detect Tactics, Techniques & Combat Threats", Rabobank CDC; ≈2.4k ดาว, push ล่าสุด 19 ต.ค. 2026, v2.2.0, GPL-3.0) "helps blue teams using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours" ด้วย Python CLI, YAML, web Editor และ Excel scoring table โดย output คือ "coloured visualisations … made by loading generated JSON layer files into the ATT&CK Navigator" (เช่น `python dettect.py generic -ds`) และมี Dettectinator สำหรับอ่าน detection จาก SIEM/EDR ([DeTT&CT README](https://github.com/rabobank-cdc/DeTTECT); [wiki](https://github.com/rabobank-cdc/DeTTECT/wiki); [editor](https://rabobank-cdc.github.io/dettect-editor)) ฝั่งผู้ผลิต Splunk ES "Detection Studio" map detection library เข้า ATT&CK อัตโนมัติ "to visualize technical coverage in real-time" และเก็บ "a time-series view of the changes in MITRE ATT&CK coverage as detections are turned on, turned off, or updated" ([Splunk blog](https://www.splunk.com/en_us/blog/security/mastering-the-detection-lifecycle-with-detection-studio.html); [Splunk docs](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security)) ขณะที่ elastic/detection-rules (≈2.9k) และ SigmaHQ/sigma (≈11.4k) tag rule ด้วย technique ID ซึ่งเป็นสิ่งที่ coverage script parse การตรวจสอบเชิงประจักษ์ใช้ **Atomic Red Team** (Red Canary; ≈12.7k; "Small and highly portable detection tests based on MITRE's ATT&CK") และ **CALDERA** (GitHub `mitre/caldera` redirect ไป `apache/caldera`, ≈7.5k; "automate adversary emulation, assist manual red-teams, and automate incident response"; Python 3.10+; agent Sandcat; plugin Atomic/Stockpile/Emu) ([atomic-red-team](https://github.com/redcanaryco/atomic-red-team); [atomicredteam.io](https://atomicredteam.io/); [apache/caldera](https://github.com/apache/caldera); [CALDERA docs](https://caldera.readthedocs.io/en/latest/)) ผู้ปฏิบัติเตือนไม่ให้ไล่ 100% coverage: "Aiming for full coverage would mean tremendous efforts spent on building detection measures against threats that might never materialize" ([Wiz Academy](https://www.wiz.io/api/md/academy/detection-and-response/soc-metrics)) และ awesome-soc ลิงก์ CTID Mappings Explorer, SANS continuous purple teaming และ TIBER-EU purple best practices (ECB, 2025) ([SANS continuous purple teaming](https://www.sans.org/blog/continuous-purple-teaming-practical-approach-strengthening-offensive-capabilities); [TIBER-EU 2025](https://www.ecb.europa.eu/pub/pdf/annex/ecb.tiber_eu_purple_best_practices_2025.en.pdf); [CTID mappings explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/))

ดัชนีชุมชนที่ดีที่สุดสำหรับหลักสูตรคือ **cyb3rxp/awesome-soc** (≈1.9k, push ล่าสุด 20 ต.ค. 2026) ที่มีหมวด Fundamental concepts, SOC internals/core, AI, SOAR, Detection engineering, Threat intelligence, Playbooks/SOP, SOC metrics (KPI/SLA), SOC Management, HR and training, IT architecture และหน้า metrics ที่อ้าง MITRE Strategy 10 (หน้า 301–318), SOC-CMM Metrics 101, SANS SOC survey 2025/2022 และ Gartner "Cybersecurity business value benchmark" ส่วนหน้า maturity อ้าง MITRE 11 Strategies, SOC-CMM, SOC-TOM, Microsoft "SOC/IR hierarchy of needs", DeTT&CT ([awesome-soc](https://github.com/cyb3rxp/awesome-soc); [metrics-kpi.md](https://github.com/cyb3rxp/awesome-soc/blob/main/metrics-kpi.md); [detection_engineering.md](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md); [Microsoft hierarchy PDF](https://download.microsoft.com/download/E/6/2/E62530BF-47CC-4527-88BA-F13DF5294A65/HierarchyofCybersecurityNeeds.pdf); [Gartner value benchmark PDF](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)) ร่วมกับ **infosecB/awesome-detection-engineering** (≈1.4k) ([GitHub](https://github.com/infosecB/awesome-detection-engineering)) และ OTRF ThreatHunter-Playbook (≈4.7k) Splunk นิยาม "MTTD measures the average time a SOC team takes to detect an incident or a security breach" และให้ detection ที่ tag ATT&CK ผ่าน research.splunk.com ([Splunk security monitoring](https://splunk.com/en_us/solutions/security-monitoring.html); [research.splunk.com](https://research.splunk.com)) blog ของผู้ผลิตให้ threshold ที่ **ไม่ตรงกันและเป็นความเห็น**: FP rate เกิน 50% ในหมวดหนึ่ง "indicates significant tuning work needed" (แหล่งหนึ่ง) กับเกิน 30% (อีกแหล่ง); 5–30 alert/วัน ต่อ L1 analyst กับต่ำกว่า 50; "organizations typically cover 20 to 40 percent of relevant techniques; 60 percent or above is strong coverage"; ควรติดตาม MTTD "separately by attack technique category"; และควรใช้ median แทน mean ([Secure.com](https://www.secure.com/blog/soc-metrics-and-kpis); [CyberDefenders](https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/); [Prophet Security](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more); [Decryption Digest](https://www.decryptiondigest.com/blog/soc-metrics-and-kpis)) คำเตือนที่ถูกอ้างซ้ำ (ให้เครดิต UK NCSC ผ่าน ReliaQuest) คือเลี่ยง "easily quantifiable metrics like 'number of tickets processed', 'time taken to close a ticket', 'number of detection rules written', and 'volume of logs'" และวัดประสิทธิผลด้วย red/purple teaming ([ReliaQuest](https://reliaquest.com/blog/cybersecurity-metrics/)) และบทความแย้ง "Why MTTD is the wrong metric to obsess over" (Techspective, มิ.ย. 2026) ([Techspective](https://techspective.net/2026/06/17/why-mttd-is-wrong-metric-to-obsess-over/)) จาก SANS 2025 SOC Survey: EDR เป็น "the most trusted and mature tool in use. AI/ML is at the bottom of the satisfaction list", threat hunting ส่วนใหญ่เป็น "partially automated hunting using vendor-provided tools (48%)", และ "62% of respondents express a clear lack of confidence" ในการรักษาคน ขณะที่ปี 2023 รายงานว่า 84% ของ SOC เก็บ metric ([SANS 2025 PDF](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf); [Dropzone](https://content.dropzone.ai/2025-sans-soc-survey-report); [Prophet](https://resources.prophetsecurity.ai/sans-soc-survey-2025); [Anomali SANS 2023](https://anomali.com/resources/whitepapers/sans-2023-soc-survey); [SANS/Anvilogic webcast](https://sans.org/webcasts/insights-into-detection-engineering-findings-from-a-sans-and-anvilogic-survey)) และ Gartner มี SOC Model Guide (build/outsource/hybrid), "Choose the Right Tools in Your Security Operations Maturity Journey" (21 ม.ค. 2025) และ Hype Cycle for Security Operations 2025 (23 มิ.ย. 2025) ([Vectra-hosted SOC Model Guide](https://vectra.ai/resources/gartner-soc-model-guide); [Expel-hosted Hype Cycle 2025](https://expel.com/gartner-hype-cycle-security-operations-2025/); [Gartner abstract](https://www.gartner.com/en/documents/5088831)) pipeline coverage ขั้นต่ำด้วย Python คือ parse metadata ของ rule (Sigma/Elastic `tags: attack.tXXXX`) → ชุด technique ID ที่ครอบคลุม → เทียบกับ technique universe จาก `mitreattack-python` (หรือกรองตาม threat profile จาก DeTT&CT group YAML) → ออก Navigator v4.5 layer ที่มี `score` ต่อ technique → (ทางเลือก) รัน Atomic test สำหรับ technique ที่ครอบคลุมแล้วบันทึกว่า alert เกิดหรือไม่ โดย visibility เป็น leading indicator และ detection เป็น lagging indicator รายงานประจำสัปดาห์ควรแสดงทั้งคู่พร้อม delta จากสัปดาห์ก่อน ส่วน threshold ของผู้ผลิตควรสอนเป็น *ตัวอย่างของเป้าหมายที่ตั้งเอง* ตามที่ SOC-CMM ระบุ และ SOC-CMM เป็นโมเดลเปิดเพียงตัวเดียว (CC BY-SA 4.0, spreadsheet) ที่ทั้ง MITRE และ SANS ชี้ไป จึงเหมาะเป็น "scoring engine" ของโปรเจ็กต์ Python (อ่าน xlsx ด้วย pandas/openpyxl)

### ตัวอย่างโค้ด

**ตัวอย่าง 9.1 — เปอร์เซ็นต์ coverage เทียบกับรายการ technique ทั้งหมด (mitreattack-python)** — *illustrative*; API ตาม [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/) (`MitreAttackData`, `get_techniques`, `get_attack_id`); ข้อมูลจาก [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
```python
# pip install mitreattack-python ; download enterprise-attack.json from attack-stix-data
from mitreattack.stix20 import MitreAttackData
import json

attack = MitreAttackData("enterprise-attack.json")
techs = attack.get_techniques(remove_revoked_deprecated=True)
universe = {attack.get_attack_id(t) for t in techs}

layer = json.load(open("coverage_layer.json"))
covered = {t["techniqueID"] for t in layer["techniques"] if t.get("score", 0) > 0}

coverage_pct = 100 * len(covered & universe) / len(universe)
print(f"{len(covered & universe)}/{len(universe)} techniques covered = {coverage_pct:.1f}%")
gaps = sorted(universe - covered)
print("first 10 gaps:", gaps[:10])
```

**ตัวอย่าง 9.2 — MTTD และ MTTR จาก ticket export (pandas)** — *illustrative*; pandas API ตาม [pandas docs](https://pandas.pydata.org/docs/); นิยามนาฬิกาตามข้อเตือนของผู้ปฏิบัติว่า MTTD อาจหมายถึง activity→alert, alert→acknowledge หรือ alert→confirm ([Prophet Security](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more)); รายงาน median เคียง mean
```python
import pandas as pd

t = pd.read_csv("tickets.csv", parse_dates=["first_activity", "alerted", "acknowledged", "resolved"])
# Clock definitions (state them in the report!):
t["ttd_h"] = (t["alerted"] - t["first_activity"]).dt.total_seconds() / 3600   # detection
t["tta_m"] = (t["acknowledged"] - t["alerted"]).dt.total_seconds() / 60       # pickup
t["ttr_h"] = (t["resolved"] - t["alerted"]).dt.total_seconds() / 3600         # response/resolve

def summarise(g):
    return pd.Series({
        "n": len(g),
        "MTTD_mean_h": g["ttd_h"].mean(), "MTTD_median_h": g["ttd_h"].median(),
        "MTTA_median_min": g["tta_m"].median(),
        "MTTR_mean_h": g["ttr_h"].mean(), "MTTR_median_h": g["ttr_h"].median(),
        "p90_TTR_h": g["ttr_h"].quantile(0.9),
    })

by_sev = t.groupby("severity").apply(summarise).round(1)
overall = summarise(t).round(1)
print(by_sev, "\n\nOverall:\n", overall)
# Weekly trend for the executive chart
weekly = t.set_index("alerted").resample("W")[["ttd_h", "ttr_h"]].median()
weekly.to_csv("weekly_mttd_mttr.csv")
```

**ตัวอย่าง 9.3 — อัตรา false positive ต่อ detection rule และการจัดลำดับ tuning** — *illustrative*; นิยาม metric ตาม SOC-CMM Metrics 101 ("% Percentage of false positives – alerts that fired incorrectly"; "% benign positives – fired correctly but not an incident") ([SOC-CMM Metrics 101](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf))
```python
import pandas as pd

a = pd.read_csv("alerts_triaged.csv")   # columns: rule, disposition in {true_positive, benign_positive, false_positive}
piv = pd.crosstab(a["rule"], a["disposition"]).reindex(
    columns=["true_positive", "benign_positive", "false_positive"], fill_value=0)
piv["total"] = piv.sum(axis=1)
piv["fp_rate"] = piv["false_positive"] / piv["total"]
piv["bp_rate"] = piv["benign_positive"] / piv["total"]
piv["precision"] = piv["true_positive"] / piv["total"]

# Tuning priority = analyst minutes wasted: FP volume weighted by FP rate (noisy AND wrong)
piv["tuning_score"] = piv["false_positive"] * piv["fp_rate"]
ranked = piv[piv["total"] >= 20].sort_values("tuning_score", ascending=False)

print(ranked.head(10).round(2))
ranked.head(10).to_csv("rules_to_tune.csv")
org_fp = piv["false_positive"].sum() / piv["total"].sum()
print(f"Org-wide FP rate: {org_fp:.1%}  (SOC-CMM target: trend decreasing)")
```

**ตัวอย่าง 9.4 — โครง Streamlit SOC dashboard** — *illustrative*; API ตาม [Streamlit docs](https://docs.streamlit.io/) (`st.metric`, `st.columns`, `st.bar_chart`, `st.dataframe`, `st.sidebar`); รันด้วย `streamlit run soc_dashboard.py`
```python
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC Dashboard", layout="wide")
st.title("SOC Operations Dashboard")

alerts = pd.read_csv("alerts.csv", parse_dates=["fired_at"])
tickets = pd.read_csv("tickets.csv", parse_dates=["alerted", "resolved"])
days = st.sidebar.slider("Window (days)", 1, 90, 7)
cutoff = pd.Timestamp.now() - pd.Timedelta(days=days)
a, t = alerts[alerts["fired_at"] >= cutoff], tickets[tickets["alerted"] >= cutoff]

mttr_h = (t["resolved"] - t["alerted"]).dt.total_seconds().div(3600).median()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts", len(a))
c2.metric("Incidents", len(t))
c3.metric("Median TTR (h)", f"{mttr_h:.1f}")
c4.metric("Open incidents", int(t["resolved"].isna().sum()))

st.subheader("Alerts by severity")
st.bar_chart(a["severity"].value_counts())
st.subheader("Noisiest rules")
st.bar_chart(a["rule"].value_counts().head(10))
st.subheader("Incident register")
st.dataframe(t.sort_values("alerted", ascending=False), use_container_width=True)
```

ตัวอย่าง 8.4/9.1 และ 9.3 ผลิตหลักฐาน detection-engineering (coverage layer, coverage %, tuning backlog); 9.2 และ 9.4 ผลิต KPI ปฏิบัติการ รวมกับหัวข้อ 8 แล้วได้โปรเจ็กต์ "weekly SOC report generator" ที่เชื่อมโยงกัน

### เอกสารอ้างอิงประจำหัวข้อ

- MITRE 11 Strategies — https://www.mitre.org/11strategies
- MITRE 11 Strategies highlights PDF — https://www.mitre.org/sites/default/files/2022-04/11-strategies-world-class-csoc-highlights.pdf
- MITRE press release — https://www.mitre.org/news-insights/news-release/mitre-publishes-11-strategies-world-class-cybersecurity-operations
- SOC-CMM introduction — https://www.soc-cmm.com/introduction
- SOC-CMM product page — https://www.soc-cmm.com/products/soc-cmm
- SOC-CMM 2.4.2 basic xlsx — https://www.soc-cmm.com/img/upload/files/62-soc-cmm-242-basic.xlsx
- SOC-CMM 2.4.2 advanced xlsx — https://www.soc-cmm.com/img/upload/files/63-soc-cmm-242-advanced.xlsx
- SOC-CMM → NIST CSF mapping xlsx — https://www.soc-cmm.com/img/upload/files/6-soc-cmm-23-nist-csf-mapping.xlsx
- SOC-CMM Metrics 101 PDF — https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf
- soc-cmm.com — https://www.soc-cmm.com/
- SOC-TOM — https://soc-cmm.com/soc-tom/
- SOC-CMM SOC metrics — https://www.soc-cmm.com/soc-metrics
- SOC-CMM certification — https://certification.soc-cmm.com/
- SOC-CMM community — https://soc-cmm.discourse.group/
- SANS profile: Rob van Os — https://www.sans.org/profiles/rob-van-os
- SANS Blueprint podcast with Rob van Os — https://sans.org/podcasts/blueprint/maturing-your-cyber-defense-with-rob-van-os
- andrews.hu SOC-CMM overview — https://andrews.hu/en/blog/soc-cmm-model-security-operations-center-framework/
- CISO Tradecraft on SOC-CMM — https://cisotradecraft.substack.com/p/the-soc-assessment-tool-every-ciso
- SOC-CMM 2016 v1.1 guide (Scribd) — https://www.scribd.com/document/426096902/dd
- SANS SOC Metrics Cheat Sheet — https://www.sans.org/posters/soc-metrics-cheat-sheet
- Kyle Bailey Detection Engineering Maturity Matrix — https://detectionengineering.io/
- k-bailey/detection-engineering-maturity-matrix — https://github.com/k-bailey/detection-engineering-maturity-matrix/blob/main/index.md
- Elastic Security Labs DEBMM — https://www.elastic.co/security-labs/elastic-releases-debmm
- infosecB/awesome-detection-engineering — https://github.com/infosecB/awesome-detection-engineering
- Google SRE Book: Eliminating Toil — https://sre.google/sre-book/eliminating-toil/
- Google SRE Book: Service Level Objectives — https://sre.google/sre-book/service-level-objectives/
- Google Cloud: M-Trends 2025 — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/
- Google Cloud: M-Trends 2026 — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026
- M-Trends executive edition — https://cloud.google.com/security/resources/m-trends-executive-edition
- Verizon 2025 DBIR news release — https://verizon.com/about/news/2025-data-breach-investigations-report
- Tenable summary of 2025 DBIR — https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025
- Verizon DBIR hub — https://www.verizon.com/business/resources/reports/dbir/
- Red Canary Threat Detection Report methodology — https://redcanary.com/threat-detection-report/methodology/
- Red Canary techniques — https://redcanary.com/threat-detection-report/techniques/
- IT Brief: Red Canary 2025 report — https://itbrief.com.au/story/red-canary-warns-of-surge-in-identity-ai-threats-for-2025
- Expel Annual Threat Report 2025 PDF — https://expel.com/wp-content/uploads/2025/01/Expel-Annual-Threat-Report-2025-013025.pdf
- Expel blog: 2025 Annual Threat Report — https://expel.com/blog/its-here-expels-2025-annual-threat-report/
- Expel annual report hub — https://expel.com/annual-report/
- Expel ATR 2025 page — https://expel.com/annual-threat-report-2025/
- Expel Service Review Dashboard Metrics — https://support.expel.io/hc/en-us/articles/7228662328083-Service-Review-Dashboard-Metrics
- Vectra-hosted Gartner SOC Model Guide — https://vectra.ai/resources/gartner-soc-model-guide
- Expel-hosted Gartner Hype Cycle 2025 — https://expel.com/gartner-hype-cycle-security-operations-2025/
- Gartner abstract 5088831 — https://www.gartner.com/en/documents/5088831
- rabobank-cdc/DeTTECT — https://github.com/rabobank-cdc/DeTTECT
- DeTT&CT wiki — https://github.com/rabobank-cdc/DeTTECT/wiki
- DeTT&CT Editor — https://rabobank-cdc.github.io/dettect-editor
- Splunk blog: Detection Studio — https://www.splunk.com/en_us/blog/security/mastering-the-detection-lifecycle-with-detection-studio.html
- Splunk docs: Detection Studio coverage — https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security
- redcanaryco/atomic-red-team — https://github.com/redcanaryco/atomic-red-team
- atomicredteam.io — https://atomicredteam.io/
- apache/caldera — https://github.com/apache/caldera
- CALDERA docs — https://caldera.readthedocs.io/en/latest/
- Wiz Academy: SOC metrics — https://www.wiz.io/api/md/academy/detection-and-response/soc-metrics
- SANS: Continuous purple teaming — https://www.sans.org/blog/continuous-purple-teaming-practical-approach-strengthening-offensive-capabilities
- ECB TIBER-EU purple best practices 2025 — https://www.ecb.europa.eu/pub/pdf/annex/ecb.tiber_eu_purple_best_practices_2025.en.pdf
- CTID Mappings Explorer — https://center-for-threat-informed-defense.github.io/mappings-explorer/external/
- cyb3rxp/awesome-soc — https://github.com/cyb3rxp/awesome-soc
- awesome-soc metrics-kpi.md — https://github.com/cyb3rxp/awesome-soc/blob/main/metrics-kpi.md
- awesome-soc detection_engineering.md — https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md
- Microsoft Hierarchy of Cybersecurity Needs PDF — https://download.microsoft.com/download/E/6/2/E62530BF-47CC-4527-88BA-F13DF5294A65/HierarchyofCybersecurityNeeds.pdf
- Gartner Cybersecurity Business Value Benchmark PDF — https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf
- Splunk security monitoring — https://splunk.com/en_us/solutions/security-monitoring.html
- research.splunk.com — https://research.splunk.com
- Secure.com: SOC metrics and KPIs 2026 — https://www.secure.com/blog/soc-metrics-and-kpis
- CyberDefenders: SOC metrics — https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/
- Prophet Security: SOC metrics that matter — https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more
- Decryption Digest: SOC metrics and KPIs — https://www.decryptiondigest.com/blog/soc-metrics-and-kpis
- ReliaQuest: cybersecurity metrics — https://reliaquest.com/blog/cybersecurity-metrics/
- Techspective: Why MTTD is the wrong metric — https://techspective.net/2026/06/17/why-mttd-is-wrong-metric-to-obsess-over/
- Dropzone: SANS 2025 SOC survey report — https://content.dropzone.ai/2025-sans-soc-survey-report
- Prophet Security: SANS SOC survey 2025 — https://resources.prophetsecurity.ai/sans-soc-survey-2025
- Anomali: SANS 2023 SOC survey — https://anomali.com/resources/whitepapers/sans-2023-soc-survey
- SANS/Anvilogic detection engineering webcast — https://sans.org/webcasts/insights-into-detection-engineering-findings-from-a-sans-and-anvilogic-survey
- SANS white papers index — https://www.sans.org/white-papers/
- SANS 2022 SOC survey (reading-room URL) — https://www.sans.org/reading-room/whitepapers/analyst/2022-sans-soc-survey/

---

## บทสรุป: สอน "ความสามารถ" ไม่ใช่ผลิตภัณฑ์ และให้ schema เป็นสันหลังของทั้งสอง module

ข้อค้นพบที่สำคัญเกินกว่าการรวบรวมรายการเครื่องมือคือ **ทุกหัวข้อในหลักสูตรมี "มาตรฐานเปิดที่กำหนดรูปร่างข้อมูล" กำกับอยู่** และนั่นคือสิ่งที่คงทนกว่า library ใด ๆ: RFC 5424 กำหนด syslog parser, ECS/OCSF กำหนด field ปลายทางที่ Sigma pipeline และ SIEM ใช้, STIX 2.1/TAXII 2.1 กำกับทั้ง IOC exchange และ ATT&CK, OCSF Detection Finding (class_uid 2004) ให้ schema ขั้นต่ำของ alert pipeline, CACAO 2.0 ให้คำศัพท์ playbook ที่เป็นกลาง และ Navigator layer v4.5 ให้ format ของ coverage report เมื่อ runtime ของผู้ผลิตเปลี่ยน (TheHive ถูก archive และกลายเป็นเชิงพาณิชย์, pyattck และ OpenCTI client-python ถูก archive, Azure Data Collector API ถูก deprecate, abuse.ch ย้ายไปใช้ Auth-Key, Gartner ประกาศ SOAR obsolete, SEC573 เปลี่ยนชื่อไปทาง LLM/MCP) ทักษะที่ตั้งอยู่บน schema เหล่านี้ยังคงใช้ได้ ข้อค้นพบที่สองคือ **ตัวเลขที่ใช้ใน SOC แทบไม่มีตัวใดเป็นมาตรฐาน**: threshold brute-force 5/60 s, CV < 0.3 สำหรับ beacon, dedupe window 5–15 นาที, FP rate 30% หรือ 50%, coverage 20–40% ล้วนเป็นธรรมเนียมจากผู้ผลิตหรือ repo ขนาดเล็ก ขณะที่สิ่งที่มีมาตรฐานจริงคือ *นิยาม* (SOC-CMM Metrics 101 แยก false positive ออกจาก benign positive; Expel นิยามนาฬิกา alert-to-first-remediation) ดังนั้นโค้ดทุกชิ้นในรายงานนี้จึงเปิดเผย threshold เป็นค่าคงที่ที่มีชื่อ และหลักสูตรควรสอนให้นักเรียนระบุ clock-start/clock-stop ทุกครั้งที่รายงาน MTTD/MTTR

นัยต่อการออกแบบหลักสูตร: Module 5 ควรไล่จาก stdlib เพียว (ตัวอย่าง 1.1–1.3, 2.1, 3.1–3.3) ไปสู่การเพิ่ม third-party ทีละตัว (pandas, drain3, pysigma, zat, requests+Retry, stix2/taxii2-client) โดยให้ KEV และ ATT&CK TAXII เป็น integration แรกเพราะไม่ต้อง auth และมี schema ชัด ส่วน Module 6 ควรจบด้วย pipeline ที่ต่อตัวอย่าง 7.1 → 7.2 → 6.1/7.4 → 8.1/8.4/9.1–9.3 เป็นโปรเจ็กต์เดียว โดยใช้ platform ฟรี (Wazuh/Elastic → FastAPI → TheHive 5 + Cortex → Shuffle/n8n → Jira) และวางผลลัพธ์ตัวเลขทั้งหมดบนนิยามของ SOC-CMM กับ MITRE Strategy 10 เพราะ 69% ของ SOC ยังรายงาน metric ด้วยมือ และเกือบครึ่งมี false positive เกินครึ่ง โปรเจ็กต์ที่ปิดวงจร "triage outcome → rule tuning → coverage delta รายสัปดาห์" คือสิ่งที่สร้างความแตกต่างได้มากที่สุดต่อ SOC จริง สิ่งที่ยังไม่พบในรอบการค้นคว้านี้คือ repository สาธารณะที่มีดาวสูงซึ่งทำสิ่งเหล่านี้ครบวงจรเป็น Python ตัวอย่างของหลักสูตรจึงมีแนวโน้มจะกลายเป็น reference หลักของนักเรียนเอง และนั่นทำให้การ smoke-test โค้ดทุกชิ้นก่อนเผยแพร่เป็นข้อบังคับ ไม่ใช่ทางเลือก

---

## ข้อจำกัดของการค้นคว้า

ข้อจำกัดต่อไปนี้รวบรวมจากส่วน Gaps ของบันทึกการค้นคว้าทั้งห้าชุด (รวบรวม 2026-11-01) ผู้สอนควรตรวจสอบก่อนนำไปใช้

**ข้อจำกัดทั่วไปที่กระทบทุกหัวข้อ**
- **ไม่มี snippet ใดถูกรันจริงในรอบการค้นคว้า** (ไม่มี API key, ไม่มีการรันเครือข่าย) ทุกชิ้นตรวจความสอดคล้องกับ README/เอกสารเท่านั้น โดยเฉพาะ snippet ที่ทำเครื่องหมาย illustrative ควร smoke-test ก่อนใช้ในชั้นเรียน
- **จำนวนดาว GitHub เป็นค่า ณ 2026-11-01** และจะเปลี่ยนไป; บางตัวเลขต่างกันระหว่าง GitHub กับ aggregator (เช่น awesome-threat-intelligence 10.8k บน GitHub เทียบ 10,483 บน aggregator; IntelOwl 4.8k เทียบ 4.6k) โดย GitHub ถือเป็นแหล่งอ้างอิง; ดาวของ `mitre/caldera` ปัจจุบันสะสมที่ `apache/caldera`
- หน้าเว็บหลายแห่ง **ปฏิเสธการดึงอัตโนมัติ** (HTTP 403/404/429): gartner.com, mitre.org (หน้า publication และ highlights PDF ในหนึ่งรอบ), docs.splunk.com, iso.org, O'Reilly/Packt (TOC หนังสือ), Medium บางบทความ, Koldunov notebook (429), dabeaz.com (TLS error) ทำให้ต้องอ้างแหล่งทุติยภูมิหรือ mirror ในหลายจุด
- **ไม่พบเวอร์ชัน release ล่าสุด** ของ Plaso, python-evtx (Alpine บอก 0.8.0 แต่ Debian sid บอก 8.1.0 — ขัดแย้งกัน), stix2, taxii2-client, msticpy, PyMISP, shuffle-sdk (เห็นล่าสุด 0.0.8) จากหน้า GitHub ที่ดึงมา ควรตรวจบน PyPI
- ไม่พบ **SANS Reading Room / GIAC paper** ที่เจาะจง Python log analysis, Python SOC automation หรือ Python CTI automation ในการค้นหา (ใกล้เคียงที่สุดคือ ISC diaries และ O'Brien 2016) ข้ออ้างจาก blog ว่ามี "2025 SANS survey" แสดงว่าทีมที่ script งานซ้ำลด MTTR ได้ถึง 40% **สืบไปถึงแหล่ง SANS ไม่ได้และไม่ควรอ้าง**

**หัวข้อ 1–2 (Fundamentals, Log Analysis)**
- ไม่ได้ดึงถ้อยคำเฉพาะของเอกสาร `json`, `pathlib`, `datetime`; หน้า SEC573 ไม่กล่าวถึง pandas จึงยืนยันไม่ได้ว่า lab ปัจจุบันสอน pandas; ไม่มีแหล่ง peer-reviewed ที่จัดอันดับ "essential modules" รายการที่ให้คือการ triangulate จากหลักสูตรและเอกสารเครื่องมือ; ไม่ได้ดึง citation count ของหนังสือ; ไม่ได้ดึง TOC ระดับบทของ Poston
- หน้า Getting Started ของ pySigma ดึงไม่ได้ (404) ตัวอย่าง 2.5 จึงเป็น illustrative และควรรันกับ pySigma รุ่นปัจจุบัน; ไม่พบสูตร scoring ที่แน่นอนของ RITA ในเอกสารทางการ; ตัวเลข precision/recall >95% ของ DeepLog มาจากสรุปทุติยภูมิภาษาจีนและไม่ได้ตรวจกับ paper
- สถานะ final ของ NIST SP 800-92 Rev. 1 ยืนยันไม่ได้ (พบเฉพาะ IPD ต.ค. 2023); ไม่ได้อ้างรายละเอียดระดับ field ของ ECS (`@timestamp`, `message`, `event.*`); ไม่ได้ดึงเอกสาร EVTX ของ Microsoft เอง (libevtx เป็น spec de facto)
- repo brute-force ทั้งหมดเป็นงานอดิเรกที่มีดาวน้อย threshold เป็นธรรมเนียม; **threshold CV < 0.3** สำหรับ beacon พบเฉพาะใน skill mirror ของชุมชน ยืนยันจากแหล่งต้นทางไม่ได้; `follow.py` ต้นฉบับของ Beazley ดาวน์โหลดไม่ได้ ตัวอย่าง 1.2 เป็นการเขียนใหม่ของ idiom

**หัวข้อ 3–4 (Automation Scripts, API Integration)**
- หน้า NVD developer เป็น JavaScript-rendered; limit 5/50 ต่อ 30 วินาทีและ sleep 6 วินาทียืนยันผ่าน search summary และแหล่งทุติยภูมิ; `resultsPerPage` สูงสุด 2000 มาจากบทความ DEV Community; ช่วงวันที่สูงสุด 120 วันยืนยันไม่ได้
- ไม่พบแหล่งทางการที่กำหนด "logging pattern สำหรับ security script"; ไม่ได้ดึงเอกสาร aiohttp และ `urllib`
- ไม่พบ rate limit ต่อวินาทีของ Shodan บนหน้า REST API; endpoint FIM ของ Wazuh และอายุ token default ไม่อยู่ในหน้าที่ดึง; หน้า `.nessus` file format ของ Tenable คืน 404 จึงไม่มี snippet parse .nessus/OpenVAS; vt-py README ไม่แสดงคำสั่งติดตั้ง/asyncio; หน้า GitHub ของ python-nmap (`nmmapper/python-nmap`) คืน 404; ไม่ได้ดึงดาวของ pyTenable, python-nmap mirror, shodan-python
- ชื่อ header `x-apikey` ของ VirusTotal ไม่ปรากฏบนหน้าที่ดึง; รายการ security-scheme type ของ OpenAPI (§4.27) ยืนยันไม่ได้เพราะส่วนที่ดึงจบก่อนถึงตาราง; ไม่มีแหล่งครอบคลุม mutual-TLS หรือ private_key_jwt
- ตัวอย่าง 3.3 อาศัย Nmap DTD ที่ไม่ได้ดึง; ไม่มี snippet ของ Splunk SDK search (`service.jobs.oneshot`) หรือ pyTenable `tio.exports.vulns()` เพราะหน้าที่ดึงไม่แสดงตัวอย่าง

**หัวข้อ 5 (Threat Intelligence)**
- ตารางคุณสมบัติบังคับของ Indicator ใน STIX 2.1 §4.7 ไม่ได้อ่านจาก OASIS HTML โดยตรง (หน้า ~700k ตัวอักษร อ่าน 100k แรก) จึงอ้างจากเอกสาร stix2; หน้า OASIS ไม่สอดคล้องกันเองเรื่องป้ายสถานะ ("OASIS Standard incorporating Draft 01 of Errata 01" vs "Committee Specification Draft 01") — ให้อ้างเป็น STIX 2.1 Errata 01 (2025); ไม่พบวันปลดระวาง TAXII 2.0 server เดิม `cti-taxii.mitre.org`; ช่วงหน้าของ Hutchins et al. ไม่สอดคล้องระหว่างดัชนี (1–14 vs 80–)
- ลายเซ็นเต็มของ PyMISP `search()` ยืนยันไม่ได้; `iocextract.extract_iocs()` ไม่ปรากฏใน README ที่ดึง; รายการ key ของ `ioc-finder` (cves, attack_techniques) ยืนยันไม่ได้; `misp.search(controller="attributes", ...)`, `otx.getsince_iter(since, limit=...)` และ filter syntax ของ pycti `marking_definition.read()` มาจากธรรมเนียมของ library ไม่ใช่หน้าที่ดึง
- ชื่อคอลัมน์ CSV ของ URLhaus และ Feodo Tracker ยืนยันไม่ได้ (เอกสารดาวน์โหลดอยู่หลัง login และ endpoint เดิมหายไป) ตัวอย่าง 5.8 จึงค้นหา column ตอน runtime; ไม่พบ rate limit ทางการของ OTX; โควตารายเดือนของ VT ไม่ได้ยืนยัน; ไม่ได้ดึง ThreatFox API
- หน้า Recorded Future มีสามวันที่ (2020/2024/2026) — อ้างเป็น "2020, updated 2024"; TOC ของหนังสือ Brown/Roberts และ Costa-Gazcón ดึงไม่ได้ (403) โมเดล F3EAD จึงไม่ได้ยืนยันจากหน้าที่ดึง; หน้า FOR578 ไม่กล่าวถึง Pyramid of Pain
- ไม่พบ blog post ที่เป็นกลางและถูกอ้างกว้างขวางซึ่งเดินผ่าน script enrichment VT + AbuseIPDB + OTX; ผลค้นหาถูกครอบงำด้วย blog ผู้ผลิตและ "agent skill" mirror ที่ไม่ทราบที่มา; ไม่ได้ดึงรายชื่อ session เต็มของ CTI Summit 2025

**หัวข้อ 6–7 (Workflow Automation, Alert Processing)**
- ถ้อยคำปี 2017 ของ Gartner อ้างจาก Gartner โดยตรงไม่ได้ (paywall/403); ที่มาของป้าย "obsolete before plateau" ขัดแย้งระหว่าง Security Operations Hype Cycle (29 ก.ค. 2024) กับ ITSM Hype Cycle (17 มิ.ย. 2024) ทั้งคู่รายงานโดยผู้ผลิต
- หน้า SANS Handbook ยืนยัน "six phases" แต่ไม่ได้ระบุชื่อ ต้องตรวจใน PDF; ยืนยันจากแหล่งต้นทางไม่ได้ว่า OCSF deprecate Security Finding (2001) อย่างเป็นทางการ (ช่วงเวอร์ชันใน Tenzir mirror บ่งชี้เช่นนั้น)
- docs.splunk.com คืน 403 จึงใช้ help.splunk.com (SOAR Cloud) แทน และไม่ได้โค้ด tutorial แบบ verbatim; หน้า PyPI ของ Shuffle ไม่ render; `shuffler.io/docs/app_creation` คืน "Couldn't find documentation"; รายการ connector ของ Elastic rule actions ไม่ได้ดึง; ข้อจำกัดของ Tines (python3.9, 25 s) อาจล้าสมัยตาม caveat ของเอกสารเอง; `Shuffle/Shuffle-Tools` ไม่มีเป็น repo (เป็น app ใน python-apps)
- ไม่พบสเปก scoring/dedupe window ที่ vendor-neutral หรือ peer-reviewed ตัวเลขทั้งหมด (5 นาที, 80% FP reduction) มาจากผู้ผลิตรายเดียว; ไม่พบบทความเจาะจงของ Alex Teixeira เรื่อง alert triage หรือ essay "Detection Engineering" ของ Florian Roth (ดึงได้เฉพาะ YARA Forge); PDF ของ SANS 2025 SOC Survey ที่ elastic.co ดึงมาได้เพียงหน้าปกในหนึ่งรอบ เปอร์เซ็นต์หลายตัวมาจากสรุปของผู้ผลิต; ไม่พบ "IDC alert overload" survey
- ชื่อพารามิเตอร์ `phantom.set_severity`/`phantom.add_tags` และ argument ของ `closeInvestigation` ใน XSOAR มาจากความรู้ทั่วไปของ API เหล่านั้น ควรตรวจกับ reference ปัจจุบัน; ไม่ได้โค้ด Cortex analyzer ทางการแบบ verbatim (หน้า StrangeBee แสดงเฉพาะ JSON definition)

**หัวข้อ 8–9 (Reporting, SOC Optimization)**
- ไม่ได้ดึงเนื้อความเต็มของ CVSS v4.0 spec (JS-heavy; สรุปจาก Sysdig/Qualys); หมายเลขเวอร์ชันเอกสาร (v1.2, 2023-11-01 จาก mirror) ควรตรวจบน first.org; เวอร์ชัน model EPSS ปัจจุบัน (v4, มี.ค. 2025 ตามข่าวอุตสาหกรรม) ยืนยันจาก first.org ไม่ได้ (`/epss/model` คืน 404); schema `jobParams` ของ Kibana ไม่พบในเอกสาร
- ไม่ได้ดึงรายการ section ของ template รายงาน SANS Incident Handler's Handbook; ไม่ได้ดึงเนื้อความ PCI DSS v4.0.1 ทางการ (ต้องยอมรับ license) และแหล่ง control-mapping ไม่ตรงกันว่า "automated mechanisms" อยู่ที่ 10.4.1 หรือ 10.4.1.1; เนื้อหา ISO 27001 clause 9.1 มาจากความรู้ฝึกอบรม ไม่ได้ตรวจซ้ำ (iso.org 403); ไม่พบแนวทาง Forrester ด้าน SOC reporting/maturity ที่ใหม่กว่า 2010
- ชื่อระดับวุฒิภาวะ/capability ทางการของ SOC-CMM ยืนยันจาก soc-cmm.com ไม่ได้ (มาจาก write-up ทุติยภูมิและ PDF v1.1 ปี 2016); ไม่ได้เปิด spreadsheet v2.4.2; จำนวน aspect ที่อ้าง (21/26/27) ต่างกันตามเวอร์ชัน
- ตัวเลข Verizon 2025 DBIR มาจากสรุปของผู้ผลิตและข่าวประชาสัมพันธ์ ไม่ใช่ PDF รายงาน; ขนาดตัวอย่าง 2026 DBIR ไม่แสดงบน hub; เปอร์เซ็นต์ 24/7 ของ SANS 2025 ขัดแย้งระหว่างแหล่งทุติยภูมิ (79% vs 82%); ไม่พบ Expel quarterly "alert-to-fix" เป็นนาที
- สเกลตัวเลขของ DeTT&CT (data-source quality 0–5, visibility 0–4, detection –1 ถึง 5) ไม่ได้ตรวจซ้ำจาก wiki; วันที่และสถานะการย้าย CALDERA ไป Apache ไม่ปรากฏใน README ที่ดึง (เห็นเพียง redirect); ไม่พบ blog ของ Elastic ที่เจาะจง SOC metrics/MTTD
- ไม่มี snippet ในหัวข้อ 8–9 ที่คัดจากแหล่งภายนอกแบบ verbatim เพราะไม่พบ repository สาธารณะที่ทำงานเหล่านี้สำหรับ SOC โดยตรง; ชื่อเมธอด `get_techniques`/`get_attack_id` มาจาก `MitreAttackData` ที่มีเอกสาร; string เวอร์ชัน ATT&CK "17" ในตัวอย่าง 8.4 เป็น placeholder ต้องให้ตรงกับ STIX bundle ที่ใช้จริง

---

## รายการอ้างอิงรวม

จัดกลุ่มตามประเภทแหล่ง ตัดรายการซ้ำข้ามหัวข้อแล้ว ทุก URL ตามที่บันทึกไว้เมื่อ 2026-11-01

### ก. มาตรฐาน ข้อกำหนด และเอกสารภาครัฐ/องค์กรมาตรฐาน
- RFC 5424 The Syslog Protocol — https://datatracker.ietf.org/doc/html/rfc5424
- RFC 6585 Additional HTTP Status Codes (429) — https://www.rfc-editor.org/rfc/rfc6585
- RFC 6749 OAuth 2.0 §4.4 — https://www.rfc-editor.org/rfc/rfc6749#section-4.4
- RFC 6749 OAuth 2.0 §2.3.1 — https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
- OpenAPI Specification v3.2.1 — https://spec.openapis.org/oas/latest.html
- OASIS STIX 2.1 — https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- OASIS TAXII 2.1 — https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
- OASIS CACAO Security Playbooks v2.0 — https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html
- OASIS CACAO CS01 announcement — https://www.oasis-open.org/?p=10546
- OASIS CACAO approval release — https://www.oasis-open.org/?p=10491
- NIST SP 800-61 Rev. 3 — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-61r3 PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
- NIST news: SP 800-61 revision — https://nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations
- NIST CSRC Incident Response project — https://csrc.nist.gov/projects/incident-response
- NIST CSF 2.0 (CSWP 29) PDF — https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- NIST SP 800-92 Rev. 1 ipd — https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
- NIST SP 800-92r1 ipd PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92r1.ipd.pdf
- NIST Log management project — https://csrc.nist.gov/projects/log-management
- NIST SP 800-92 (2006) — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf
- NIST SP 800-150 — https://csrc.nist.gov/pubs/sp/800/150/final
- NIST SP 800-150 PDF — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf
- FIRST Traffic Light Protocol 2.0 — https://www.first.org/tlp/
- FIRST CVSS v4.0 Specification Document — https://www.first.org/cvss/v4.0/specification-document
- FIRST CVSS v4.0 landing — https://www.first.org/cvss/v4-0/
- FIRST EPSS — https://www.first.org/epss/
- FIRST EPSS API docs — https://api.first.org/epss/
- FIRST EPSS live call — https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400&pretty=true
- FIRST EPSS probability vs percentile — https://www.first.org/epss/articles/prob_percentile_bins
- CISA KEV Catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV overview — https://www.cisa.gov/known-exploited-vulnerabilities
- CISA KEV JSON schema — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
- NVD Developers – Start Here — https://nvd.nist.gov/developers/start-here
- NVD Developers – Vulnerabilities — https://nvd.nist.gov/developers/vulnerabilities
- MITRE ATT&CK Data & Tools — https://attack.mitre.org/resources/attack-data-and-tools/
- MITRE ATT&CK resources — https://attack.mitre.org/resources/
- MITRE ATT&CK Navigator Layer format v4.5 — https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
- MITRE ATT&CK Navigator app — https://mitre-attack.github.io/attack-navigator/
- MITRE attack-workbench-taxii-server USAGE.md — https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md
- MITRE 11 Strategies — https://www.mitre.org/11strategies
- MITRE 11 Strategies publication page — https://www.mitre.org/news-insights/publication/11-strategies-world-class-cybersecurity-operations-center
- MITRE 11 Strategies highlights PDF — https://www.mitre.org/sites/default/files/2022-04/11-strategies-world-class-csoc-highlights.pdf
- MITRE press release — https://www.mitre.org/news-insights/news-release/mitre-publishes-11-strategies-world-class-cybersecurity-operations
- OCSF schema browser — https://schema.ocsf.io
- OCSF Detection Finding — https://schema.ocsf.io/classes/detection_finding
- ocsf/ocsf-schema — https://github.com/ocsf/ocsf-schema
- Tenzir OCSF 1.4.0 detection_finding — https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding
- Tenzir OCSF 1.0.0 security_finding — https://docs.tenzir.com/reference/ocsf/1-0-0/classes/security_finding
- Tenzir OCSF FAQ — https://docs.tenzir.com/reference/ocsf/faqs/when-should-i-use-a-finding-event-class
- Linux Foundation press release (OCSF) — https://www.linuxfoundation.org/press/open-cybersecurity-schema-framework-ocsf-joins-the-linux-foundation-to-optimize-critical-security-data
- Tanium press release (OCSF launch) — https://www.tanium.com/press-releases/cybersecurity-and-technology-industry-leaders-launch-open-source-project
- Elastic Common Schema reference — https://www.elastic.co/docs/reference/ecs
- ECS field reference — https://www.elastic.co/docs/reference/ecs/ecs-field-reference
- Elastic blog: ECS → OpenTelemetry — https://www.elastic.co/blog/ecs-elastic-common-schema-otel-opentelemetry-announcement
- ArcSight CEF Implementation Standard PDF — https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
- ArcSight: What is CEF? — https://microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm
- libevtx EVTX format documentation — https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
- evtxexport man page — https://manpages.opensuse.org/Leap-16.0/libevtx-tools/evtxexport.1.en.html
- Apache mod_log_config — https://web.mit.edu/manual/mod/mod_log_config.html
- nginx ngx_http_log_module — https://nginx.org/en/docs/http/ngx_http_log_module.html
- CIS Benchmarks — https://www.cisecurity.org/cis-benchmarks
- PCI SSC document library — https://www.pcisecuritystandards.org/document_library/
- ISO/IEC 27001 — https://www.iso.org/standard/27001
- SOC-CMM introduction — https://www.soc-cmm.com/introduction
- SOC-CMM product page — https://www.soc-cmm.com/products/soc-cmm
- SOC-CMM Metrics 101 PDF — https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf
- SOC-CMM 2.4.2 basic xlsx — https://www.soc-cmm.com/img/upload/files/62-soc-cmm-242-basic.xlsx
- SOC-CMM 2.4.2 advanced xlsx — https://www.soc-cmm.com/img/upload/files/63-soc-cmm-242-advanced.xlsx
- SOC-CMM NIST CSF mapping xlsx — https://www.soc-cmm.com/img/upload/files/6-soc-cmm-23-nist-csf-mapping.xlsx
- soc-cmm.com — https://www.soc-cmm.com/
- SOC-TOM — https://soc-cmm.com/soc-tom/
- SOC-CMM SOC metrics — https://www.soc-cmm.com/soc-metrics
- SOC-CMM certification — https://certification.soc-cmm.com/
- SOC-CMM community — https://soc-cmm.discourse.group/
- ECB TIBER-EU purple best practices 2025 — https://www.ecb.europa.eu/pub/pdf/annex/ecb.tiber_eu_purple_best_practices_2025.en.pdf
- CTID Mappings Explorer — https://center-for-threat-informed-defense.github.io/mappings-explorer/external/

### ข. เอกสาร Python standard library และ library ทั่วไป
- Python docs: re — https://docs.python.org/3/library/re.html
- Python docs: collections — https://docs.python.org/3/library/collections.html
- Python docs: csv — https://docs.python.org/3/library/csv.html
- Python docs: logging — https://docs.python.org/3/library/logging.html
- Python docs: argparse — https://docs.python.org/3/library/argparse.html
- Python docs: json — https://docs.python.org/3/library/json.html
- Python docs: pathlib — https://docs.python.org/3/library/pathlib.html
- Python docs: datetime — https://docs.python.org/3/library/datetime.html
- Python docs: subprocess (Security Considerations) — https://docs.python.org/3/library/subprocess.html#security-considerations
- Python docs: subprocess.run — https://docs.python.org/3/library/subprocess.html#subprocess.run
- Python docs: hashlib — https://docs.python.org/3/library/hashlib.html
- Python docs: hashlib.file_digest — https://docs.python.org/3/library/hashlib.html#hashlib.file_digest
- Python docs: hmac — https://docs.python.org/3/library/hmac.html
- Python docs: ssl — https://docs.python.org/3/library/ssl.html#ssl.create_default_context
- Requests Advanced Usage — https://requests.readthedocs.io/en/latest/user/advanced/
- Requests: Automatic Retries — https://requests.readthedocs.io/en/latest/user/advanced/#example-automatic-retries
- Requests: Timeouts — https://requests.readthedocs.io/en/latest/user/advanced/#timeouts
- Requests: SSL Cert Verification — https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification
- Requests: Proxies — https://requests.readthedocs.io/en/latest/user/advanced/#proxies
- Requests: Custom Authentication — https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication
- Requests: Link Headers — https://requests.readthedocs.io/en/latest/user/advanced/#link-headers
- Requests: Blocking Or Non-Blocking? — https://requests.readthedocs.io/en/latest/user/advanced/#blocking-or-non-blocking
- urllib3 util reference (Retry) — https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
- HTTPX Timeouts — https://www.python-httpx.org/advanced/timeouts/
- Pydantic Settings — https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/
- schedule docs — https://schedule.readthedocs.io/en/stable/
- APScheduler 3.x User Guide — https://apscheduler.readthedocs.io/en/3.x/userguide.html
- pandas docs — https://pandas.pydata.org/docs/
- pandas read_csv — https://pandas.pydata.org/docs/reference/api/pandas.read_csv.html
- Jinja2 docs — https://jinja.palletsprojects.com/en/stable/
- GitHub API pallets/jinja — https://api.github.com/repos/pallets/jinja
- WeasyPrint docs — https://doc.courtbouillon.org/weasyprint/stable/
- Kozea/WeasyPrint — https://github.com/Kozea/WeasyPrint
- ReportLab docs — https://docs.reportlab.com/
- ReportLab User Guide PDF — https://www.reportlab.com/docs/reportlab-userguide.pdf
- Pandoc MANUAL — https://pandoc.org/MANUAL.html
- python-docx docs — https://python-docx.readthedocs.io/en/latest/
- python-openxml/python-docx — https://github.com/python-openxml/python-docx
- python-pptx docs — https://python-pptx.readthedocs.io/en/latest/
- scanny/python-pptx — https://github.com/scanny/python-pptx
- matplotlib docs — https://matplotlib.org/stable/
- matplotlib/matplotlib — https://github.com/matplotlib/matplotlib
- plotly python docs — https://plotly.com/python/
- plotly/plotly.py — https://github.com/plotly/plotly.py
- Streamlit docs — https://docs.streamlit.io/
- streamlit/streamlit — https://github.com/streamlit/streamlit
- jira.readthedocs.io examples — https://jira.readthedocs.io/examples.html
- Nmap XML DTD (ไม่ได้ดึง) — https://nmap.org/book/nmap-dtd.html

### ค. หนังสือ หลักสูตร การบรรยาย และบทความวิชาการ
- Al Sweigart, Automate the Boring Stuff with Python — https://automatetheboringstuff.com/
- Bookshop.org: Automate the Boring Stuff 3rd ed. — https://bookshop.org/p/books/automate-the-boring-stuff-with-python-3rd-edition-al-sweigart/07df7b58a1c84fa2
- i-programmer Book Watch — https://i-programmer.info/book-watch-archive/18069-automate-the-boring-stuff-with-python-3rd-ed-no-starch-press.html
- SANS SEC573 — https://www.sans.org/sec573
- SANS SEC573 (course page) — https://www.sans.org/cyber-security-courses/automating-information-security-with-python/
- SANS 2018 event page — https://www.sans.org/event/sans-2018/course/automating-information-security-with-python
- SANS.edu profile: Mark Baggett — https://www.sans.edu/profiles/mark-baggett
- SANS FOR578 — https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/
- Wiley: Python for Cybersecurity (Poston) — https://www.wiley.com/en-us/Python+for+Cybersecurity%3A+Using+Python+for+Cyber+Offense+and+Defense-p-9781119850649
- O'Reilly: Python for Cybersecurity ch.1 — https://www.oreilly.com/library/view/python-for-cybersecurity/9781119850649/c01.xhtml
- O'Reilly listing: Python for Cybersecurity — https://www.oreilly.com/library/view/-/9781119850649
- Eyrolles: Python for Cybersecurity — https://www.eyrolles.com/Informatique/Livre/python-for-cybersecurity-9781119850649/
- O'Reilly: Cybersecurity Ops with bash — https://oreilly.com/library/view/cybersecurity-ops-with/9781492041306
- UPNM TOC: Cybersecurity Ops with bash — https://libexplorer.upnm.edu.my/home/Record/54874/TOC
- No Starch: Black Hat Python 2E — https://nostarch.com/black-hat-python2E
- Packt: Security Automation with Python — https://www.packtpub.com/product/security-automation-with-python/9781805125105
- O'Reilly: Security Automation with Python — https://www.oreilly.com/library/view/-/9781805125105/
- O'Reilly: Intelligence-Driven Incident Response 2e — https://www.oreilly.com/library/view/intelligence-driven-incident-response/9781098120672/
- Heidelberg library catalogue — https://katalog.ub.uni-heidelberg.de/titel/69152504
- wristers.nl — https://www.wristers.nl/boek/9781098120689
- O'Reilly: Practical Threat Intelligence — https://oreilly.com/library/view/practical-threat-intelligence/9781838556372
- Packt: Practical Threat Intelligence — https://packtpub.com/product/practical-threat-intelligence-and-data-driven-threat-hunting/9781838556372
- Lehmanns listing — https://www.lehmanns.de/shop/mathematik-informatik/55989559-9781838551636-practical-threat-intelligence-and-data-driven-threat-hunting
- SimeonOnSecurity book list — https://simeononsecurity.com/articles/essential-books-cybersecurity-it-professionals/
- David Beazley, Generator Tricks for Systems Programmers — https://www.dabeaz.com/generators2
- Drain (ICWS 2017) — http://jiemingzhu.github.io/pub/pjhe_icws2017.pdf
- DeepLog (CCS 2017) — https://users.cs.utah.edu/~lifeifei/papers/deeplog.pdf
- DeepLog dblp — https://dblp.dagstuhl.de/rec/conf/ccs/Du0ZS17.html
- Lockheed Martin Intel-Driven Defense PDF — https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf
- connections-qj.org listing — https://connections-qj.org/article/intelligence-driven-computer-network-defense-informed-analysis-adversary-campaigns-and
- BibSonomy entry — https://bibsonomy.org/bibtex/ce281b592eb8dc68cb35e45ff801bd3c
- securityandtechnology.org mirror — https://securityandtechnology.org/wp-content/uploads/2020/07/lm-white-paper-intel-driven-defense.pdf
- Diamond Model (DTIC) — https://apps.dtic.mil/sti/pdfs/ADA586960.pdf
- Diamond Model (activeresponse.org) — https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf
- Bianco: The Pyramid of Pain — https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Bianco Speaker Deck — https://speakerdeck.com/davidjbianco/the-pyramid-of-pain-intel-driven-detection-and-response-to-increase-your-adversarys-cost-of-operations
- Sqrrl Pyramid of Pain PDF — https://www.threathunting.net/files/A%20Framework%20for%20Cyber%20Threat%20Hunting%20Part%201_%20The%20Pyramid%20of%20Pain%20_%20Sqrrl.pdf
- arXiv 2609.19091 — https://arxiv.org/pdf/2609.19091
- arXiv 2601.04486 — https://arxiv.org/pdf/2601.04486
- SANS Incident Handler's Handbook — https://www.sans.org/white-papers/33901/
- SANS white paper 36572 (O'Brien 2016) — https://www.sans.org/white-papers/36572
- GIAC research paper 36572 — https://www.giac.org/research-papers/36572
- SANS IH-Identification form — https://www.sans.org/media/score/incident-forms/IH-Identification.pdf
- SANS SOC Metrics Cheat Sheet — https://www.sans.org/posters/soc-metrics-cheat-sheet
- SANS white papers index — https://www.sans.org/white-papers/
- PyCon US 2022: Python for Threat Intelligence — https://pycon-archive.python.org/2022/schedule/presentation/43/index.html
- Google SRE Book ch.6 — https://sre.google/sre-book/monitoring-distributed-systems/
- Google SRE Book: Postmortem Culture — https://sre.google/sre-book/postmortem-culture/
- Google SRE Book: Eliminating Toil — https://sre.google/sre-book/eliminating-toil/
- Google SRE Book: SLOs — https://sre.google/sre-book/service-level-objectives/
- Kyle Bailey Detection Engineering Maturity Matrix — https://detectionengineering.io/
- k-bailey/detection-engineering-maturity-matrix — https://github.com/k-bailey/detection-engineering-maturity-matrix/blob/main/index.md
- Elastic Security Labs DEBMM — https://www.elastic.co/security-labs/elastic-releases-debmm
- Elastic Security Labs: Identifying beaconing malware — https://www.elastic.co/security-labs/identifying-beaconing-malware-using-elastic
- Recorded Future Intelligence Handbook 4th ed. — https://go.recordedfuture.com/hubfs/ebooks/intelligence-handbook-fourth-edition.pdf?hsLang=en
- Lenny Zeltser IR report template — https://zeltser.com/incident-response-report-template

### ง. เอกสาร API/SDK ของผู้ผลิตและแพลตฟอร์ม
- VirusTotal Public vs Premium API — https://docs.virustotal.com/reference/public-vs-premium-api
- VirusTotal quota consumption — https://docs.virustotal.com/docs/quota-consumption
- VirusTotal consumption quotas handled — https://docs.virustotal.com/docs/consumption-quotas-handled
- vt-py quickstart — https://virustotal.github.io/vt-py/quickstart.html
- Shodan REST API — https://developer.shodan.io/api
- shodan-python tutorial — https://shodan.readthedocs.io/en/latest/tutorial.html
- AbuseIPDB API docs — https://docs.abuseipdb.com/
- HIBP API v3 — https://haveibeenpwned.com/API/v3
- URLhaus API docs — https://urlhaus-api.abuse.ch/
- URLhaus feeds page — https://urlhaus.abuse.ch/api/
- URLhaus csv_recent (410) — https://urlhaus.abuse.ch/downloads/csv_recent/
- Feodo Tracker blocklist — https://feodotracker.abuse.ch/blocklist/
- MISP feeds — https://www.misp-project.org/feeds/
- PyMISP README — https://pymisp.readthedocs.io/en/latest/README.html
- PyMISP examples/last.py — https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py
- OpenCTI docs: Python library — https://docs.opencti.io/latest/development/python/
- OTX SDK README — https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/README.md
- OTXv2.py source — https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py
- stix2 docs — https://stix2.readthedocs.io/en/latest/guide/creating.html
- mitreattack-python docs — https://mitreattack-python.readthedocs.io/en/latest/
- mitreattack-python MitreAttackData — https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html
- ioc-finder docs — https://hightower.space/ioc-finder/
- msticpy docs — https://msticpy.readthedocs.io/en/latest/
- msticpy TI Providers — https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html
- pyTenable docs — https://pytenable.readthedocs.io/en/stable/
- python-gvm docs — https://greenbone.github.io/python-gvm/
- nvdlib.com — https://nvdlib.com
- python-nmap PyPI — https://pypi.org/project/python-nmap/
- libnmap parser docs — https://libnmap.readthedocs.io/en/latest/parser.html
- Splunk SDK docs — https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/
- Elasticsearch Python client – Connecting — https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting
- Elasticsearch Python client – Getting started — https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started
- Elastic Security alert schema 8.18 — https://www.elastic.co/guide/en/security/8.18/alert-schema.html
- Elastic: Create a detection rule — https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule
- Elastic: Automating report generation — https://www.elastic.co/docs/explore-analyze/report-and-share/automating-report-generation
- Kibana legacy automating report generation — https://www.elastic.co/guide/en/kibana/current/automating-report-generation.html
- Kibana Reporting integration — https://www.elastic.co/pt/guide/en/kibana/current/reporting-integration.html
- Filebeat CEF exported fields — https://www.elastic.co/jp/guide/en/beats/filebeat/current/exported-fields-cef.html
- Grafana Reporting HTTP API (next) — https://grafana.com/docs/grafana/next/developers/http_api/reporting/
- Grafana v12.4 Reporting API — https://grafana.com/docs/grafana/v12.4/developer-resources/api-reference/http-api/reporting.md
- Wazuh API Getting Started — https://documentation.wazuh.com/current/user-manual/api/getting-started.html
- Wazuh custom active response scripts — https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- Azure Monitor HTTP Data Collector API — https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
- Microsoft Graph Security authorization — https://learn.microsoft.com/en-us/graph/security-authorization
- Microsoft Graph List alerts_v2 — https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2
- CrowdStrike developer Python SDK — https://developer.crowdstrike.com/sdks/python/
- Slack SDK Webhook — https://docs.slack.dev/tools/python-slack-sdk/webhook/
- thehive4py docs — https://thehive-project.github.io/TheHive4py/latest/
- thehive4py alert examples — https://thehive-project.github.io/TheHive4py/latest/examples/alert/
- docs.strangebee.com — https://docs.strangebee.com/
- StrangeBee: How to Write and Submit an Analyzer — https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/
- docs.thehive-project.org mirror — https://docs.thehive-project.org/cortex/api/how-to-create-an-analyzer/
- TheHive Project blog — https://blog.thehive-project.org/tag/misp/page/4
- DeepWiki Cortex-Analyzers guide — https://deepwiki.com/TheHive-Project/Cortex-Analyzers/6-developer-guide
- Shuffle shuffle-docs apps.md — https://github.com/Shuffle/shuffle-docs/blob/master/docs/apps.md
- shuffler.io/docs/apps — https://shuffler.io/docs/apps
- shuffle-sdk PyPI — https://pypi.org/project/shuffle-sdk/0.0.8/
- Splunk SOAR Playbook automation API — https://help.splunk.com/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api
- Splunk SOAR On-prem Playbook API — https://docs.splunk.com/Documentation/SOARonprem/latest/PlaybookAPI/PlaybookAPI
- Splunk SOAR tutorial — https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial/playbook-api-tutorial/tutorial-create-a-simple-playbook-in-splunk-soar-cloud
- Splunk SOAR Python Playbook Tutorial (On-prem) — https://help.splunk.com/en/splunk-soar/soar-on-premises/python-playbook-tutorial
- Splunk SOAR legacy custom function block — https://help.splunk.com/en/splunk-soar/soar-on-premises/build-playbooks/6.3.0/use-the-classic-playbook-editor-to-create-and-view-playbooks-to-automate-analyst-workflows/add-custom-code-to-your-splunk-soar-on-premises-playbook-with-the-legacy-custom-function-block-using-the-classic-playbook-editor
- Splunk Detection Studio docs — https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security
- Splunk blog: Detection Studio — https://www.splunk.com/en_us/blog/security/mastering-the-detection-lifecycle-with-detection-studio.html
- Splunk security monitoring — https://splunk.com/en_us/solutions/security-monitoring.html
- research.splunk.com — https://research.splunk.com
- XSOAR Script Code Snippets — https://cortex-docs.paloaltonetworks.com/python-development-quick-start-guide/cortex-xsoar-python-development-quick-start-guide/script-code-snippets
- xsoar.pan.dev Code Conventions — https://xsoar.pan.dev/docs/integrations/code-conventions
- xsoar.pan.dev Common Server Python — https://xsoar.pan.dev/docs/reference/api/common-server-python
- XSOAR playbook: SANS – Lessons Learned — https://demisto.pan.dev/docs/reference/playbooks/sans---lessons-learned
- docs.stackstorm.com Actions — https://docs.stackstorm.com/actions.html
- Tines Run Python Script — https://www.tines.com/docs/actions/templates/templates/frequently-used-templates/run-python-script/
- Tines Tunnel — https://www.tines.com/stories/whats-new/execute-python-code-via-tines-tunnel/
- Tines Python how-to — https://tines.com/blog/python-tines-how-to-guide
- docs.n8n.io Code node — https://docs.n8n.io/code/code-node/
- Red Canary docs: Alert states — https://docs.redcanary.com/docs/alert-states
- Expel Service Review Dashboard Metrics — https://support.expel.io/hc/en-us/articles/7228662328083-Service-Review-Dashboard-Metrics
- Plaso parsers and plugins — https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html
- pySigma docs — https://sigmahq-pysigma.readthedocs.io/en/latest/
- pySigma Backends doc — https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
- docs.rs evtx README — https://docs.rs/crate/evtx/latest/source/README.md
- PyPI evtx — https://pypi.org/project/evtx
- PyPI deeplog — https://pypi.org/project/deeplog/
- PyPI iocingestor — https://pypi.org/project/iocingestor/
- CALDERA docs — https://caldera.readthedocs.io/en/latest/
- atomicredteam.io — https://atomicredteam.io/
- DeTT&CT Editor — https://rabobank-cdc.github.io/dettect-editor
- infosecjupyterbook.com — https://infosecjupyterbook.com/

### จ. Repository ชุมชนบน GitHub (ดาวโดยประมาณ ณ 2026-11-01)
- n8n-io/n8n (≈209k) — https://github.com/n8n-io/n8n
- streamlit/streamlit (≈46.2k) — https://github.com/streamlit/streamlit
- matplotlib/matplotlib (≈23.4k) — https://github.com/matplotlib/matplotlib
- plotly/plotly.py (≈18.9k) — https://github.com/plotly/plotly.py
- wazuh/wazuh (≈17.5k) — https://github.com/wazuh/wazuh
- redcanaryco/atomic-red-team (≈12.7k) — https://github.com/redcanaryco/atomic-red-team
- pallets/jinja (≈11.8k) — https://github.com/pallets/jinja
- SigmaHQ/sigma (≈11.4k) — https://github.com/SigmaHQ/sigma
- hslatman/awesome-threat-intelligence (≈10.8k) — https://github.com/hslatman/awesome-threat-intelligence
- Kozea/WeasyPrint (≈9.8k) — https://github.com/Kozea/WeasyPrint
- meirwah/awesome-incident-response (≈9.5k) — https://github.com/meirwah/awesome-incident-response
- apache/caldera (≈7.5k) — https://github.com/apache/caldera
- StackStorm/st2 (≈6.6k) — https://github.com/StackStorm/st2
- python-openxml/python-docx (≈5.8k) — https://github.com/python-openxml/python-docx
- fabacab/awesome-cybersecurity-blueteam (≈5.6k) — https://github.com/fabacab/awesome-cybersecurity-blueteam
- Security-Onion-Solutions/securityonion (≈5.0k) — https://github.com/Security-Onion-Solutions/securityonion
- intelowlproject/IntelOwl (≈4.8k) — https://github.com/intelowlproject/IntelOwl
- 0x4D31/awesome-threat-detection (≈4.8k) — https://github.com/0x4D31/awesome-threat-detection
- OTRF/ThreatHunter-Playbook (≈4.7k) — https://github.com/OTRF/ThreatHunter-Playbook
- elastic/elasticsearch-py (≈4.4k) — https://github.com/elastic/elasticsearch-py
- TheHive-Project/TheHive (≈4.0k, archived) — https://github.com/TheHive-Project/TheHive
- scanny/python-pptx (≈3.6k) — https://github.com/scanny/python-pptx
- elastic/detection-rules (≈2.9k) — https://github.com/elastic/detection-rules
- logpai/loghub (≈2.9k) — https://github.com/logpai/loghub
- mitre-attack/attack-navigator (≈2.5k) — https://github.com/mitre-attack/attack-navigator
- Shuffle/Shuffle (≈2.5k) — https://github.com/Shuffle/Shuffle
- rabobank-cdc/DeTTECT (≈2.4k) — https://github.com/rabobank-cdc/DeTTECT
- DeTT&CT wiki — https://github.com/rabobank-cdc/DeTTECT/wiki
- log2timeline/plaso (≈2.2k) — https://github.com/log2timeline/plaso
- microsoft/msticpy (≈2.0k) — https://github.com/microsoft/msticpy
- yeti-platform/yeti (≈2.0k) — https://github.com/yeti-platform/yeti
- cyb3rxp/awesome-soc (≈1.9k) — https://github.com/cyb3rxp/awesome-soc
- awesome-soc metrics-kpi.md — https://github.com/cyb3rxp/awesome-soc/blob/main/metrics-kpi.md
- awesome-soc detection_engineering.md — https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md
- TheHive-Project/Cortex (≈1.6k) — https://github.com/TheHive-Project/Cortex
- logpai/loglizer (≈1.4k) — https://github.com/logpai/loglizer
- infosecB/awesome-detection-engineering (≈1.4k) — https://github.com/infosecB/awesome-detection-engineering
- demisto/content (≈1.3k) — https://github.com/demisto/content
- correlatedsecurity/Awesome-SOAR (≈1.0k) — https://github.com/correlatedsecurity/Awesome-SOAR
- InQuest/ThreatIngestor (≈932) — https://github.com/InQuest/ThreatIngestor
- ocsf/ocsf-schema (≈910) — https://github.com/ocsf/ocsf-schema
- logpai/Drain3 (≈904) — https://github.com/logpai/Drain3
- logpai/awesome-log-analysis (≈810) — https://github.com/logpai/awesome-log-analysis
- VirusTotal/vt-py (≈792) — https://github.com/VirusTotal/vt-py
- williballenthin/python-evtx (≈786) — https://github.com/williballenthin/python-evtx
- mitre-attack/mitreattack-python (≈755) — https://github.com/mitre-attack/mitreattack-python
- splunk/splunk-sdk-python (≈747) — https://github.com/splunk/splunk-sdk-python
- mitre-attack/attack-stix-data (≈707) — https://github.com/mitre-attack/attack-stix-data
- microsoftgraph/msgraph-sdk-python (≈634) — https://github.com/microsoftgraph/msgraph-sdk-python
- SigmaHQ/pySigma (≈604) — https://github.com/SigmaHQ/pySigma
- SigmaHQ/pySigma-plugin-directory — https://github.com/SigmaHQ/pySigma-plugin-directory
- InQuest/iocextract (≈581) — https://github.com/InQuest/iocextract
- socfortress/CoPilot (≈538) — https://github.com/socfortress/CoPilot
- CrowdStrike/falconpy (≈517) — https://github.com/CrowdStrike/falconpy
- MISP/PyMISP (≈494) — https://github.com/MISP/PyMISP
- TheHive-Project/Cortex-Analyzers (≈494) — https://github.com/TheHive-Project/Cortex-Analyzers
- savon-noir/python-libnmap (≈493) — https://github.com/savon-noir/python-libnmap
- swimlane/pyattck (≈480, archived) — https://github.com/swimlane/pyattck
- SuperCowPowers/zat (≈456) — https://github.com/SuperCowPowers/zat
- zat zeek_to_pandas.py — https://raw.githubusercontent.com/SuperCowPowers/zat/main/examples/zeek_to_pandas.py
- oasis-open/cti-python-stix2 (≈440) — https://github.com/oasis-open/cti-python-stix2
- AlienVault-OTX/OTX-Python-SDK (≈402) — https://github.com/AlienVault-OTX/OTX-Python-SDK
- TheHive-Project/TheHive4py (≈244) — https://github.com/TheHive-Project/TheHive4py
- SigmaHQ/sigma-cli (≈220) — https://github.com/SigmaHQ/sigma-cli
- fhightower/ioc-finder (≈184) — https://github.com/fhightower/ioc-finder
- OpenCTI-Platform/client-python (≈145, archived) — https://github.com/OpenCTI-Platform/client-python
- OTRF/infosec-jupyter-book (≈134) — https://github.com/OTRF/infosec-jupyter-book
- Shuffle/python-apps (≈130) — https://github.com/Shuffle/python-apps
- oasis-open/cti-taxii-client (≈129) — https://github.com/oasis-open/cti-taxii-client
- greenbone/python-gvm (≈126) — https://github.com/greenbone/python-gvm
- Vehemont/nvdlib (≈118) — https://github.com/Vehemont/nvdlib
- demisto/demisto-sdk (≈90) — https://github.com/demisto/demisto-sdk
- omerbenamram/pyevtx-rs (≈55) — https://github.com/omerbenamram/pyevtx-rs
- TheHive-Project/cortexutils (≈8) — https://github.com/TheHive-Project/cortexutils
- hevnsnt/Awesome_Incident_Response — https://github.com/hevnsnt/Awesome_Incident_Response
- MarkBaggett/freq — https://github.com/MarkBaggett/MarkBaggett/tree/master/freq
- Neptunes22/Python-Security-Log-Analyzer — https://github.com/Neptunes22/Python-Security-Log-Analyzer
- ihorpjp/soc-log-analyzer — https://github.com/ihorpjp/soc-log-analyzer
- Ronoh12/auth-log-analyzer — https://github.com/Ronoh12/auth-log-analyzer
- SigmaHQ README (jsDelivr mirror) — https://cdn.jsdelivr.net/gh/sigmahq/sigma@master/README.md
- awesome.ecosyste.ms (awesome-threat-intelligence) — https://awesome.ecosyste.ms/projects/github.com%2Fhslatman%2Fawesome-threat-intelligence
- awesome.ecosyste.ms (awesome-incident-response) — https://awesome.ecosyste.ms/projects/github.com%2Fmeirwah%2Fawesome-incident-response
- gittrend.io IntelOwl — https://gittrend.io/repo/intelowlproject/IntelOwl
- Alpine py3-evtx — https://pkgs.alpinelinux.org/package/edge/community/x86/py3-evtx
- Debian python3-evtx — https://pkgdex.org/debian/sid/x86_64/main/python3-evtx_8.1.0-1.deb.html

### ฉ. บทความ บล็อก การสำรวจ และสื่อ
- BHIS: Log File Frequency Analysis with Python — https://www.blackhillsinfosec.com/?p=5933
- BHIS: Detecting Malware Beacons With Zeek and RITA — https://www.blackhillsinfosec.com/detecting-malware-beacons-with-zeek-and-rita/
- BHIS: The Detection Engineering Process (slides) — https://www.blackhillsinfosec.com/wp-content/uploads/2024/11/SLIDES_The-Detection-Engineering-Process.pdf
- ISC diary 20451: Continuous Monitoring for Random Strings — https://isc.sans.edu/diary/Continuous+Monitoring+for+Random+Strings/20451
- ISC diary 32038: DShield honeypot tooling — https://isc.sans.edu/diary/Automated+Tools+to+Assist+with+DShield+Honeypot+Investigations+Guest+Diary/32038
- Infosec Institute: Python scripting — https://infosecinstitute.com/resources/professional-development/python-scripting-tool-cybersecurity/
- TechTarget: Boost SOC efficiency with Python security automation — https://www.techtarget.com/searchsecurity/tip/Boost-SOC-efficiency-with-Python-security-automation
- TechTarget: SOAR definition — https://www.techtarget.com/searchsecurity/definition/SOAR
- DEV Community: NVD API v2 — https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p
- dev.to: Parsing Nginx logs using Python — https://dev.to/ksndeveloper/parsing-nginx-logs-using-python-1m6k
- gist ksn-developer — https://gist.github.com/ksn-developer/4072a9e092bccf68559c21f1c5ac2de2
- nbviewer grokcode nginx-log-analysis — https://nbviewer.jupyter.org/github/grokcode/ipython-notebooks/tree/master/nginx-log-analysis.ipynb
- nbviewer koldunovn Apache_log — https://nbviewer.jupyter.org/github/koldunovn/nk_public_notebooks/tree/master/Apache_log.ipynb
- eddmann.com: Processing Apache and Nginx access logs — https://eddmann.com/posts/processing-apache-and-nginx-access-logs/
- cipherssecurity tutorial — https://cipherssecurity.com/?p=17370
- Community mirror: Zeek beaconing skill — https://claudeskills.info/skills/mukul975/Anthropic-Cybersecurity-Skills/detecting-beaconing-patterns-with-zeek/
- Active Countermeasures: Simplifying beacon analysis — https://www.activecountermeasures.com/threat-hunting-simplifying-the-beacon-analysis-process/
- Active Countermeasures: Detecting Beacons With Jitter — https://www.activecountermeasures.com/detecting-beacons-with-jitter/
- Recorded Future: Threat Intelligence Lifecycle — https://www.recordedfuture.com/blog/threat-intelligence-lifecycle-phases
- CSO Online: threat intelligence lifecycle — https://www.csoonline.com/article/575001/dissecting-threat-intelligence-lifecycle-problems.html/amp/
- CSO Online: Sigma rules explained — https://www.csoonline.com/article/572973/sigma-rules-explained-when-and-how-to-use-them-to-log-events.html
- Graylog community (OTX rate limit) — https://community.graylog.org/t/no-longer-receiving-results-after-using-my-otx-api-key/12267
- SANS CTI Summit 2024 visual summary — https://sans.org/blog/a-visual-summary-of-sans-cti-summit-2024
- SANS CTI Summit 2025 visual summary — https://www.sans.org/blog/a-visual-summary-of-sans-cti-summit-2025
- SANS Threat Analysis Rundown CTI Summit preview — https://www.sans.org/blog/sans-threat-analysis-rundown-in-review-sans-cti-summit-preview
- GovEvents CTI Summit 2025 — https://govevents.com/event/9358
- GovEvents SANS 2025 CTI Survey webcast — https://govevents.com/pub/83651/cc54a
- SANS webcast: Agentic CTI Automation — https://www.sans.org/webcasts/agentic-cti-automation-for-fun-and-profit
- SANS webcast: CTI in the AI Arms Race 2026 — https://www.sans.org/webcasts/cti-ai-arms-race-building-resilient-adaptive-intelligence-platforms-2026
- SANS: State of Automation in Security Operations — https://www.sans.org/white-papers/state-automation-security-operations-sans-survey/
- SANS 2022 SOC survey — https://www.sans.org/reading-room/whitepapers/analyst/2022-sans-soc-survey/
- SANS SOC Survey 2025 PDF — https://www.elastic.co/pdf/sans-soc-survey-2025.pdf
- Elastic: 2025 State of the SOC Survey — https://www.elastic.co/resources/security/report/2025-state-of-the-soc-survey
- Swimlane: SANS 2025 SOC survey — https://swimlane.com/blog/global-soc-survey-insights/
- Torq: SANS 2025 SOC survey — https://torq.io/blog/sans-2025-soc-survey
- Dropzone: 2025 SANS SOC survey infographic — https://content.dropzone.ai/2025-sans-soc-survey-infographic
- Dropzone: 2025 SANS SOC survey report — https://content.dropzone.ai/2025-sans-soc-survey-report
- Prophet Security: SANS SOC survey 2025 — https://resources.prophetsecurity.ai/sans-soc-survey-2025
- Anomali: SANS 2023 SOC survey — https://anomali.com/resources/whitepapers/sans-2023-soc-survey
- SANS/Anvilogic webcast — https://sans.org/webcasts/insights-into-detection-engineering-findings-from-a-sans-and-anvilogic-survey
- SANS: Continuous purple teaming — https://www.sans.org/blog/continuous-purple-teaming-practical-approach-strengthening-offensive-capabilities
- SANS profile: Rob van Os — https://www.sans.org/profiles/rob-van-os
- SANS Blueprint podcast: Rob van Os — https://sans.org/podcasts/blueprint/maturing-your-cyber-defense-with-rob-van-os
- Rapid7/SANS 2025 Detection & Response survey — https://www.rapid7.com/cdn/assets/blt2e3e3f0d1864c31f/6937f5fa43c2f8cbe153e2a5/Survey_Detection-Response_Rapid7_2025.pdf
- Critical Start 2019 SOC survey — https://criticalstart.com/resources/criticalstart-releases-third-annual-security-operations-center-soc-professional-survey
- Critical Start report PDF — https://www.criticalstart.com/wp-content/uploads/CS_MDR_Survey_Report.pdf
- Help Net Security 2019 — https://www.helpnetsecurity.com/2019/08/29/soc-alert-overload/
- Help Net Security 2021 — https://www.helpnetsecurity.com/2021/03/11/alert-overload-still-plagues-cybersecurity-industry/
- Dark Reading: Overburdened SOC analysts — https://www.darkreading.com/analytics/overburdened-soc-analysts-shift-priorities/d/d-id/1335698
- Dark Reading: SOAR Is Dead, Long Live SOAR — https://darkreading.com/cybersecurity-operations/soar-is-dead-long-live-soar
- D3 Security: SOAR vs SAO — https://d3security.com/blog/whats-the-difference-between-soar-and-sao/
- D3 Security: Why MITRE calls SOAR indispensable — https://d3security.com/blog/why-mitre-calls-soar-indispensable-in-its-latest-book
- D3 Security: Event Pipeline — https://d3security.com/resources/event-pipeline-automate-handling-of-hundreds-of-alerts-per-minute/
- Swimlane: Gartner Innovation Insight — https://swimlane.com/?p=9805
- Solutions Review: Gartner 2022 definition — https://solutionsreview.com/security-information-event-management/wp-json/wp/v2/posts/3178
- Solutions Review: 2019 Market Guide — https://solutionsreview.com/security-information-event-management/key-findings-from-gartners-2019-market-guide-for-soar
- secrss SOAR history — https://www.secrss.com/articles/24043
- Wikipedia: Security orchestration — https://en.wikipedia.org/wiki/Security_orchestration
- Gartner glossary: SOAR — https://www.gartner.com/en/information-technology/glossary/security-orchestration-automation-response-soar
- Gartner Hype Cycle abstract 5622491 — https://www.gartner.com/en/documents/5622491
- Gartner abstract 6389843 — https://www.gartner.com/en/documents/6389843
- Gartner abstract 5088831 — https://www.gartner.com/en/documents/5088831
- Gartner Cybersecurity Business Value Benchmark PDF — https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf
- TechRepublic: 2023 Gartner Market Guide for SOAR — https://www.techrepublic.com/resource-library/whitepapers/2023-gartner-market-guide-for-security-orchestration-automation-and-response-solutions/
- Netenrich: Hype Cycle for Security Operations 2024 — https://netenrich.com/blog/a-strategic-perspective-of-gartner-hype-cycle-for-security-operations-2024
- Torq on Gartner — https://torq.io/?p=9180
- Torq: threat intelligence tools — https://torq.io/blog/threat-intelligence-tools/
- Blink Ops: Gartner says goodbye to SOAR — https://www.blinkops.com/blog/gartner-says-goodbye-to-soar-whats-next-for-security-operations
- Intezer: Gartner's Changing Views on SOAR — https://intezer.com/guides/soar-security/gartner-view-on-soar
- Red Canary-hosted Gartner Journey Guide — https://redcanary.com/resources/guides/gartner-journey-guide-building-soc
- Vectra-hosted Gartner SOC Model Guide — https://vectra.ai/resources/gartner-soc-model-guide
- Expel-hosted Gartner Hype Cycle 2025 — https://expel.com/gartner-hype-cycle-security-operations-2025/
- Linford & Co on SP 800-61 — https://linfordco.com/blog/nist-sp-800-61/
- Tandem on SP 800-61 Rev. 3 — https://tandem.app/blog/updated-nist-incident-response-guidance-sp-800-61-rev-3
- BusinessWire: MITRE 11 Strategies — https://www.businesswire.com/news/home/20220329005299/en/MITRE-Publishes-11-Strategies-of-a-World-Class-Cybersecurity-Operations-Center
- RSAC podcast: Turn it up to 11 — https://www.rsaconference.com/library/podcast/turn-it-up-to-11-csoc
- UnderDefense: AI-enabled incident triage — https://underdefense.com/blog/ai-enabled-incident-triage/
- Dropzone AI: Alert Triage Guide 2025 — https://dropzone.ai/resource-guide/alert-triage-guide-2025
- Security Scientist: alert deduplication — https://www.securityscientist.net/blog/12-questions-and-answers-about-alert-deduplication/
- Deepwatch glossary: Automated Incident Triage — https://www.deepwatch.com/glossary/automated-incident-triage/
- NHI Mgmt Group glossary: Alert management — https://nhimg.org/glossary/alert-management/
- NHI Mgmt Group: SOC automation and detection quality — https://nhimg.org/community/cybersecurity-beyond-identity/soc-automation-and-detection-quality-where-should-teams-start/
- NHI Mgmt Group FAQ — https://nhimg.org/faq/how-should-security-teams-turn-triage-outcomes-into-better-detections/
- Red Canary: Alert Center — https://redcanary.com/blog/alert-center/
- Red Canary: AI agentic tuning — https://redcanary.com/blog/product-updates/ai-agentic-tuning/
- Red Canary Threat Detection Report methodology — https://redcanary.com/threat-detection-report/methodology/
- Red Canary techniques — https://redcanary.com/threat-detection-report/techniques/
- IT Brief: Red Canary 2025 — https://itbrief.com.au/story/red-canary-warns-of-surge-in-identity-ai-threats-for-2025
- Panther: Tuning detections without a backlog — https://panther.com/blog/tuning-detections-without-a-backlog
- Expel: alert fatigue solutions — https://expel.com/cyberspeak/how-to-implement-alert-fatigue-solutions/
- Expel: reduce false positives — https://expel.com/cyberspeak/reduce-false-positives-in-soc-operations/
- Expel Annual Threat Report 2025 PDF — https://expel.com/wp-content/uploads/2025/01/Expel-Annual-Threat-Report-2025-013025.pdf
- Expel blog: 2025 ATR — https://expel.com/blog/its-here-expels-2025-annual-threat-report/
- Expel annual report hub — https://expel.com/annual-report/
- Expel ATR 2025 page — https://expel.com/annual-threat-report-2025/
- Target Tech: Boost Detection Confidence — https://tech.target.com/blog/boost_detection_confidence
- Security Boulevard: AiStrike — https://securityboulevard.com/2026/03/aistrike-launches-continuous-detection-engineering-to-fix-alert-noise-at-the-source/
- cyb3rops: Introducing YARA Forge — https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab
- Alex Teixeira about — https://ateixei.medium.com/about
- zendannyy Substack — https://zendannyy.substack.com/p/detection-engineering-series-detections
- TryHackMe: detection engineering — https://tryhackme.com/resources/blog/how-detection-engineering-actually-works
- Elastic Security Labs: detection engineering — https://www.elastic.co/pt/security-labs/category/detection-engineering
- Google Cloud: M-Trends 2025 — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/
- Google Cloud: M-Trends 2026 — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026
- M-Trends executive edition — https://cloud.google.com/security/resources/m-trends-executive-edition
- Verizon 2025 DBIR news release — https://verizon.com/about/news/2025-data-breach-investigations-report
- Verizon DBIR hub — https://www.verizon.com/business/resources/reports/dbir/
- Tenable: Verizon DBIR summary — https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025
- Sysdig: CVSS 4.0 — https://www.sysdig.com/blog/cvss-version-4-0-whats-new
- Qualys: CVSS v4 — https://blog.qualys.com/product-tech/2023/11/02/cvss-v4-is-now-live-and-what-do-you-need-to-know
- Cloudaware PCI DSS 4.0.1 §10.4.1 — https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/04/01/
- RSI Security: PCI DSS Requirement 10 — https://blog.rsisecurity.com/tracking-and-monitoring-under-pci-dss-requirement-10/
- Forrester ISMM blog — https://www.forrester.com/blogs/10-07-27-the_forrester_information_security_maturity_model/
- andrews.hu SOC-CMM overview — https://andrews.hu/en/blog/soc-cmm-model-security-operations-center-framework/
- CISO Tradecraft: SOC-CMM — https://cisotradecraft.substack.com/p/the-soc-assessment-tool-every-ciso
- SOC-CMM 2016 v1.1 guide (Scribd) — https://www.scribd.com/document/426096902/dd
- Microsoft Hierarchy of Cybersecurity Needs PDF — https://download.microsoft.com/download/E/6/2/E62530BF-47CC-4527-88BA-F13DF5294A65/HierarchyofCybersecurityNeeds.pdf
- Wiz Academy: SOC metrics — https://www.wiz.io/api/md/academy/detection-and-response/soc-metrics
- Secure.com: SOC metrics 2026 — https://www.secure.com/blog/soc-metrics-and-kpis
- CyberDefenders: SOC metrics — https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/
- Prophet Security: SOC metrics that matter — https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more
- Decryption Digest: SOC metrics — https://www.decryptiondigest.com/blog/soc-metrics-and-kpis
- ReliaQuest: cybersecurity metrics — https://reliaquest.com/blog/cybersecurity-metrics/
- Techspective: Why MTTD is the wrong metric — https://techspective.net/2026/06/17/why-mttd-is-wrong-metric-to-obsess-over/
- Tines blog: Pulsedive and Tines — https://www.tines.com/blog/streamlining-threat-intelligence-with-pulsedive-and-tines

---

*รายงานนี้สังเคราะห์จากบันทึกการค้นคว้าห้าชุดที่รวบรวมเมื่อ 2026-11-01 จำนวนดาว GitHub ทั้งหมดเป็นค่าโดยประมาณ ณ วันนั้น ตัวอย่างโค้ดทุกชิ้นยังไม่ได้รันทดสอบและควร smoke-test ก่อนใช้ในชั้นเรียน*
