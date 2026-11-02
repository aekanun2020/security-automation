# ใบงาน 001 รอบ 2: queue smoke-test — FAIL

Codex ประเมินใหม่จาก output ของการรันครั้งนี้เอง เวลา 2026-11-02T17:42:34+07:00 ไม่ใช้ผลตัดสินจากโมเดลภายนอก ผลเกณฑ์ (1)–(5): **PASS 4, FAIL 1**; ค่าใช้จ่ายบริการภายนอกที่เรียกใช้ 0 USD

ทดสอบบน branch `main` ที่ pin `d71bf29a76efe93f63e0932c67e34d7175da7702` ใน clone ใหม่ `/private/tmp/security-automation-001-r2.ifZNjy` หลัง `git fetch origin main` และตรวจว่า pin เป็น ancestor ของ `origin/main` งานนี้ไม่มี branch งานหรือ code commit ตามข้อยกเว้นของ [ใบงานที่อนุมัติ](../../queue/001-queue-smoke-test.md); `branch` และ `head` ใน manifest เป็น `null`

| ข้อ | คำสั่งที่รัน | เกณฑ์ | ค่าที่ได้จริง | ผล | Output |
| --- | --- | --- | --- | --- | --- |
| 1 | `bash module5/01-python-fundamentals/run_smoke_tests.sh` โดยตั้ง environment ตาม [commands.md](commands.md) | interpreter ≥3.11; บรรทัดสุดท้าย `passed=7 failed=0` | `/opt/anaconda3/bin/python3.12 (Python 3.12.7)`; `passed=7 failed=0`; exit 0 | **PASS** | [m5-1-smoke.txt](m5-1-smoke.txt) |
| 2 | `bash module5/02-log-analysis-automation/run_smoke_tests.sh` ด้วย environment เดียวกัน; script สร้าง `.venv` และ `.venv-evtx` เอง | interpreter ≥3.11; dependency ครบ; บรรทัดสุดท้าย `passed=16 failed=0` | Python 3.12.7; `passed=10 failed=6`; exit 1; pip build-dependency download timeout ทำให้ dependency ไม่ครบ | **FAIL** | [m5-2-smoke.txt](m5-2-smoke.txt) |
| 3 | `wc -l` กับ auth.log, syslog.log, access.log, conn.log และ events.jsonl ตาม [คำสั่งเต็ม](commands.md) | 44/121/698/109/302 ตามลำดับ | 44/121/698/109/302; รวม 1274; exit 0 | **PASS** | [sample-counts.txt](sample-counts.txt) |
| 4 | `/opt/anaconda3/bin/python3.12 module5/01-python-fundamentals/1_1_combined_log_counter.py module5/02-log-analysis-automation/samples/access.log` | บรรทัดสุดท้าย `SCANNER? 203.0.113.50 73/80 = 91%` ตรงตัว | `SCANNER? 203.0.113.50 73/80 = 91%`; exit 0 | **PASS** | [scanner.txt](scanner.txt) |
| 5 | Python `hashlib.sha256` กับ `git ls-tree`, `git cat-file blob <pin>:<path>` และไฟล์บนดิสก์หลังรันที่ pin ก่อน rebase | Python 3+8 ไฟล์ และ smoke script 2 ไฟล์ รวม 13; before=after ทุกไฟล์; branch/head=null | 13/13 ตรงกัน; module changes=0; branch/head=null; downloads={} | **PASS** | [hashes.json](hashes.json), [hash-verification.txt](hash-verification.txt) |

## หลักฐานของข้อที่ไม่ผ่าน

M5.2 เริ่มที่ 2026-11-02T17:41:09+07:00 และจบที่ 2026-11-02T17:41:30+07:00 การติดตั้ง build dependencies ของ pip ดาวน์โหลด `setuptools-84.2.1-py3-none-any.whl` แล้วเกิด `TimeoutError` และ `ReadTimeoutError: HTTPSConnectionPool(host='files.pythonhosted.org', port=443): Read timed out.` ขั้น pip subprocess จบด้วย exit 2 จึงยืนยันว่าติดตั้ง dependency จาก requirements ครบไม่ได้

Script ไม่มี `set -e` จึงทำ smoke-test ต่อ ได้ syntax PASS 8 ข้อ, auth.log PASS และ pyevtx-rs import ใน `.venv-evtx` PASS รวม 10 ข้อ อีก 6 ข้อ FAIL ด้วย `ModuleNotFoundError` สำหรับ `Evtx`, `pandas` (3 ข้อ), `drain3` และ `sigma` หลักฐานนี้ระบุว่า bootstrap ไม่สำเร็จ ไม่เพียงพอจะสรุปว่าตรรกะ module ผิด หรือว่าแก้ timeout แล้วจะผ่านครบ

จัดเป็น **FAIL** ตามใบงานเฉพาะนี้ เพราะทั้งสอง script รันและสรุปผลได้ โดย M5.2 มีค่าจริงไม่ตรงเกณฑ์ ไม่ใช่กรณีรันไม่ได้เลย เก็บ stdout/stderr รวมในไฟล์ output ของแต่ละคำสั่ง และเก็บ exit code กับลิงก์ชื่อไฟล์ output ไว้ใน [run-metadata.json](run-metadata.json) รัน smoke-test หัวข้อละหนึ่งครั้ง ไม่มีการติดตั้งซ่อมเองหรือรันซ้ำแทนผลตก

## ค่าที่ตรวจได้จากไฟล์

Output ระบุ Python 3.12.7 ทั้งสองชุด; M5.1 `passed=7 failed=0`; M5.2 `passed=10 failed=6`; sample 44/121/698/109/302; บรรทัด SCANNER ตรงตัว; SHA-256 ของ Python 11 ไฟล์และ scripts 2 ไฟล์ before=after ครบ 13/13; `downloads={}` การตรวจ Git หลังรันที่ pin ไม่พบการเปลี่ยนแปลง tracked หรือ unignored ภายในสองหัวข้อ

`before` คำนวณจาก bytes ของ `git cat-file blob d71bf29a76efe93f63e0932c67e34d7175da7702:<path>`; `after` จาก bytes ของไฟล์บนดิสก์หลังรันที่ pin ก่อน rebase ไม่ได้อ้าง hash ของไฟล์จาก upstream หลังทดสอบ

## คำรับรองของ Codex

เครือข่ายเฉพาะ git origin `https://github.com/aekanun2020/security-automation.git` และ pip bootstrap ผ่าน PyPI (`pypi.org`/`files.pythonhosted.org`) ตั้ง `PIP_CONFIG_FILE=/dev/null` และลบตัวแปร PIP เดิมทั้งหมดก่อนกำหนด index เป็น PyPI ไม่มีการเรียกโมเดลภายนอก บริการเสียเงิน API key หรือสมัครบริการ และไม่ดาวน์โหลด dataset รายการ `downloads` จึงเป็นว่างตามข้อยกเว้น pip bootstrap ของใบงาน ไม่มี packet capture อิสระ; คำรับรองนี้แยกจากค่าที่ตรวจได้จากไฟล์

ไม่แก้ไฟล์ใน module, smoke scripts, tests, เกณฑ์, requirements, README ราก/หัวข้อ, docs, queue, กติกา หรือ repository อื่น Script สร้างเพียง venv ที่ ignored ภายในหัวข้อและไฟล์ชั่วคราวตามพฤติกรรมเดิม ตั้ง `PYTHONDONTWRITEBYTECODE=1 PIP_NO_COMPILE=1` และไม่เรียก `python3` เปล่าหรือ `py_compile`

workspace เดิมถูก sandbox ปฏิเสธ `git fetch origin main` ด้วย `cannot open '.git/FETCH_HEAD': Operation not permitted` จึงใช้ clone ชั่วคราวที่เขียนได้ตามกติกา ไม่แก้สิทธิ์ workspace เดิม สำหรับการเผยแพร่ commit แล้ว fetch/rebase บน `main` และส่งเฉพาะรายงาน/results/LOG โดยไม่สร้างหรือ merge branch งาน ประวัติ LOG เดิมคงครบและเพิ่มผลรอบนี้หนึ่งบรรทัด

## ประวัติแยกจากการประเมินครั้งนี้

[รายงาน FAIL รอบ 1](round1-FAIL/README.md) และ [ผลรอบ 1](../../results/001-round1-FAIL.md) เป็นหลักฐานย้อนหลังที่ upstream เก็บแยกไว้ ไม่ใช่ผลรันที่ pin รอบ 2 นี้ ไม่มีการแก้ไขหลักฐานรอบเดิม

## ข้อเสนอ

เจ้าของควรตรวจการดาวน์โหลดจาก `files.pythonhosted.org` ในสภาพแวดล้อมที่ใช้รัน ก่อนอนุมัติการรันครั้งใหม่ งานนี้ไม่ได้สั่ง retry ดาวน์โหลดหรือติดตั้ง dependency เพิ่มนอก script เปลี่ยน timeout หรือแก้ implementation จึงยังไม่พิสูจน์ว่ารอบใหม่จะผ่าน 16/16

ลิงก์เก่าบางแห่งในรายงานรอบ 1 ไม่ตรงหลัง upstream ย้าย archive; ควรตรวจการนำทางของ archive ในงานแยก งานนี้ไม่แก้ย้อนหลัง
