# คำสั่งและ environment ของใบงาน 001 รอบ 2

ทดสอบที่ `main@d71bf29a76efe93f63e0932c67e34d7175da7702`; cwd `/private/tmp/security-automation-001-r2.ifZNjy`

## Environment

ตัวจัดรันใช้ `/opt/anaconda3/bin/python3.12` และ `subprocess.run` เพื่อเก็บ output/exit code เท่านั้น ลบ inherited variables ที่ชื่อขึ้นต้น `PIP_` ทั้งหมด แล้วกำหนดค่าต่อไปนี้; environment อื่นไม่ถูกพิมพ์เพื่อหลีกเลี่ยง credential

```text
PYTHON=/opt/anaconda3/bin/python3.12
PYTHONDONTWRITEBYTECODE=1
PIP_NO_COMPILE=1
PIP_DISABLE_PIP_VERSION_CHECK=1
PIP_CONFIG_FILE=/dev/null
PIP_INDEX_URL=https://pypi.org/simple
PIP_NO_CACHE_DIR=1
```

## คำสั่งที่รันจริง

แต่ละคำสั่งรันครั้งเดียวตามลำดับ; stdout และ stderr รวมลงไฟล์; ไม่มี pipe ที่บดบัง exit code

### m5-1-smoke.txt

```sh
bash module5/01-python-fundamentals/run_smoke_tests.sh
```

เริ่ม 2026-11-02T17:41:07+07:00; จบ 2026-11-02T17:41:09+07:00; exit 0; [output](m5-1-smoke.txt)

### m5-2-smoke.txt

```sh
bash module5/02-log-analysis-automation/run_smoke_tests.sh
```

เริ่ม 2026-11-02T17:41:09+07:00; จบ 2026-11-02T17:41:30+07:00; exit 1; [output](m5-2-smoke.txt)

### sample-counts.txt

```sh
wc -l module5/02-log-analysis-automation/samples/auth.log module5/02-log-analysis-automation/samples/syslog.log module5/02-log-analysis-automation/samples/access.log module5/02-log-analysis-automation/samples/conn.log module5/01-python-fundamentals/samples/events.jsonl
```

เริ่ม 2026-11-02T17:41:30+07:00; จบ 2026-11-02T17:41:30+07:00; exit 0; [output](sample-counts.txt)

### scanner.txt

```sh
/opt/anaconda3/bin/python3.12 module5/01-python-fundamentals/1_1_combined_log_counter.py module5/02-log-analysis-automation/samples/access.log
```

เริ่ม 2026-11-02T17:41:30+07:00; จบ 2026-11-02T17:41:30+07:00; exit 0; [output](scanner.txt)

## ตรวจ hash และ scope

`git ls-tree -r --name-only <pin> -- module5/01-python-fundamentals module5/02-log-analysis-automation` เลือก path ที่ลงท้าย `.py` หรือ `/run_smoke_tests.sh` ได้ 13 ไฟล์ ใช้ `git cat-file blob <pin>:<path>` คำนวณ before และ `Path.read_bytes()` คำนวณ after ด้วย `hashlib.sha256` ก่อน rebase; ตรวจ `git status --porcelain -- <สองหัวข้อ>` ได้ว่าง

## Git bootstrap

`git fetch origin main` ใน workspace เดิม exit 255 เพราะ `.git/FETCH_HEAD` ถูก sandbox ปฏิเสธ จากนั้น `git clone --branch main --single-branch` จาก origin ที่ยืนยันแล้วลง mktemp directory, fetch origin main, `git merge-base --is-ancestor <pin> origin/main`, checkout main และ reset ใน clone ใหม่ไป pin เท่านั้น ตรวจ branch=main และ HEAD ตรง pin ก่อนรัน
