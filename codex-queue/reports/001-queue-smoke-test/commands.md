# คำสั่งและวิธีเก็บหลักฐาน — ใบงาน 001 รอบ 3

คำสั่งทั้งหมดทำใน clone แยกของ origin ที่อนุญาต ไม่แตะ working tree ของเจ้าของ

```sh
git clone --branch main --single-branch https://github.com/aekanun2020/security-automation.git /private/tmp/security-automation-001.6nvzgP
cd /private/tmp/security-automation-001.6nvzgP
git fetch origin main
git merge-base --is-ancestor d71bf29a76efe93f63e0932c67e34d7175da7702 origin/main
git switch -C main d71bf29a76efe93f63e0932c67e34d7175da7702
git rev-parse HEAD
mkdir -p codex-queue/reports/001-queue-smoke-test
```

รันสองคำสั่งต่อไปนี้ตามลำดับ หัวข้อละหนึ่งครั้ง เก็บ stdout และ stderr รวมกันในไฟล์ที่ระบุ ทั้งสอง exit 0

```sh
bash module5/01-python-fundamentals/run_smoke_tests.sh > codex-queue/reports/001-queue-smoke-test/m5-1-smoke.txt 2>&1
env -u PIP_EXTRA_INDEX_URL -u PIP_FIND_LINKS -u PIP_NO_INDEX PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple PIP_NO_CACHE_DIR=1 PIP_NO_INPUT=1 bash module5/02-log-analysis-automation/run_smoke_tests.sh > codex-queue/reports/001-queue-smoke-test/m5-2-smoke.txt 2>&1
wc -l module5/02-log-analysis-automation/samples/auth.log module5/02-log-analysis-automation/samples/syslog.log module5/02-log-analysis-automation/samples/access.log module5/02-log-analysis-automation/samples/conn.log module5/01-python-fundamentals/samples/events.jsonl > codex-queue/reports/001-queue-smoke-test/sample-counts.txt
PYTHONDONTWRITEBYTECODE=1 /opt/anaconda3/bin/python3.12 module5/01-python-fundamentals/1_1_combined_log_counter.py module5/02-log-analysis-automation/samples/access.log > codex-queue/reports/001-queue-smoke-test/scanner.txt 2>&1
```

script เลือก `/opt/anaconda3/bin/python3.12` เองจาก PATH ไม่ได้ตั้งตัวแปร `PYTHON` และ script ตั้ง `PYTHONDONTWRITEBYTECODE=1 PIP_NO_COMPILE=1` เอง การกำหนดค่า pip ด้านบนจำกัด index ให้ PyPI, ปิด config/extra index/find-links และ cache โดยไม่เปลี่ยน test หรือ dependency

## การคำนวณ hashes

เรียก `PYTHONDONTWRITEBYTECODE=1 /opt/anaconda3/bin/python3.12 -` ส่งโปรแกรมผ่าน stdin โดยโปรแกรมตรวจ HEAD/branch ว่าเป็น pin บน main, เรียกคำสั่งต่อไปนี้ผ่าน `subprocess.check_output` แล้วเลือกเฉพาะ `.py` และ `run_smoke_tests.sh` รวม 13 ไฟล์

```sh
git ls-tree -r --name-only d71bf29a76efe93f63e0932c67e34d7175da7702 -- module5/01-python-fundamentals module5/02-log-analysis-automation
git cat-file blob d71bf29a76efe93f63e0932c67e34d7175da7702:<path>
```

`before = hashlib.sha256(blob).hexdigest()`; `after = hashlib.sha256(Path(path).read_bytes()).hexdigest()` เขียนผลตรงตาม schema ลง [hashes.json](hashes.json) และรายการค่าเต็มลง [hash-verification.txt](hash-verification.txt) ตรวจซ้ำเฉพาะ hash/หลักฐานหลัง smoke จบ โดยไม่รัน smoke ซ้ำ

```sh
git diff --exit-code -- module5
git status --short --untracked-files=all
```

ก่อนส่งขึ้น origin จะ commit เฉพาะรายงาน/results/LOG, `git fetch origin main`, `git rebase origin/main`, ตรวจ diff และประวัติเดิม แล้ว `git push origin main` ไม่มี branch งานและไม่มีการ merge code
