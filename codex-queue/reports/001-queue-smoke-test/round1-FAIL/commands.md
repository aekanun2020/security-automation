# ใบงาน 001: คำสั่งและวิธีสร้างหลักฐาน

คำสั่งจาก root ของ clone ชั่วคราว; stdout/stderr ของ smoke-test ถูกเก็บทั้งครั้ง ไม่มี rerun

```sh
PYTHON=/usr/bin/python3 bash module5/01-python-fundamentals/run_smoke_tests.sh > codex-queue/reports/001-queue-smoke-test/m5-1-smoke.txt 2>&1
env -u PIP_TARGET -u PIP_PREFIX -u PIP_USER PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple PIP_EXTRA_INDEX_URL= PIP_FIND_LINKS= PIP_TRUSTED_HOST= PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_RETRIES=0 bash module5/02-log-analysis-automation/run_smoke_tests.sh > codex-queue/reports/001-queue-smoke-test/m5-2-smoke.txt 2>&1
wc -l module5/02-log-analysis-automation/samples/auth.log module5/02-log-analysis-automation/samples/syslog.log module5/02-log-analysis-automation/samples/access.log module5/02-log-analysis-automation/samples/conn.log module5/01-python-fundamentals/samples/events.jsonl > codex-queue/reports/001-queue-smoke-test/sample-counts.txt
python3 module5/01-python-fundamentals/1_1_combined_log_counter.py module5/02-log-analysis-automation/samples/access.log > codex-queue/reports/001-queue-smoke-test/scanner.txt 2>&1
```

Smoke-test script ของ M5.2 เป็นผู้เรียก `python3 -m venv .venv`, `.venv/bin/pip install -q -r requirements.txt`, `python3 -m venv .venv-evtx` และ `.venv-evtx/bin/pip install -q -r requirements-evtx-rs.txt` ตามโค้ดที่ pin ไม่มีการรัน pip ติดตั้งซ้ำ

สร้าง hashes.json และ hash-verification.txt ด้วยคำสั่งต่อไปนี้ (รันจริงก่อน rebase โดย HEAD อยู่ที่ pin):

```sh
module5/02-log-analysis-automation/.venv/bin/python - <<'PY'
import hashlib, json, pathlib, subprocess
pin = '22c935f62e4c4b75d0973f566a7b853302983a8c'
report = pathlib.Path('codex-queue/reports/001-queue-smoke-test')
topics = ['module5/01-python-fundamentals', 'module5/02-log-analysis-automation']
paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', pin, '--', *topics], text=True).splitlines()
paths = [p for p in paths if p.endswith('.py') or pathlib.PurePosixPath(p).name == 'run_smoke_tests.sh']
files = {}
for path in paths:
    before = subprocess.check_output(['git', 'cat-file', 'blob', f'{pin}:{path}'])
    after = pathlib.Path(path).read_bytes()
    files[path] = {'before': hashlib.sha256(before).hexdigest(), 'after': hashlib.sha256(after).hexdigest()}
result = {'commit': pin, 'branch': None, 'head': None, 'files': files, 'downloads': {}}
(report / 'hashes.json').write_text(json.dumps(result, indent=2) + '\n')
lines = [f'commit={pin}', 'branch=null', 'head=null', f'files={len(files)}']
lines.extend(f'{"MATCH" if value["before"] == value["after"] else "MISMATCH"} {path} {value["after"]}' for path, value in files.items())
lines.extend([f'matching={sum(v["before"] == v["after"] for v in files.values())}', 'downloads=0'])
(report / 'hash-verification.txt').write_text('\n'.join(lines) + '\n')
print('\n'.join(lines[:4] + lines[-2:]))
PY
```

หลักฐาน Python ของระบบ:

```sh
python3 -c 'import sys; print("executable=" + sys.executable); print("version=" + sys.version.replace("\n", " ")); print("pycache_prefix=" + str(sys.pycache_prefix))' > codex-queue/reports/001-queue-smoke-test/system-python.txt
```

Codex ตรวจผลจริงและจัดประเภท PASS/FAIL เอง การคำนวณ hash/จำนวนบรรทัดเป็น deterministic check ไม่มี external LLM-as-judge
