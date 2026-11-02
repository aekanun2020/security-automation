#!/usr/bin/env bash
# Smoke-test ตัวอย่าง 1.1–1.3 (stdlib เท่านั้น ไม่ต้องมี venv)
# 1.1 ใช้ access.log ของ M5.2, 1.2 ทดสอบด้วยการ append บรรทัดลงไฟล์ชั่วคราวระหว่างที่ watcher รันอยู่, 1.3 ใช้ samples/events.jsonl
set -u
cd "$(dirname "$0")"
# เลือก interpreter: ตัวแปร PYTHON ถ้าตั้งไว้ > python3.12 > python3.11 > python3 (บทเรียนใบงาน 001: python3 ของ Xcode เป็น 3.9 และเขียน cache ที่ sandbox ห้าม)
pick_python() {
  if [ -n "${PYTHON:-}" ]; then command -v "$PYTHON"; return; fi
  for c in python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return; fi
  done
}
# ไม่เขียน bytecode cache ทั้งตอนรันและตอน pip install (Python ของ Xcode ชี้ cache ไปที่ ~/Library/Caches/com.apple.python ซึ่ง sandbox ของ Codex ห้ามเขียน)
export PYTHONDONTWRITEBYTECODE=1 PIP_NO_COMPILE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
syntax_ok() { "$1" -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' "$2"; }
PY=$(pick_python); echo "interpreter: $PY ($("$PY" --version 2>&1))"
pass=0; fail=0
run() { local label=$1; shift
  if "$@" >/tmp/smoke_out.txt 2>&1; then echo "PASS $label"; pass=$((pass+1));
  else echo "FAIL $label"; sed 's/^/    /' /tmp/smoke_out.txt | tail -5; fail=$((fail+1)); fi; }
for f in 1_*.py; do run "syntax $f" syntax_ok "$PY" "$f"; done
run "1.1 combined log counter finds scanner" bash -c "$PY 1_1_combined_log_counter.py ../02-log-analysis-automation/samples/access.log | grep -q 'SCANNER? 203.0.113.50'"
run "1.2 follow() alerts on live burst" $PY - <<'PYT'
import subprocess, sys, tempfile, time, os, threading
tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False); tmp.write("boot\n"); tmp.flush()
p = subprocess.Popen([sys.executable, "1_2_follow_log_watcher.py", tmp.name], stdout=subprocess.PIPE, text=True)
lines = []
threading.Thread(target=lambda: [lines.append(l) for l in p.stdout], daemon=True).start()
time.sleep(1.0)                      # let follow() seek to EOF before appending
with open(tmp.name, "a") as fh:
    for i in range(6):
        fh.write(f"Mar  1 02:00:0{i} server sshd[1]: Failed password for root from 203.0.113.9 port 5{i} ssh2\n"); fh.flush()
deadline = time.time() + 5
while time.time() < deadline and not any("[ALERT] 203.0.113.9" in l for l in lines):
    time.sleep(0.2)
p.kill(); os.unlink(tmp.name)
print("".join(lines).strip() or "(no output)")
sys.exit(0 if any("[ALERT] 203.0.113.9: 5 failed logins in 60s" in l for l in lines) else 1)
PYT
run "1.3 jsonl counter top value + csv" bash -c "$PY 1_3_jsonl_field_counter.py samples/events.jsonl --field source.ip --top 3 --csv /tmp/smoke_1_3.csv | head -1 | grep -q '203.0.113.50' && head -2 /tmp/smoke_1_3.csv | grep -q '^value,count'"
run "1.3 verbose logs bad JSON lines" bash -c "$PY 1_3_jsonl_field_counter.py samples/events.jsonl -v 2>&1 | grep -q 'bad JSON at'"
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
