#!/usr/bin/env bash
# Smoke-test ตัวอย่าง 2.1–2.7 กับ sample log ในโฟลเดอร์ samples/
# ใช้: ./run_smoke_tests.sh   (สร้าง .venv จาก requirements.txt และ .venv-evtx จาก requirements-evtx-rs.txt ให้อัตโนมัติถ้ายังไม่มี)
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
BASEPY=$(pick_python)
if ! "$BASEPY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "ต้องการ Python >= 3.11 สำหรับ pySigma แต่ได้ $BASEPY ($("$BASEPY" --version 2>&1)) ตั้งตัวแปร PYTHON ให้ชี้ไป python3.11+ แล้วรันใหม่"; exit 2
fi
echo "interpreter: $BASEPY ($("$BASEPY" --version 2>&1))"
if [ ! -x .venv/bin/python ]; then
  "$BASEPY" -m venv .venv && .venv/bin/pip install -q -r requirements.txt
fi
PY=.venv/bin/python
pass=0; fail=0
run() {  # run <label> <command...>
  local label=$1; shift
  if "$@" >/tmp/smoke_out.txt 2>&1; then echo "PASS $label"; pass=$((pass+1));
  else echo "FAIL $label"; sed 's/^/    /' /tmp/smoke_out.txt | tail -5; fail=$((fail+1)); fi
}
for f in 2_*.py; do run "syntax $f" syntax_ok "$PY" "$f"; done
run "2.1 auth.log brute force"      $PY 2_1_authlog_bruteforce.py samples/auth.log
run "2.2 python-evtx import"        $PY -c "import Evtx.Evtx"
if [ ! -x .venv-evtx/bin/python ]; then "$BASEPY" -m venv .venv-evtx && .venv-evtx/bin/pip install -q -r requirements-evtx-rs.txt; fi
run "2.2b pyevtx-rs import (venv แยก)" .venv-evtx/bin/python -c "from evtx import PyEvtxParser"
run "2.3 syslog -> pandas"          $PY 2_3_syslog_to_pandas.py samples/syslog.log
run "2.4 Drain3 templates"          $PY 2_4_drain3_templates.py samples/syslog.log
run "2.5 pySigma -> Splunk"         $PY 2_5_pysigma_convert.py
run "2.6 Zeek beacon candidates"    $PY 2_6_zeek_beacon_candidates.py samples/conn.log
run "2.7 access log -> pandas"      $PY 2_7_access_log_pandas.py samples/access.log
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
