#!/usr/bin/env bash
# Smoke-test ตัวอย่าง 2.1–2.7 กับ sample log ในโฟลเดอร์ samples/
# ใช้: ./run_smoke_tests.sh   (สร้าง .venv จาก requirements.txt และ .venv-evtx จาก requirements-evtx-rs.txt ให้อัตโนมัติถ้ายังไม่มี)
set -u
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
fi
PY=.venv/bin/python
pass=0; fail=0
run() {  # run <label> <command...>
  local label=$1; shift
  if "$@" >/tmp/smoke_out.txt 2>&1; then echo "PASS $label"; pass=$((pass+1));
  else echo "FAIL $label"; sed 's/^/    /' /tmp/smoke_out.txt | tail -5; fail=$((fail+1)); fi
}
for f in 2_*.py; do run "compile $f" $PY -m py_compile "$f"; done
run "2.1 auth.log brute force"      $PY 2_1_authlog_bruteforce.py samples/auth.log
run "2.2 python-evtx import"        $PY -c "import Evtx.Evtx"
if [ ! -x .venv-evtx/bin/python ]; then python3 -m venv .venv-evtx && .venv-evtx/bin/pip install -q -r requirements-evtx-rs.txt; fi
run "2.2b pyevtx-rs import (venv แยก)" .venv-evtx/bin/python -c "from evtx import PyEvtxParser"
run "2.3 syslog -> pandas"          $PY 2_3_syslog_to_pandas.py samples/syslog.log
run "2.4 Drain3 templates"          $PY 2_4_drain3_templates.py samples/syslog.log
run "2.5 pySigma -> Splunk"         $PY 2_5_pysigma_convert.py
run "2.6 Zeek beacon candidates"    $PY 2_6_zeek_beacon_candidates.py samples/conn.log
run "2.7 access log -> pandas"      $PY 2_7_access_log_pandas.py samples/access.log
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
