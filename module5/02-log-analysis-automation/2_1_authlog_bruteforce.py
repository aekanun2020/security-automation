"""ตัวอย่าง 2.1 — ตรวจ burst ของ failed login ใน Linux auth.log (sliding window ด้วย deque)

ที่มา: illustrative อิงจาก documented APIs: collections.deque (docs.python.org); รูปบรรทัดและ default 5-in-300s จาก ihorpjp/soc-log-analyzer, รุ่น 5-in-60s จาก Neptunes22/Python-Security-Log-Analyzer
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_1_authlog_bruteforce.py samples/auth.log
ต้องติดตั้ง: stdlib เท่านั้น
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
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
