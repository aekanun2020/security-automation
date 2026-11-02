"""ตัวอย่าง 1.2 — streaming log watcher แบบ tail -f ด้วย generator พร้อม alert แบบ live

ที่มา: idiom follow() จาก David Beazley, PyCon 2008 "Generator Tricks for Systems Programmers" (dabeaz.com/generators2) เขียนใหม่ในรายงานเพราะไฟล์ต้นฉบับดึงไม่สำเร็จ; การตรวจ rate ด้วย collections.deque (docs.python.org)
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 1) โดยไม่แก้ไขตรรกะ
การใช้: python 1_2_follow_log_watcher.py /var/log/auth.log   (รันค้างไว้ หยุดด้วย Ctrl-C)
ต้องติดตั้ง: stdlib เท่านั้น
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
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
