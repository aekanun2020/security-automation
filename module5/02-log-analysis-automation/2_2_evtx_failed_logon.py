"""ตัวอย่าง 2.2 — อ่าน Windows EVTX ด้วย python-evtx และดึง Event ID 4625 (failed logon)

ที่มา: อิงจาก README ของ python-evtx (evtx_dump.py: วน log.records() แล้ว record.xml()) https://github.com/williballenthin/python-evtx ; การดึง field จาก XML เป็น illustrative
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_2_evtx_failed_logon.py Security.evtx
ต้องติดตั้ง: pip install python-evtx (ไม่มี sample .evtx ใน repo)
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
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
