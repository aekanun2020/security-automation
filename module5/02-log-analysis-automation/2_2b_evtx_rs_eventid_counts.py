"""ตัวอย่าง 2.2b — นับ Event ID ด้วย pyevtx-rs (Rust-backed)

ที่มา: อิงจาก README ของ pyevtx-rs (PyEvtxParser(path), records_json(), skip_errors=True) https://github.com/omerbenamram/pyevtx-rs ; หมายเหตุ: EventID อาจ serialize เป็น dict ที่มี #text เมื่อมี attribute
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_2b_evtx_rs_eventid_counts.py Security.evtx
ต้องติดตั้ง: pip install evtx (ไม่มี sample .evtx ใน repo)
แก้ไขจากรายงาน: บรรทัด import (evtx 0.15.0 export PyEvtxParser ที่ top-level ไม่ใช่ evtx.parser)
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import json, sys
from collections import Counter
from evtx import PyEvtxParser             # pip install evtx  (แก้จากรายงาน: evtx 0.15.0 ไม่มี submodule evtx.parser)

parser = PyEvtxParser(sys.argv[1], skip_errors=True)
eids = Counter()
for rec in parser.records_json():
    ev = json.loads(rec["data"])["Event"]
    eids[str(ev["System"]["EventID"])] += 1   # EventID may be int or {"#text": ...}
print(eids.most_common(10))
