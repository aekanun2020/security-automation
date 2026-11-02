"""ตัวอย่าง 2.6 — Zeek conn.log → pandas ด้วย ZAT แล้วหา beacon candidates จากความสม่ำเสมอของ inter-arrival

ที่มา: การเรียก ZAT จาก examples/zeek_to_pandas.py ของโครงการ (LogToDataFrame().create_dataframe) https://github.com/SuperCowPowers/zat ; heuristic CV-of-intervals สะท้อนแนวคิด repeating intervals ของ RITA (activecountermeasures.com); threshold CV < 0.3 เป็น illustrative ยืนยันจากแหล่งต้นทางไม่ได้
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_6_zeek_beacon_candidates.py samples/conn.log
ต้องติดตั้ง: pip install zat pandas
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import sys
import pandas as pd
from zat.log_to_dataframe import LogToDataFrame      # pip install zat

df = LogToDataFrame().create_dataframe(sys.argv[1])  # Zeek conn.log (TSV) -> DataFrame, ts index
df = df.reset_index().sort_values("ts")

rows = []
for (src, dst, port), g in df.groupby(["id.orig_h", "id.resp_h", "id.resp_p"]):
    if len(g) < 12:                                  # need enough connections for stats
        continue
    gaps = g["ts"].diff().dt.total_seconds().dropna()
    mean, std = gaps.mean(), gaps.std()
    cv = std / mean if mean else float("inf")        # coefficient of variation of intervals
    rows.append((src, dst, port, len(g), round(mean, 1), round(cv, 3),
                 round(g["orig_bytes"].std() / max(g["orig_bytes"].mean(), 1), 3)))

cols = ["src", "dst", "port", "conns", "mean_gap_s", "gap_cv", "bytes_cv"]
res = pd.DataFrame(rows, columns=cols)
beacons = res[(res.gap_cv < 0.3) & (res.bytes_cv < 0.5)].sort_values("gap_cv")
print(beacons.head(20).to_string(index=False))
