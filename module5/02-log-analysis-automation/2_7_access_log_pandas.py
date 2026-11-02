"""ตัวอย่าง 2.7 — access log → pandas: อัตรา 404 ต่อ IP, ปริมาณรายชั่วโมง, user agent หายาก

ที่มา: illustrative อิงจาก documented APIs: pandas read_csv/value_counts (pandas.pydata.org); pattern จากตัวอย่าง 1.1; แนวทางจาก grokcode nginx-log-analysis notebook และ dev.to/ksndeveloper
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_7_access_log_pandas.py samples/access.log
ต้องติดตั้ง: pip install pandas
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import re, sys
import pandas as pd

PAT = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
                 r'(?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')
recs = [m.groupdict() for m in map(PAT.match, open(sys.argv[1], errors="replace")) if m]
df = pd.DataFrame(recs)
df["time"] = pd.to_datetime(df["time"], format="%d/%b/%Y:%H:%M:%S %z")
df["status"] = df["status"].astype(int)

per_ip = df.groupby("ip").agg(total=("status", "size"),
                              n404=("status", lambda s: (s == 404).sum()),
                              uniq_paths=("path", "nunique"))
per_ip["rate404"] = per_ip.n404 / per_ip.total
print(per_ip[(per_ip.total >= 50) & (per_ip.rate404 > 0.5)].sort_values("rate404", ascending=False))

print(df.set_index("time").resample("1h").size().tail(24))       # hourly request volume
ua_counts = df["ua"].value_counts()
print(ua_counts[ua_counts == 1].head(15))                       # long-tail / rare user agents
print(df[df.status >= 500]["path"].value_counts().head(10))     # error hot spots
