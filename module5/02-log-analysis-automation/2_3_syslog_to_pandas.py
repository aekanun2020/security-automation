"""ตัวอย่าง 2.3 — โหลด syslog (RFC 5424 และแบบดั้งเดิม) เข้า pandas แล้ว resample

ที่มา: illustrative อิงจาก documented APIs: RFC 5424 HEADER และ PRI = facility×8+severity (datatracker.ietf.org/doc/html/rfc5424); pandas.read_csv/to_datetime (pandas.pydata.org)
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_3_syslog_to_pandas.py samples/syslog.log
ต้องติดตั้ง: pip install pandas
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import re, sys
import pandas as pd

RFC5424 = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<ver>\d) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) '
    r'(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|\[.*?\]) ?(?P<msg>.*)$')
BSD = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) '
    r'(?P<app>[^\[:]+)(?:\[(?P<procid>\d+)\])?: (?P<msg>.*)$')

rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = RFC5424.match(line) or BSD.match(line)
    if m:
        rows.append(m.groupdict())
df = pd.DataFrame(rows)
if "pri" in df:
    pri = pd.to_numeric(df["pri"], errors="coerce")
    df["facility"], df["severity"] = pri // 8, pri % 8      # RFC 5424 §6.2.1
df["ts"] = pd.to_datetime(df["ts"], errors="coerce", utc=True, format="mixed")
df = df.dropna(subset=["ts"]).set_index("ts").sort_index()
print(df["app"].value_counts().head(10))
print(df[df.get("severity", 7) <= 3].resample("5min").size())   # error+ per 5 minutes
