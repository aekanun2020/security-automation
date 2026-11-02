"""ตัวอย่าง 1.1 — parse Nginx/Apache combined log ด้วย regex + Counter (top IPs, top 404 paths, อัตรา 404 ต่อ IP)

ที่มา: illustrative อิงจาก documented APIs: nginx combined format (nginx.org/en/docs/http/ngx_http_log_module.html); re named groups/groupdict() และ collections.Counter.most_common (docs.python.org)
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 1) โดยไม่แก้ไขตรรกะ
การใช้: python 1_1_combined_log_counter.py ../02-log-analysis-automation/samples/access.log
ต้องติดตั้ง: stdlib เท่านั้น
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import re, sys
from collections import Counter, defaultdict

COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"')

hits, errs, paths_404, uas = Counter(), Counter(), Counter(), Counter()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = COMBINED.match(line)
    if not m:
        continue
    r = m.groupdict()
    hits[r["ip"]] += 1
    uas[r["ua"]] += 1
    if r["status"] == "404":
        errs[r["ip"]] += 1
        paths_404[r["path"]] += 1

print("Top talkers:", hits.most_common(5))
print("Top 404 paths:", paths_404.most_common(5))
print("Rare user agents:", [ua for ua, n in uas.items() if n == 1][:10])
for ip, total in hits.most_common():
    rate = errs[ip] / total
    if total >= 50 and rate > 0.5:          # scanner heuristic: many requests, >50% 404
        print(f"SCANNER? {ip} {errs[ip]}/{total} = {rate:.0%}")
