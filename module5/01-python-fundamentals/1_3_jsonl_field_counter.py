"""ตัวอย่าง 1.3 — โครง CLI สำหรับนักวิเคราะห์ด้วย argparse + logging + csv/json

ที่มา: illustrative อิงจาก documented APIs: argparse (FileType deprecated ใน 3.14 จึงเปิดไฟล์หลัง parse), logging.getLogger(__name__), csv.DictWriter กับ newline='', pathlib (docs.python.org)
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 1) โดยไม่แก้ไขตรรกะ
การใช้: python 1_3_jsonl_field_counter.py samples/events.jsonl --field source.ip --top 5 --csv out.csv
ต้องติดตั้ง: stdlib เท่านั้น
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import argparse, csv, json, logging, sys
from collections import Counter
from pathlib import Path

log = logging.getLogger(__name__)

def main(argv=None):
    p = argparse.ArgumentParser(description="Count field values in JSON-lines logs")
    p.add_argument("paths", nargs="+", type=Path, help="one or more .jsonl files")
    p.add_argument("--field", default="source.ip", help="dotted field name (ECS style)")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--csv", type=Path, help="write results to CSV")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    counts = Counter()
    for path in a.paths:
        log.info("reading %s", path)
        with path.open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("bad JSON at %s:%d", path, n); continue
                for key in a.field.split("."):
                    ev = ev.get(key, {}) if isinstance(ev, dict) else {}
                if ev: counts[str(ev)] += 1
    for value, n in counts.most_common(a.top):
        print(f"{n:8d}  {value}")
    if a.csv:
        with a.csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["value", "count"]); w.writeheader()
            w.writerows({"value": v, "count": n} for v, n in counts.most_common())
    return 0

if __name__ == "__main__":
    sys.exit(main())
