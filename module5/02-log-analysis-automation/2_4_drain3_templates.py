"""ตัวอย่าง 2.4 — template mining ด้วย Drain3 พร้อม masking IP/ตัวเลข

ที่มา: อิงจาก API ใน README ของ Drain3 (TemplateMinerConfig, TemplateMiner, add_log_message, change_type/cluster_id/template_mined) https://github.com/logpai/Drain3 ; รายละเอียด config เป็น illustrative
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_4_drain3_templates.py samples/syslog.log
ต้องติดตั้ง: pip install drain3
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
import sys
from collections import Counter
from drain3 import TemplateMiner                      # pip install drain3
from drain3.template_miner_config import TemplateMinerConfig

cfg = TemplateMinerConfig()
cfg.drain_sim_th, cfg.drain_depth = 0.4, 4            # README defaults
cfg.masking_instructions = []                        # or cfg.load("drain3.ini") with [MASKING]
miner = TemplateMiner(config=cfg)

sizes = Counter()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    msg = line.split(": ", 1)[-1].rstrip()            # strip syslog header, keep message
    res = miner.add_log_message(msg)
    sizes[res["cluster_id"]] = res["cluster_size"]
    if res["change_type"] == "cluster_created":
        print(f"NEW TEMPLATE #{res['cluster_id']}: {res['template_mined']}")

print("\nRarest templates (candidate anomalies):")
for cid, n in sorted(sizes.items(), key=lambda kv: kv[1])[:5]:
    tmpl = next(c for c in miner.drain.clusters if c.cluster_id == cid).get_template()
    print(n, tmpl)
