# ใบงาน 002–007 ชุดแรก (Python labs) — เก็บเป็นประวัติ

ร่างเมื่อ 2 พ.ย. 2026 ตามตาราง checklist "ทำให้ ELK ใกล้ QRadar ด้วยสิ่งที่ AI ทำได้" ในรูปสคริปต์ Python รอบ SIEM ที่มีอยู่ ไม่เคยถูกอนุมัติหรือรัน

เจ้าของเปลี่ยนทิศทางในวันเดียวกันเป็น "ให้ Codex สร้าง ELK เป็น SIEM" ใบงานชุดใหม่ (002–016 = T0–T14) อยู่ใน `codex-queue/queue/` และอ้างอิง [docs/elastic-siem-vs-qradar.md](../../../../docs/elastic-siem-vs-qradar.md) เนื้อหาของใบงานเดิมถูกนำไปใช้ต่อใน T8 (Sigma), T9 (threat intel feed ไม่ต้องมี key) และ T10 (ชั้น offense: fingerprint/dedupe/score) ไฟล์ในโฟลเดอร์นี้ไม่ถูกอ่านโดย Codex และไม่ควรอนุมัติ
