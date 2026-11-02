# 001 รอบ 2 — FAIL
Codex ประเมินใหม่จากการรันจริงที่ pin `d71bf29a76efe93f63e0932c67e34d7175da7702`; เกณฑ์ (1)–(5): PASS 4, FAIL 1; 0 USD
ค่าที่ตรวจได้จากไฟล์: Python 3.12.7 ทั้งคู่; M5.1 `passed=7 failed=0` exit 0; M5.2 `passed=10 failed=6` exit 1 (คาด 16/0)
ค่าที่ตรวจได้จากไฟล์: sample auth/syslog/access/conn/events = 44/121/698/109/302; SCANNER `203.0.113.50 73/80 = 91%` ตรงตัว
ค่าที่ตรวจได้จากไฟล์: SHA-256 before=after 13/13; module changes=0; downloads={}; hashes.branch/head=null
ข้อ (2) FAIL: pip build-dependency ดาวน์โหลด setuptools จาก files.pythonhosted.org แล้ว ReadTimeoutError; dependency ไม่ครบ เกิด ModuleNotFoundError 6 ข้อ
คำรับรองของ Codex: เครือข่ายเฉพาะ git origin และ PyPI bootstrap; ไม่ใช้โมเดลภายนอก บริการเสียเงิน API key หรือดาวน์โหลด dataset
คำรับรองของ Codex: ไม่แก้ไฟล์ module/test/เกณฑ์; smoke-test หัวข้อละครั้ง; ไม่ retry หรือรันซ้ำแทนผลตก
branch/commit งาน: null/null ตามข้อยกเว้น 001; ทดสอบ `main@d71bf29a76efe93f63e0932c67e34d7175da7702`
เผยแพร่รายงานบน `main` เฉพาะ reports/results/LOG; commit สุดท้ายของรายงานดู Git history ของไฟล์นี้ (ไม่มี code commit)
[รายงานเต็ม](../reports/001-queue-smoke-test/README.md) · [hashes](../reports/001-queue-smoke-test/hashes.json) · [การรัน/exit](../reports/001-queue-smoke-test/run-metadata.json)
ข้อเสนอ: ตรวจ PyPI download ก่อนอนุมัติรันใหม่; ยังไม่พิสูจน์ว่าจะผ่าน 16/16; ไม่แก้ไฟล์เพื่อให้ผ่าน
