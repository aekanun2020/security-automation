# 001 รอบเดิม pin 22c935f — FAIL
ขอบเขต: รอบเดิมเท่านั้น; upstream re-pin เป็น `d71bf29a76efe93f63e0932c67e34d7175da7702` และ approved:no; ยังไม่ได้รันฉบับใหม่
ประเมินใหม่โดย Codex; 0 USD; เกณฑ์ (1)–(5): PASS 3, FAIL 2
ค่าที่ตรวจได้จากไฟล์: M5.1 `passed=4 failed=3` (คาด 7/0), M5.2 `passed=4 failed=12` (คาด 16/0); exit 1 ทั้งคู่
ค่าที่ตรวจได้จากไฟล์: sample auth/syslog/access/conn/events = 44/121/698/109/302; SCANNER `203.0.113.50 73/80 = 91%` ตรงตัว
ค่าที่ตรวจได้จากไฟล์: SHA-256 ก่อน/หลังตรงกัน 13/13; downloads={}; hashes.branch/head=null
สาเหตุที่มีหลักฐาน: Python เขียน cache นอก sandbox ไม่ได้; pip ติดตั้ง hexdump ไม่สำเร็จ ทำให้ M5.2 dependency ไม่ครบ
คำรับรองของ Codex: เครือข่ายเฉพาะ git origin และ PyPI bootstrap; ไม่เรียกโมเดลภายนอก/บริการเสียเงิน/API key
คำรับรองของ Codex: ไม่แก้ไฟล์ tracked ใน module; รัน smoke-test หัวข้อละครั้ง; ไม่แก้ test/เกณฑ์และไม่รันซ้ำแทนผลตก
branch/commit งาน: null/null ตามข้อยกเว้น 001; ทดสอบบน `main` ที่ `22c935f62e4c4b75d0973f566a7b853302983a8c`
เผยแพร่บน `main` เฉพาะ reports/results/LOG; commit รายงานตรวจได้จาก Git history ของไฟล์นี้ (ไม่มี code commit)
[รายงานเต็ม](../reports/001-queue-smoke-test/README.md) · [hashes](../reports/001-queue-smoke-test/hashes.json) · [การรัน/exit code](../reports/001-queue-smoke-test/run-metadata.json)
ข้อเสนอ: ให้เจ้าของจัดพื้นที่ Python cache ที่เขียนได้ก่อนอนุมัติรันใหม่; ยังไม่พิสูจน์ว่าปรับแล้วผ่าน
