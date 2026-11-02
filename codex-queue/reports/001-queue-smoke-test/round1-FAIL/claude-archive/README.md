# 001 รอบที่ 1 (2026-11-02 15:47–15:48 +07:00) — หยุดก่อนส่งมอบ

Claude คัดลอกไฟล์ที่ Codex เขียนไว้ใน clone ชั่วคราว (`/private/tmp/security-automation-001-20261102`) มาเก็บเป็นประวัติ เพราะ Codex เสียการเชื่อมต่อเครือข่ายหลัง 17:17 น. และไม่ได้เขียน results/LOG หรือ push

## สิ่งที่รอบนี้พิสูจน์ได้

- กลไกอนุมัติทำงาน: รอบก่อนหน้า Codex เห็น `approved: no` แล้วหยุดโดยไม่ทำอะไร
- Codex ทำตามกติกาข้อ 13 (fetch ใน workspace ถูก sandbox ปฏิเสธ → clone ไปที่ /private/tmp) และข้อ 3 (ไม่รันซ้ำเพื่อแทนผลที่ตก)
- ข้อ (3) sample-counts และ (4) SCANNER ผ่าน; ข้อ (5) hashes 13/13 ตรง git blob ที่ pin (`hash-verification.txt`)

## สิ่งที่ล้ม และสาเหตุ

- ข้อ (1) M5.1 `passed=4 failed=3` และข้อ (2) M5.2 `passed=4 failed=12`
- สาเหตุเดียว (`system-python.txt`): login shell ของ Codex ชี้ `python3` ไปที่ Python 3.9.6 ของ Xcode ซึ่งตั้ง `pycache_prefix=~/Library/Caches/com.apple.python` sandbox แบบ workspace-write ห้ามเขียนที่นั่น ทำให้ `py_compile` ล้มทุกไฟล์ และ pip ล้มตอน compile แพ็กเกจ (hexdump ของ python-evtx) นอกจากนี้ 3.9 ต่ำกว่าที่ pySigma ต้องการ (≥ 3.11)
- เป็นข้อบกพร่องของ harness (`run_smoke_tests.sh` ที่ Claude เขียน) ไม่ใช่ของโค้ดจากรายงาน research และไม่ใช่ความผิดของ Codex

## การแก้ (โดย Claude ใน commit ถัดไป)

- `run_smoke_tests.sh` ทั้งสองเลือก interpreter เอง (`PYTHON` env > python3.12 > python3.11 > python3), M5.2 ปฏิเสธ Python < 3.11 ตั้งแต่ต้นพร้อมข้อความชัด, ตรวจ syntax ด้วย `ast.parse` แทน `py_compile`, และ `export PYTHONDONTWRITEBYTECODE=1 PIP_NO_COMPILE=1`
- ใบงาน 001 ถูก re-pin ไปยัง commit ที่แก้แล้ว และรีเซ็ตเป็น `approved: no` รอเจ้าของอนุมัติใหม่
