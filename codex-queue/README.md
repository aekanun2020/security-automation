# คิวสั่งงาน Claude → Codex (repository security-automation)

ยึดกลไกจาก `codex-queue/` ของ repository อ้างอิง `aekanun2020/SUT-AI-Chat-App-with-Fine-tuned-Harness-with-KM` (อ่านอย่างเดียว ห้ามแก้ repository นั้น) มาปรับให้เข้ากับ repo นี้ซึ่งเป็นสื่อการสอน: ไม่มี MCP, ไม่มี Docker, ไม่มี paid model call ทุกใบงานจึงมี `budget_usd: 0` และด่าน `mcp` ถูกแทนด้วยด่าน `network` (none หรือ downloads ตามรายการ URL ที่ใบงานระบุ) ดู [กติกาทุกข้อ](CODEX-RULES.md)

ใบงาน 001 คือใบงานหุ่นทดสอบกลไกคิว (ปิดเป็น DONE แล้ว) ใบงาน 002–016 (= T0–T14) ให้ Codex สร้าง Elastic Stack เป็น SIEM ที่ใกล้ QRadar ที่สุดเท่าที่ tier ฟรีอนุญาต ตาม blueprint ใน [docs/elastic-siem-vs-qradar.md](../docs/elastic-siem-vs-qradar.md) §9 ทุกอย่างถูกสร้างเป็นไฟล์ใต้ `elk-siem/` และตรวจผ่าน REST API ด้วย `elk-siem/tests/verify-T<n>.sh` ส่วน Docker เป็นของเจ้าของ (กติกาข้อ 17) ใบงานที่ต้อง start container จึงทำสองรอบ: รอบแรก Codex เขียนไฟล์แล้วจบด้วย blocked รอเจ้าของ `docker compose up`, รอบสองรัน bootstrap และ verify ใบงานชุดแรก 002–007 (สคริปต์ Python รอบ SIEM) ถูกเก็บไว้ที่ [queue/archive/python-labs-002-007/](queue/archive/python-labs-002-007/README.md) โดยไม่ลบ ชุดข้อมูลที่ใบงานสั่งดาวน์โหลดถูกตรวจ URL, license และขนาดไว้แล้วใน [รายงาน datasets](../docs/datasets-for-gap-labs.md)

## บทบาท

| ใคร | ทำอะไร | ไม่ทำอะไร |
|---|---|---|
| Claude | ร่างใบงาน `queue/NNN-*.md` โดยนับตัวเลขในเกณฑ์ด้วยคำสั่งจริงบน commit ที่ pin ก่อนส่ง; หลัง Codex push แล้ว `git fetch` รัน smoke-test ซ้ำในเครื่องของตนเอง เทียบ sha256 กับ `hashes.json`; ในรายงานแยกให้ชัดว่าข้อใด **Claude ตรวจเอง** และข้อใดเป็น **คำรับรองของ Codex** | ไม่รันงานแทน Codex ไม่อนุมัติใบงานเอง ไม่แก้ repository อ้างอิง |
| Codex | ทำงานใน clone แยกบน branch `codex/NNN-<slug>` ที่แตกจาก commit ที่ pin; แก้ได้เฉพาะไฟล์ที่ใบงานระบุ; เขียน `results/NNN.md` ≤ 20 บรรทัด, รายงานเต็ม, `hashes.json`, `LOG.md`; push branch ของงานและ scope คิว | ไม่แก้ไฟล์นอกรายการ ไม่รันซ้ำเพื่อแทนผลที่ตก ไม่ดาวน์โหลดจาก URL นอกใบงาน ไม่ใช้ API key ใด ไม่แตะ repository อื่น |
| เจ้าของ (ครูเอ้) | อนุมัติด้วยข้อความ **`อนุมัติ NNN`** เท่านั้น; ตัดสินงาน blocked/UNVERIFIED; สั่ง `merge NNN` เมื่อรับงาน | — |

ใบงานเริ่มที่ `approved: no` Claude เปลี่ยนเป็น `approved: yes` ได้เมื่อเจ้าของพิมพ์ `อนุมัติ NNN` ตรงเลขงานเท่านั้น ข้อความอื่น เช่น "โอเค" "ไปต่อ" ไม่นับ

## ไฟล์

| ที่ | ใคร | อะไร |
|---|---|---|
| `queue/NNN-<slug>.md` | Claude | ใบงานหนึ่งงาน ส่วนหัวตาม [CODEX-RULES.md](CODEX-RULES.md): pin commit, งบ (0), `network` (none/downloads/local), `files` ที่แก้ได้, `downloads` ที่อนุญาต, report_dir, เกณฑ์ผ่านที่เขียนก่อนรัน ใบงาน ELK ระบุด้วยว่าเจ้าของต้องรัน `docker compose` อะไรก่อน |
| `results/NNN.md` | Codex | สรุป **ไม่เกิน 20 บรรทัด** แยก "ค่าที่ตรวจได้จากไฟล์" กับ "คำรับรองของ Codex" พร้อม branch และ commit ของงาน |
| `results/NNN-blocked-<เหตุ>.md` | Codex | งานหยุดก่อนทำ บอกว่าติดอะไร ต้องการอะไรจากเจ้าของ |
| `reports/NNN-<slug>/` | Codex | รายงานเต็ม: `README.md`, `hashes.json`, output ของ smoke-test, `blocked/` ประวัติการบล็อก; ไฟล์ดิบขนาดใหญ่ไว้ใต้ `artifacts/` ซึ่ง `.gitignore` ไม่ติดตาม |
| `LOG.md` | Codex | หนึ่งบรรทัดต่อเหตุการณ์: เวลา, id, สถานะ, ตัวเลขหลัก, ลิงก์ |
| `CODEX-RULES.md` | คงที่ | กติกาทุกงาน (ส่งเป็นส่วนแรกของ prompt ให้ Codex ทุกครั้ง) |

## ลำดับเหตุการณ์

1. Claude push `queue/NNN-*.md` (`approved: no`) และบอกเจ้าของว่าใบงานต้องการ network อะไร ดาวน์โหลดอะไร ขนาดเท่าไร
2. เจ้าของพิมพ์ `อนุมัติ NNN` → Claude แก้เป็น `approved: yes` แล้ว commit+push
3. เจ้าของรัน Codex บนเครื่องของตนด้วย prompt = `CODEX-RULES.md` + ใบงาน (เช่น `codex exec "$(cat codex-queue/CODEX-RULES.md codex-queue/queue/NNN-*.md)"`) → Codex clone, แตก branch จาก pin, ทำงาน, รัน smoke-test, เขียนผล, push branch `codex/NNN-<slug>` และ scope คิวบน `main`
4. Claude `git fetch origin` → checkout branch ของงานใน worktree ชั่วคราว → รัน smoke-test ซ้ำ → เทียบ `hashes.json` → อ่าน `results/NNN.md` → รายงานเจ้าของ
5. เจ้าของสั่ง `merge NNN` → Claude merge branch เข้า `main` (fast-forward หรือ merge commit) แล้ว push; งานที่ blocked: เจ้าของแก้เหตุแล้วลบ `results/NNN-blocked-*.md` → รันเลขเดิมใหม่

## ฝั่งเจ้าของ (MacBook)

```sh
cd ~/security-automation
git checkout main && git pull --rebase
codex exec "$(cat codex-queue/CODEX-RULES.md codex-queue/queue/00N-*.md)"
```

ไม่ต้อง export key ใด ทุกใบงานเป็น 0 USD และใช้เฉพาะ feed/ชุดข้อมูลที่ไม่ต้องมี key สำหรับใบงาน ELK ให้ตั้ง memory ของ Docker Desktop ≥ 16 GB ก่อน และรัน `docker compose` ตามที่ใบงานระบุเมื่อ Codex จบรอบแรกด้วย blocked-waiting-owner

[กลับหน้าหลัก](../README.md)
