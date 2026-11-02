# กติกาคงที่สำหรับทุกงานในคิว (repository security-automation)

ใช้กับทุกใบงานใน `codex-queue/queue/` ของ repository นี้ (https://github.com/aekanun2020/security-automation, branch `main`) คงสาระจากคิวของ repository อ้างอิง `aekanun2020/SUT-AI-Chat-App-with-Fine-tuned-Harness-with-KM` ปรับให้เข้ากับ repo สื่อการสอนที่ไม่มี MCP, Docker หรือ paid model call

## กติกา

1. `git fetch origin main` แล้ว checkout commit ที่ระบุใน `commit:` ของใบงาน (ต้องอยู่บน branch `main`) ทำงานใน clone แยกบน branch `codex/NNN-<slug>` ที่แตกจาก commit นั้น **interpreter**: ให้ `run_smoke_tests.sh` ของหัวข้อเป็นผู้เลือก interpreter (ลำดับ: ตัวแปร `PYTHON` > `python3.12` > `python3.11` > `python3` และ M5.2 ต้องได้ ≥ 3.11) script จะสร้าง `.venv` ของหัวข้อจาก `requirements.txt` ให้เอง และตั้ง `PYTHONDONTWRITEBYTECODE=1 PIP_NO_COMPILE=1` เพื่อไม่เขียน bytecode cache บนเครื่องของเจ้าของ `python3` ใน login shell คือ Python 3.9.6 ของ Xcode ซึ่งชี้ cache ไปที่ `~/Library/Caches/com.apple.python` ที่ sandbox ห้ามเขียน (บทเรียนใบงาน 001 รอบ 1) ถ้าต้องเรียก Python เองนอก script ให้ใช้ `PYTHON=/opt/anaconda3/bin/python3.12` หรือ `.venv/bin/python` ของหัวข้อ ห้ามเรียก `python3` เปล่า ๆ และห้ามรัน `py_compile`
2. **network** ตามส่วนหัว `network:` ของใบงาน: `none` = ห้ามเรียกเครือข่ายใดนอกจาก git origin; `downloads` = ดาวน์โหลดได้เฉพาะ URL ในรายการ `downloads:` ของใบงาน ครั้งเดียว เก็บใต้ `<topic>/data/` หรือ `<report_dir>/artifacts/` (ทั้งสองอยู่ใน `.gitignore`) บันทึก sha256 และขนาดของทุกไฟล์ที่ดาวน์โหลดใน `hashes.json` ห้ามสมัครบริการ ห้ามใช้ API key ใด ห้าม commit ชุดข้อมูลที่ดาวน์โหลด
3. ห้ามรันซ้ำเพื่อแทนผลที่ตก ทุกการรัน smoke-test อยู่ในรายงาน ถ้าตกให้รายงาน FAIL ที่ข้อนั้นพร้อมค่าที่ได้จริง **ไม่แก้เกณฑ์หรือ test เพื่อให้ผ่าน**
4. `budget_usd` ของทุกใบงานในชุดนี้คือ 0: ห้ามเรียกโมเดลภายนอกหรือบริการที่เสียเงิน
5. **โค้ดจากรายงาน research ห้ามแก้ตรรกะ** ไฟล์ `module*/0*/[0-9]_*.py` ที่มี header "คัดจาก docs/python-security-automation-research.md" ถ้าพบว่ารันไม่ได้ ให้แก้เท่าที่จำเป็นหนึ่งจุด ระบุใน header ว่า "แก้ไขจากรายงาน: ..." และรายงานในข้อเสนอ ตามแบบที่ทำกับ `2_2b_evtx_rs_eventid_counts.py`
6. รายงานเต็มที่ `report_dir:` มี `README.md` เป็นหน้าแรก: ตารางหนึ่งแถวต่อเกณฑ์ ระบุคำสั่งที่รัน ค่าที่ได้จริง PASS/FAIL และลิงก์ไฟล์ output ไม่มี raw payload ขนาดใหญ่ ไม่มี credential
7. เขียน `codex-queue/results/NNN.md` **ไม่เกิน 20 บรรทัด**: ผลรวมเทียบ `pass_criteria:` แยกบรรทัด "ค่าที่ตรวจได้จากไฟล์" (ตัวเลข sha จำนวน) กับ "คำรับรองของ Codex" (สิ่งที่ไม่ได้ทำ เช่น ไม่เรียกเครือข่ายนอกรายการ) ระบุ branch และ commit สุดท้ายของงาน
8. เพิ่มหนึ่งบรรทัดใน `codex-queue/LOG.md` (เวลา ISO +07:00, id, สถานะ DONE/FAIL/BLOCKED, ตัวเลขหลัก, ลิงก์ results และรายงาน) ประวัติห้ามลบหรือแก้ย้อนหลัง
9. push สองอย่าง: (ก) branch `codex/NNN-<slug>` ที่มีไฟล์ในรายการ `files:` ของใบงาน (ข) บน `main` เฉพาะ `codex-queue/results/`, `codex-queue/LOG.md`, `codex-queue/reports/` ก่อน push ให้ fetch แล้ว rebase ห้ามแตะไฟล์อื่นทุกไฟล์ ห้าม merge เข้า `main` เอง (เจ้าของสั่ง `merge NNN`)
10. ไม่แก้ไฟล์นอกรายการ `files:` แม้พบบั๊ก ให้เขียนเป็น "ข้อเสนอ" ท้าย README ของรายงาน
11. `hashes.json` ใน `report_dir`: `{"commit": "<pin>", "branch": "codex/NNN-<slug>", "head": "<commit สุดท้ายของ branch>", "files": {"<path>": {"before": "<sha256 ที่ pin หรือ null ถ้าไฟล์ใหม่>", "after": "<sha256 ที่ head>"}}, "downloads": {"<url>": {"path": "...", "sha256": "...", "bytes": N}}}` คำนวณ before จาก `git cat-file blob <pin>:<path>` และ after จากไฟล์บนดิสก์ที่ head
12. `codex exec` ไม่มีคนตอบ ห้ามจบงานด้วยคำถาม ถ้าเดินต่อไม่ได้ (เช่น URL ใน downloads ล่ม, pip ติดตั้งไม่ได้) ให้เขียน `results/NNN-blocked-<เหตุ>.md` ไม่เกิน 20 บรรทัด บอกว่าติดอะไร ต้องการอะไรจากเจ้าของ แล้วจบโดยไม่แก้ไฟล์ใด
13. ถ้า git fetch/checkout ใน worktree ถูก sandbox ปฏิเสธ ให้ clone origin เข้า directory ชั่วคราวที่เขียนได้แล้วทำงานใน clone นั้น ไม่ติดตั้ง dependency นอก `.venv` ของหัวข้อ
14. **เทสต้องแดงก่อนเขียว** สำหรับใบงานที่สร้างไฟล์ใหม่: เพิ่มกรณีทดสอบลง `run_smoke_tests.sh` ของหัวข้อ (หรือสร้างใหม่ตามแบบของ M5.1/M5.2) ให้ตกก่อนมีไฟล์ แล้วผ่านหลังมีไฟล์ และ smoke-test เดิมของหัวข้อต้องผ่านเท่าเดิม (M5.1 = 7/7, M5.2 = 16/16 ที่ pin)
15. ทุกไฟล์ใหม่มี header docstring ระบุ: ชื่อใบงาน, ว่าเป็น "ส่วนขยาย ไม่ได้มาจากรายงาน research", แหล่งอ้างอิง API ที่ใช้, วิธีใช้ และ dependency ตามแบบ header ของ `module5/02-log-analysis-automation/2_1_authlog_bruteforce.py`
16. ข้อมูลตัวอย่างที่สร้างใหม่ต้องเป็นข้อมูลสังเคราะห์ ใช้ IP ในช่วง TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) และไม่มีข้อมูลบุคคลจริง

## ส่วนหัวของใบงาน

```
id: 001
commit: <SHA บน branch main>
approved: no|yes
budget_usd: 0
network: none|downloads
files: <รายการ path ที่แก้หรือสร้างได้ คั่นด้วย ;>
downloads: <รายการ URL ที่ดาวน์โหลดได้ คั่นด้วย ; หรือ none>
report_dir: codex-queue/reports/001-<slug>/
pass_criteria: <เกณฑ์อ่านผลที่เขียนก่อนรัน หนึ่งบรรทัด>
```

## ห้ามแตะ (ทุกงาน ทุกสถานการณ์)

- repository อ้างอิง `aekanun2020/SUT-AI-Chat-App-with-Fine-tuned-Harness-with-KM` และ repository อื่นทุกตัวของเจ้าของ ทุกไฟล์ ทุก branch ทุก remote: ห้าม clone เพื่อแก้ ห้าม push ห้ามเปิด PR ห้าม comment
- `docs/` ทั้งหมด (รายงาน research, datasets, บริบท NT, lab design, glossary และ research_notes), `README.md` ราก, `codex-queue/queue/`, `codex-queue/README.md`, `codex-queue/CODEX-RULES.md`
- โฟลเดอร์หัวข้ออื่นที่ไม่อยู่ในรายการ `files:` ของใบงาน และไฟล์ `README.md` ของหัวข้อ (Claude อัปเดตเองหลัง merge)
- `.gitignore`, `.github/`, `requirements.txt` ราก
- API key, `.env`, credential ทุกชนิด; ห้ามสมัครบริการใดในนามเจ้าของ
- ชุดข้อมูลที่ดาวน์โหลด: ห้าม commit ห้ามแจกจ่ายต่อนอก license ที่ใบงานระบุ
