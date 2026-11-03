# Lab 1 — parser: log บรรทัดนี้ใช้ parser ไหน (G1)

**หัวข้อ** M5.2 (parse, normalize), M5.1 (อ่าน contract) · **เวลา** 30 นาที · **ข้อมูล** `module5/02-log-analysis-automation/samples/auth.log` (44 บรรทัด) และ `coherent-pcap-suricata-alerts-340.jsonl` ใน HDFS

## โจทย์

SIEM ไม่มี parser สำหรับทุกแหล่ง (gap G1) ผู้เรียนต้องให้ Claude หาว่า log ที่ได้มามี parser รองรับหรือไม่ ถ้ามี ทดสอบให้เห็นฟิลด์ที่ normalize แล้ว ถ้าไม่มี ร่าง parser ใหม่เป็น draft

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ บันทึกคำตอบในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | บรรทัด sshd มี parser รองรับไหม `resolve` คืนค่าอะไรใน `selected`, `candidates`, `unknown_format` | JSON ที่ `log_skill_resolve` คืน (ขั้น 1) |
| 2 | บรรทัด Suricata ได้ parser ตัวไหน score และ confidence เท่าไร | ตาราง candidates จาก `log_skill_resolve` (ขั้น 2) |
| 3 | parser กลุ่ม netflow ได้ score 30 ทำไมจึงใช้ไม่ได้ | ฟิลด์ `parse_success` ของ candidate นั้น |
| 4 | parser ที่เลือกใช้ fingerprint กี่ตัว, mapping กี่ฟิลด์, `required_output` กี่ฟิลด์ | YAML จาก `log_skill_get` ของ skill parser |
| 5 | บรรทัด Suricata แรกหลัง parse ได้ `event_time`, `source_ip` → `destination_ip:port`, `signature`, `severity` เป็นค่าอะไร และ `event_time` แปลงมาจากฟิลด์ดิบใด | ผล `log_skill_test_parser` record ที่ `parse_status: parsed` |
| 6 | ฟิลด์ที่ไม่อยู่ใน canonical schema (เช่น `alert_id`, `pcap_count`) ไปอยู่ที่ใด ถูกทิ้งไหม | โครง record ที่ parse แล้ว |
| 7 | ถ้า record ขาดฟิลด์ใน `required_output` จะเกิดอะไร เติมศูนย์หรือเป็น `failed` | ส่วน `validation` ใน YAML + ผล test_parser ของบรรทัด sshd |
| 8 | (ขั้น 3 ไม่บังคับ) draft parser ที่ร่าง เมื่อ test กับ auth.log ทั้ง 44 บรรทัด ผ่านกี่บรรทัด และ `list_drafts` เพิ่มจากเท่าไรเป็นเท่าไร | ผล `log_skill_test_parser` ทั้งไฟล์ + `log_skill_list_drafts` ก่อน/หลัง |

## prompt ที่ผู้เรียนพิมพ์

ขั้นที่ 1 (ไม่มี parser):
```
log บรรทัดนี้ใช้ parser ไหนใน skill server
Mar  1 02:10:00 server sshd[2824]: Failed password for invalid user admin from 198.51.100.1 port 40000 ssh2
```

ขั้นที่ 2 (มี parser):
```
อ่าน 3 บรรทัดแรกของ /student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
แล้วหาว่าใช้ parser ไหน ทดสอบ parser กับบรรทัดแรกและบรรทัด sshd ข้างบนพร้อมกัน
```

ขั้นที่ 3 (ท้าทาย ไม่บังคับ):
```
ร่าง parser skill ใหม่ชื่อ parse-linux-sshd-auth สำหรับบรรทัด sshd แบบนี้ เป็น draft
```

## ลำดับ tool ที่ควรเห็น

1. `log_skill_resolve` (sample = บรรทัด sshd) → อ่านค่า `selected`, `candidates`, `unknown_format`
2. `hdfs_read_lines` (path virtual, limit 3)
3. `log_skill_resolve` (sample = บรรทัด Suricata) → selected parser
4. `log_skill_test_parser` (skill, parser_id, samples = 2 บรรทัด)
5. (ขั้น 3) `log_skill_get` ของ parser ที่คล้ายกัน เช่น parse-huawei-security-logs เพื่อดูรูปแบบ YAML → `log_skill_save_draft`

## บันทึกคำตอบ

กรอกให้ครบทุกข้อตามเลขในตาราง "สิ่งที่ต้องค้นให้ได้" ค่าทุกค่าต้องชี้กลับไปที่ tool และฟิลด์ที่อ่านมา

| # | คำตอบ | tool → ฟิลด์/บรรทัดที่อ่านค่ามา |
| --- | --- | --- |
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |

## จุดที่คนต้องทำ

- ยืนยันความหมายของฟิลด์ เช่น `source_ip` ของ IDS คือฝั่งที่เริ่ม connection ไม่ใช่ฝั่งที่ถูกโจมตีเสมอไป
- ตรวจ % บรรทัดที่ parse ได้เทียบ ground truth (lab 2 จะให้ตัวเลข total/parsed/failed)
- รีวิวและ promote draft ผ่าน Git — Claude ทำแทนไม่ได้

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า "ไม่มี parser" โดยไม่เรียก resolve
- เลือก parser ที่ได้ score ต่ำ "เพราะก็ยังมีคะแนน" → ให้ดูฟิลด์ `parse_success` ของ candidate นั้นก่อน
- ในขั้น 3 เขียน regex จากความจำโดยไม่ทดสอบกับ 44 บรรทัดจริง → บังคับให้ test_parser กับ sample ทั้งไฟล์ (≤ 100 บรรทัด)
