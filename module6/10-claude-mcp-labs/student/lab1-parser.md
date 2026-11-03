# Lab 1 — parser: log บรรทัดนี้ใช้ parser ไหน (G1)

**หัวข้อ** M5.2 (parse, normalize), M5.1 (อ่าน contract) · **เวลา** 30 นาที · **ข้อมูล** `module5/02-log-analysis-automation/samples/auth.log` (44 บรรทัด) และ `coherent-pcap-suricata-alerts-340.jsonl` ใน HDFS

## สถานการณ์

00:00 alert ตัวแรกเข้ามา เป็นบรรทัด JSON จาก Suricata น้องยังไม่รู้ว่ามันคือเครื่องไหนคุยกับใคร เพราะยังเป็นข้อความดิบที่ SIEM ยังไม่ได้แปลง คำถามที่พา lab นี้คือ SIEM เรา parse บรรทัดนี้ออกไหม parse แล้วเห็นอะไรเพิ่มจากตอนเป็นข้อความดิบ และถ้าวันหนึ่ง log มาจากเครื่องที่ไม่มี parser (เช่น sshd ของ Linux) มันจะหายไปจาก SIEM เงียบ ๆ หรือเปล่า

## โจทย์

SIEM ไม่มี parser สำหรับทุกแหล่ง (gap G1) ผู้เรียนต้องให้ Claude หาว่า log ที่ได้มามี parser รองรับหรือไม่ ถ้ามี ทดสอบให้เห็นฟิลด์ที่ normalize แล้ว ถ้าไม่มี ร่าง parser ใหม่เป็น draft

## prompt ที่ผู้เรียนพิมพ์

ขั้นที่ 1 (alert ตัวแรกของคืนนั้น มี parser):
```
อ่าน 3 บรรทัดแรกของ /student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
แล้วหาว่าใช้ parser ไหนใน skill server
```

ขั้นที่ 2 (log ที่ SIEM ไม่รู้จัก ไม่มี parser):
```
แล้ว log บรรทัดนี้ล่ะ ใช้ parser ไหน
Mar  1 02:10:00 server sshd[2824]: Failed password for invalid user admin from 198.51.100.1 port 40000 ssh2
ทดสอบ parser ของ Suricata กับบรรทัดแรกของไฟล์เมื่อกี้และบรรทัด sshd นี้พร้อมกัน
```

ขั้นที่ 3 (ท้าทาย ไม่บังคับ):
```
ร่าง parser skill ใหม่ชื่อ parse-linux-sshd-auth สำหรับบรรทัด sshd แบบนี้ เป็น draft
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง บันทึกในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | log ของ Suricata เข้าได้ แต่แน่ใจแค่ไหนว่าเลือก parser ถูกตัว | ตาราง candidates จาก `log_skill_resolve`: score, confidence, `parse_success` | ตรวจ |
| 2 | parser ตัวอื่นที่ได้คะแนนบ้าง ทำไมไม่เอา ถ้าเอาจะเกิดอะไร | `parse_success` ของ candidate ที่ score ต่ำ | ตรวจ |
| 3 | หลัง parse แล้ว เราเห็นอะไรที่ก่อน parse ไม่เห็น ใครคุยกับใคร กี่โมง rule อะไรยิง รุนแรงแค่ไหน | ผล `log_skill_test_parser`: `event_time`, `source_ip`, `destination_ip`, `destination_port`, `signature`, `severity` และฟิลด์ดิบ `ts` ที่ `event_time` แปลงมา | ตรวจ |
| 4 | ฟิลด์ที่ vendor มีแต่ schema กลางของเราไม่มี (เช่น alert_id) หายไปไหม ถ้าต้องใช้ทีหลังจะเอาจากไหน | `vendor_fields` ใน record ที่ parse แล้ว | ตรวจ |
| 5 | log บรรทัดนี้ (sshd) SIEM ของเรา parse ได้ไหม และจะรู้ได้อย่างไรว่า "ไม่มี parser" ไม่ใช่ "parse ผิด" | `log_skill_resolve` กับบรรทัด sshd: `selected`, `candidates`, `unknown_format` | ตรวจ |
| 6 | ถ้า log บรรทัดหนึ่งขาดฟิลด์สำคัญ SIEM ควรเดาค่าให้ หรือทิ้งบรรทัดนั้นแล้วบอกเรา ระบบนี้ทำแบบไหน | ส่วน `validation.required_output` ใน YAML ของ parser + ผล test_parser ของบรรทัด sshd | ตัดสิน |
| 7 | ถ้าจะเพิ่ม parser สำหรับ sshd เอง ใครเป็นคนอนุมัติ ต้องทดสอบกับอะไรก่อนใช้จริง และเอาไปใช้กับ workflow ที่มีได้เลยไหม | (ขั้น 3 ไม่บังคับ) `log_skill_save_draft` + `log_skill_list_drafts` + `log_skill_get_draft` อ่าน YAML; `log_skill_test_parser` รับเฉพาะ skill ที่ publish แล้ว draft จึงต้องทดสอบ regex นอก server กับ auth.log ทั้ง 44 บรรทัด; ข้อจำกัดเทียบ template ของ `analyze-system-logs-with-spark` | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. `hdfs_read_lines` (path virtual, limit 3)
2. `log_skill_resolve` (sample = บรรทัด Suricata) → selected parser
3. `log_skill_resolve` (sample = บรรทัด sshd) → อ่านค่า `selected`, `candidates`, `unknown_format`
4. `log_skill_test_parser` (skill, parser_id, samples = 2 บรรทัด) → passed 1 failed 1
5. (ขั้น 3) `log_skill_get` ของ parser ที่คล้ายกัน เช่น parse-huawei-security-logs เพื่อดูรูปแบบ YAML → `log_skill_save_draft` → `log_skill_list_drafts` (`log_skill_test_parser` กับ draft จะ error จึงต้องทดสอบ regex ด้วย Python บนเครื่อง)

## บันทึกคำตอบ

กรอกทีละข้อตามเลขในตาราง "คำถามที่ถาม Claude ต่อ" คอลัมน์ 2 คือสิ่งที่ Claude ตอบ (ย่อได้ แต่ตัวเลขต้องตรง) คอลัมน์ 3 คือ tool และฟิลด์ที่ Claude อ้าง ถ้า Claude ไม่อ้าง ให้สั่งถามใหม่ก่อนกรอก คอลัมน์ 4: ข้อประเภท ตรวจ ให้เขียนว่าเทียบกับ output ดิบแล้วตรงไหม (อย่างน้อย 1 ข้อต่อ lab ต้องเทียบจริง) ข้อประเภท ตัดสิน ให้เขียนคำตัดสินของตัวเองและเหตุผล

| # | Claude ตอบว่า | อ้าง tool → ฟิลด์ | ตรวจแล้วตรงไหม / ตัดสินว่าอย่างไร |
| --- | --- | --- | --- |
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |
| 6 | | | |
| 7 | | | |

## จุดที่คนต้องทำ

- ยืนยันความหมายของฟิลด์ เช่น `source_ip` ของ IDS คือฝั่งที่เริ่ม connection ไม่ใช่ฝั่งที่ถูกโจมตีเสมอไป
- ตรวจ % บรรทัดที่ parse ได้เทียบ ground truth (lab 2 จะให้ตัวเลข total/parsed/failed)
- รีวิวและ promote draft ผ่าน Git — Claude ทำแทนไม่ได้ รายการที่ต้องดูใน YAML: `required_output` ครบไหม, ฟิลด์สำคัญของ use case (client_ip) ไปอยู่ที่ไหนและถึง Parquet ไหม, timestamp มีปีไหม, มี severity ให้ workflow ไหม, regex ทดสอบกับไฟล์จริงบน Spark แล้วหรือแค่ Python

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า "ไม่มี parser" โดยไม่เรียก resolve
- เลือก parser ที่ได้ score ต่ำ "เพราะก็ยังมีคะแนน" → ให้ดูฟิลด์ `parse_success` ของ candidate นั้นก่อน
- ในขั้น 3 เขียน regex จากความจำโดยไม่ทดสอบกับ 44 บรรทัดจริง → `log_skill_test_parser` ใช้กับ draft ไม่ได้ จึงต้องให้ Claude ทดสอบ regex ด้วย Python กับ auth.log ทั้งไฟล์ และแยกให้ชัดว่า "ผ่านใน Python" ไม่เท่ากับ "ผ่านบน Spark" (to_timestamp และคอลัมน์ที่ template ต้องการ)
- ในขั้น 3 บิด parser ให้ผ่าน template ที่มีอยู่ เช่น map `Failed password` เป็น `LOGIN_FAIL` หรือยัด client_ip ลงฟิลด์ traffic → ได้รายงานที่ดูสวยแต่ความหมายผิด ให้ Claude ประกาศข้อจำกัดแทน
