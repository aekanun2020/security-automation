# Lab 1 — parser: log บรรทัดนี้ใช้ parser ไหน (G1)

**หัวข้อ** M5.2 (parse, normalize), M5.1 (อ่าน contract) · **เวลา** 30 นาที · **ข้อมูล** `module5/02-log-analysis-automation/samples/auth.log` (44 บรรทัด) และ `coherent-pcap-suricata-alerts-340.jsonl` ใน HDFS

## โจทย์

SIEM ไม่มี parser สำหรับทุกแหล่ง (gap G1) ผู้เรียนต้องให้ Claude หาว่า log ที่ได้มามี parser รองรับหรือไม่ ถ้ามี ทดสอบให้เห็นฟิลด์ที่ normalize แล้ว ถ้าไม่มี ร่าง parser ใหม่เป็น draft

## สิ่งที่ต้องค้นให้ได้

คำถามข้างล่างคือสิ่งที่ analyst จะถามกันเมื่อเจอเรื่องนี้หน้า SIEM ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร คอลัมน์ขวาบอกว่าคำตอบต้องมาจากผลของ tool ใด (ระบุชื่อ tool และฟิลด์ที่อ่านค่ามา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ ข้อที่เป็นการตัดสินใจไม่มีคำตอบตายตัวแต่ต้องอ้างตัวเลขที่ค้นได้ คำตอบอยู่ในส่วนเฉลยด้านล่าง

| # | คำถามที่คุยกันใน SOC | ค้นจากอะไร |
| --- | --- | --- |
| 1 | log บรรทัดนี้ (sshd) SIEM ของเรา parse ได้ไหม และจะรู้ได้อย่างไรว่า "ไม่มี parser" ไม่ใช่ "parse ผิด" | `log_skill_resolve` กับบรรทัด sshd: `selected`, `candidates`, `unknown_format` |
| 2 | log ของ Suricata เข้าได้ แต่แน่ใจแค่ไหนว่าเลือก parser ถูกตัว | ตาราง candidates จาก `log_skill_resolve`: score, confidence, `parse_success` |
| 3 | parser ตัวอื่นที่ได้คะแนนบ้าง ทำไมไม่เอา ถ้าเอาจะเกิดอะไร | `parse_success` ของ candidate ที่ score ต่ำ |
| 4 | หลัง parse แล้ว เราเห็นอะไรที่ก่อน parse ไม่เห็น ใครคุยกับใคร กี่โมง rule อะไรยิง รุนแรงแค่ไหน | ผล `log_skill_test_parser`: `event_time`, `source_ip`, `destination_ip`, `destination_port`, `signature`, `severity` และฟิลด์ดิบที่ `event_time` แปลงมา |
| 5 | ฟิลด์ที่ vendor มีแต่ schema กลางของเราไม่มี (เช่น alert_id) หายไปไหม ถ้าต้องใช้ทีหลังจะเอาจากไหน | `vendor_fields` ใน record ที่ parse แล้ว |
| 6 | ถ้า log บรรทัดหนึ่งขาดฟิลด์สำคัญ SIEM ควรเดาค่าให้ หรือทิ้งบรรทัดนั้นแล้วบอกเรา ระบบนี้ทำแบบไหน | ส่วน `validation.required_output` ใน YAML ของ parser + ผล test_parser ของบรรทัด sshd |
| 7 | ถ้าจะเพิ่ม parser สำหรับ sshd เอง ใครเป็นคนอนุมัติ และต้องทดสอบกับอะไรก่อนใช้จริง | (ขั้น 3 ไม่บังคับ) `log_skill_save_draft` + `log_skill_test_parser` กับ auth.log ทั้ง 44 บรรทัด + `log_skill_list_drafts` |

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

1. `log_skill_resolve` (sample = บรรทัด sshd) → `unknown_format: true`
2. `hdfs_read_lines` (path virtual, limit 3)
3. `log_skill_resolve` (sample = บรรทัด Suricata) → selected parser
4. `log_skill_test_parser` (skill, parser_id, samples = 2 บรรทัด)
5. (ขั้น 3) `log_skill_get` ของ parser ที่คล้ายกัน เช่น parse-huawei-security-logs เพื่อดูรูปแบบ YAML → `log_skill_save_draft`

## เฉลย (รันจริง 2026-11-02)

**ขั้น 1** `resolve` คืน `{"selected": null, "candidates": [], "unknown_format": true}` — ไม่มี parser ใดจับ syslog ของ sshd

**ขั้น 2** `resolve` กับบรรทัด Suricata:

| parser | score | confidence | parse_success | เหตุผล |
| --- | --- | --- | --- | --- |
| suricata-eve-alert-json-v1 | 100 | 1.0 | true | 6 fingerprint ตรง + parser รับ sample |
| netflow-v5-* (4 ตัว) | 30 | 0.3 | false | 3 fingerprint ตรง (ฟิลด์ ip/port ซ้ำกัน) |

`test_parser` 2 sample: passed 1, failed 1

- บรรทัด Suricata → `parse_status: parsed`, ได้ `event_time 2026-08-24T00:00:00+00:00` (แปลงจาก ts epoch), `source_ip 10.70.0.66 → destination_ip 10.70.0.53:53`, `signature "LAB13 Coherent C2 DNS"`, `severity 1`, vendor_fields เก็บ `alert_id`, `pcap_count`
- บรรทัด sshd → `ok: false, error: "required content fingerprint did not match"`

**สิ่งที่ควรชี้ให้ผู้เรียนดูใน contract** (จาก `log_skill_get parse-suricata-eve-alerts`)

- `detection.required_tokens` 6 ตัว คือ fingerprint ที่ resolve ใช้
- `mapping` 16 ฟิลด์ ประเภท ip/integer/long/lowercase/string
- `validation.required_output` 8 ฟิลด์ ถ้าขาดตัวใด record จะเป็น `failed` ไม่ใช่เติมศูนย์
- ฟิลด์ที่ไม่อยู่ใน canonical schema ถูกเก็บใน `vendor_fields` ไม่ทิ้ง

**ขั้น 3** ยังไม่มีเฉลย (ไม่ได้รัน) ผลที่คาด: `save_draft` คืน draft และ `list_drafts` เพิ่มจาก 0 เป็น 1 ผู้สอนต้องรีวิว YAML ก่อน promote

## จุดที่คนต้องทำ

- ยืนยันความหมายของฟิลด์ เช่น `source_ip` ของ IDS คือฝั่งที่เริ่ม connection ไม่ใช่ฝั่งที่ถูกโจมตีเสมอไป
- ตรวจ % บรรทัดที่ parse ได้เทียบ ground truth (lab 2 จะให้ตัวเลข 340/340)
- รีวิวและ promote draft ผ่าน Git — Claude ทำแทนไม่ได้

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า "ไม่มี parser" โดยไม่เรียก resolve
- เลือก netflow parser เพราะ score 30 "ก็ยังมีคะแนน" → ชี้ว่า parse_success เป็น false
- ในขั้น 3 เขียน regex จากความจำโดยไม่ทดสอบกับ 44 บรรทัดจริง → บังคับให้ test_parser กับ sample ทั้งไฟล์ (≤ 100 บรรทัด)
