# Lab 1 — parser: log บรรทัดนี้ใช้ parser ไหน (G1)

**หัวข้อ** M5.2 (parse, normalize), M5.1 (อ่าน contract) · **เวลา** 30 นาที · **ข้อมูล** `module5/02-log-analysis-automation/samples/auth.log` (44 บรรทัด) และ `coherent-pcap-suricata-alerts-340.jsonl` ใน HDFS

## โจทย์

SIEM ไม่มี parser สำหรับทุกแหล่ง (gap G1) ผู้เรียนต้องให้ Claude หาว่า log ที่ได้มามี parser รองรับหรือไม่ ถ้ามี ทดสอบให้เห็นฟิลด์ที่ normalize แล้ว ถ้าไม่มี ร่าง parser ใหม่เป็น draft

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

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | log บรรทัดนี้ (sshd) SIEM ของเรา parse ได้ไหม และจะรู้ได้อย่างไรว่า "ไม่มี parser" ไม่ใช่ "parse ผิด" | `log_skill_resolve` กับบรรทัด sshd: `selected`, `candidates`, `unknown_format` | ตรวจ |
| 2 | log ของ Suricata เข้าได้ แต่แน่ใจแค่ไหนว่าเลือก parser ถูกตัว | ตาราง candidates จาก `log_skill_resolve`: score, confidence, `parse_success` | ตรวจ |
| 3 | parser ตัวอื่นที่ได้คะแนนบ้าง ทำไมไม่เอา ถ้าเอาจะเกิดอะไร | `parse_success` ของ candidate ที่ score ต่ำ | ตรวจ |
| 4 | หลัง parse แล้ว เราเห็นอะไรที่ก่อน parse ไม่เห็น ใครคุยกับใคร กี่โมง rule อะไรยิง รุนแรงแค่ไหน | ผล `log_skill_test_parser`: `event_time`, `source_ip`, `destination_ip`, `destination_port`, `signature`, `severity` และฟิลด์ดิบ `ts` ที่ `event_time` แปลงมา | ตรวจ |
| 5 | ฟิลด์ที่ vendor มีแต่ schema กลางของเราไม่มี (เช่น alert_id) หายไปไหม ถ้าต้องใช้ทีหลังจะเอาจากไหน | `vendor_fields` ใน record ที่ parse แล้ว | ตรวจ |
| 6 | ถ้า log บรรทัดหนึ่งขาดฟิลด์สำคัญ SIEM ควรเดาค่าให้ หรือทิ้งบรรทัดนั้นแล้วบอกเรา ระบบนี้ทำแบบไหน | ส่วน `validation.required_output` ใน YAML ของ parser + ผล test_parser ของบรรทัด sshd | ตัดสิน |
| 7 | ถ้าจะเพิ่ม parser สำหรับ sshd เอง ใครเป็นคนอนุมัติ ต้องทดสอบกับอะไรก่อนใช้จริง และเอาไปใช้กับ workflow ที่มีได้เลยไหม | (ขั้น 3 ไม่บังคับ) `log_skill_save_draft` + `log_skill_list_drafts` + `log_skill_get_draft` อ่าน YAML; `log_skill_test_parser` รับเฉพาะ skill ที่ publish แล้ว draft จึงต้องทดสอบ regex นอก server กับ auth.log ทั้ง 44 บรรทัด; ข้อจำกัดเทียบ template ของ `analyze-system-logs-with-spark` | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. `log_skill_resolve` (sample = บรรทัด sshd) → `unknown_format: true`
2. `hdfs_read_lines` (path virtual, limit 3)
3. `log_skill_resolve` (sample = บรรทัด Suricata) → selected parser
4. `log_skill_test_parser` (skill, parser_id, samples = 2 บรรทัด)
5. (ขั้น 3) `log_skill_get` ของ parser ที่คล้ายกัน เช่น parse-huawei-security-logs เพื่อดูรูปแบบ YAML → `log_skill_save_draft` → `log_skill_list_drafts` (`log_skill_test_parser` กับ draft จะ error จึงต้องทดสอบ regex ด้วย Python บนเครื่อง)

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

**ขั้น 3** (รันจริง 2026-11-03 โดยผู้เรียนทดลอง) `save_draft` สำเร็จ `list_drafts` เพิ่มจาก 0 เป็น 1: skill `parse-linux-sshd-auth`, parser id `linux-sshd-auth`, version 0.1.0, status draft, sha256 ของ draft `4055c8d1…`

สิ่งที่ Claude ทำ: อ่าน `parse-huawei-security-logs` เป็นแบบ (regex_syslog ตัวเดียวที่ approved) แล้วเขียน YAML ที่ `format: regex_syslog`, `log_type: system`, detection token `sshd[`, จับ Failed password / Accepted password / Accepted publickey, IPv4 และ IPv6, `<PRI>` มีหรือไม่มีก็ได้, `required_output` 3 ฟิลด์ (event_time, device_name, message) และเก็บ user, client_ip, client_port ไว้ใน `vendor_fields` ไม่ใช่ฟิลด์ traffic เพราะ schema ของ system event ห้าม

ข้อค้นพบที่เฉลยเดิมคาดผิด:

1. **`log_skill_test_parser` ใช้กับ draft ไม่ได้** คืน error path `/skills/parse-linux-sshd-auth/SKILL.md` (ผู้สอนลองซ้ำแล้วได้ผลเดียวกัน) tool นี้อ่านเฉพาะ skill ที่ publish แล้ว Claude จึงทดสอบ regex ด้วย Python บนเครื่อง 7 กรณีแทน (บรรทัดโจทย์, root, Accepted password, publickey + PRI + IPv6, และ 3 กรณีที่ต้องไม่ match) และประกาศเองว่ายังไม่ได้ทดสอบกับ Spark
2. **regex แบบ `(?P<name>)` ของ Python ใช้กับ Spark ได้** เพราะ template `spark_system_event_report_job.py.tmpl` แปลงเป็น `(` ก่อนส่งให้ `regexp_extract` และใช้ `groupindex` ของ Python หา index ข้อกังวลเรื่อง Java regex ที่ Claude ยกมาจึงตกไป
3. **draft นี้รันผ่าน `analyze-system-logs-with-spark` ไม่ได้** ซึ่ง Claude ระบุถูก: template เรียก `count_table("severity")` แต่ parser ไม่ map `severity` → job จะ FAILED; ตัวนับ login เทียบ `event_id` กับ `LOGIN_SUCCESS`/`LOGIN_FAIL` (ค่า Huawei) จึงนับได้ 0; template เขียน vendor_fields ลง Parquet แค่ 5 ตัว `auth_user`/`client_ip`/`client_port` จะหาย Claude เลือกไม่บิด parser ให้เข้ากับ template ("จะกลายเป็นข้อมูลปลอม") ซึ่งเป็นการตัดสินใจที่ถูก

ประเด็นที่ผู้รีวิวต้องยกก่อน promote (ยังไม่ได้แก้ draft ยังเป็น 0.1.0):

- **ไม่มีปี** `event_time` เป็น `Mon d HH:MM:SS` template parse ด้วย `MMM d HH:mm:ss` ปีจึงไม่จริง ตรงกับข้อค้นพบที่ 3 ของ smoke-test M5.2 (ปี 0001)
- **`<PRI>` ถูกจับแต่ไม่ถอด** ถ้าถอดเป็น severity = PRI mod 8 (RFC 5424 ที่ M5.2 สอน) จะได้คอลัมน์ `severity` ที่ template ต้องการโดยไม่ต้องแก้ workflow แต่บรรทัดที่ไม่มี PRI ก็ยังว่าง
- **วันเลขเดียวมีช่องว่างสองช่อง** (`Mar  1`) regex จับได้ แต่ `to_timestamp(..., "MMM d HH:mm:ss")` ของ Spark อาจคืน null ทำให้ record เป็น `failed` ทั้งที่ regex ผ่าน ต้องทดสอบกับ auth.log 44 บรรทัดจริงบน Spark ก่อนสรุป (ยังไม่ได้ทดสอบ)
- **ใช้กับ lab brute-force (ตัวอย่าง 2.1) ยังไม่ได้** เพราะ client_ip อยู่ใน vendor_fields และไม่ถึง Parquet ต้องมี workflow เวอร์ชันใหม่ที่นับ Failed password ต่อ client_ip ตามที่ Claude เสนอ
- **ยังไม่ครอบคลุม** `Invalid user … from …`, `pam_unix`, `sshd-session` (OpenSSH 9.8+), RFC3339, journald (Claude เขียนไว้ใน draft เอง)

สถานะ: draft คงไว้ ไม่ promote จนกว่าจะทดสอบบน Spark และตัดสินเรื่อง severity

## จุดที่คนต้องทำ

- ยืนยันความหมายของฟิลด์ เช่น `source_ip` ของ IDS คือฝั่งที่เริ่ม connection ไม่ใช่ฝั่งที่ถูกโจมตีเสมอไป
- ตรวจ % บรรทัดที่ parse ได้เทียบ ground truth (lab 2 จะให้ตัวเลข 340/340)
- รีวิวและ promote draft ผ่าน Git — Claude ทำแทนไม่ได้ รายการที่ต้องดูใน YAML: `required_output` ครบไหม, ฟิลด์สำคัญของ use case (client_ip) ไปอยู่ที่ไหนและถึง Parquet ไหม, timestamp มีปีไหม, มี severity ให้ workflow ไหม, regex ทดสอบกับไฟล์จริงบน Spark แล้วหรือแค่ Python

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า "ไม่มี parser" โดยไม่เรียก resolve
- เลือก netflow parser เพราะ score 30 "ก็ยังมีคะแนน" → ชี้ว่า parse_success เป็น false
- ในขั้น 3 เขียน regex จากความจำโดยไม่ทดสอบกับ 44 บรรทัดจริง → `log_skill_test_parser` ใช้กับ draft ไม่ได้ จึงต้องให้ Claude ทดสอบ regex ด้วย Python กับ auth.log ทั้งไฟล์ และแยกให้ชัดว่า "ผ่านใน Python" ไม่เท่ากับ "ผ่านบน Spark" (to_timestamp และคอลัมน์ที่ template ต้องการ)
- ในขั้น 3 บิด parser ให้ผ่าน template ที่มีอยู่ เช่น map `Failed password` เป็น `LOGIN_FAIL` หรือยัด client_ip ลงฟิลด์ traffic → ได้รายงานที่ดูสวยแต่ความหมายผิด ให้ Claude ประกาศข้อจำกัดแทน
