# ใบงานผู้เรียน M6.10 — สิ่งที่ต้องค้นให้ได้จากแต่ละ lab

ฉบับไม่มีเฉลย สำหรับแจกผู้เรียน (เฉลยอยู่ในไฟล์ lab แต่ละไฟล์ ส่วน "เฉลย") เรียงตาม[ลำดับสอนที่แนะนำ](README.md#ลำดับสอนที่แนะนำ-ครึ่งวัน)

## กติกาการตอบ

1. ตอบทุกข้อเป็นลายลักษณ์อักษร ตัวเลขทุกตัวต้องมาจาก tool ไม่ใช่จากที่ Claude สรุป
2. ทุกคำตอบระบุ **ชื่อ tool** และ **ฟิลด์หรือบรรทัด** ที่อ่านค่ามา เช่น `hdfs_query_records → sum_fields.orig_bytes`
3. ถ้า Claude ตอบโดยไม่เรียก tool ให้สั่งใหม่ และจดไว้ในช่อง "Claude ผิดตรงไหน" ท้าย lab
4. ข้อที่เป็นการตัดสินใจ (นิยาม, threshold, confirm/dismiss) ไม่มีคำตอบตายตัว แต่ต้องให้เหตุผลจากตัวเลขที่ค้นได้
5. ใช้ namespace ของตัวเอง `/m6-10/<ชื่อ>/` ทุกครั้งที่เขียน HDFS

## Lab 0 — สำรวจเครื่องมือ: MCP มีอะไรให้ Claude ใช้

ไฟล์ lab: [lab0-tools.md](lab0-tools.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | spark-hdfs server มี tool กี่ตัว แบ่งได้กี่กลุ่ม และ tool ใดอ่านไฟล์ได้ไม่เกินกี่ MB | รายชื่อ tool จาก ToolSearch จัดกลุ่มเอง + ข้อจำกัดจาก description ของ `hdfs_read_text` | |
| 2 | log-skill server มี skill กี่ตัว แยกเป็น parser กี่ตัว workflow กี่ตัว และ draft กี่ตัว | ผล `log_skill_list` และ `log_skill_list_drafts` (ไม่ใช่เดาจากชื่อ) | |
| 3 | มี tool ใดไหมที่ *รัน* โค้ดของ skill ได้ แล้ว `log_skill_read_resource` คืนอะไร | description ของ tool และ instruction ของ server | |
| 4 | virtual path กับ physical path ต่างกันอย่างไร ยกตัวอย่างค่าที่ `hdfs_mkdir` คืนมา และ path แบบไหนห้ามส่งกลับเข้า HDFS tool | instruction ของ spark-hdfs server + ผล `hdfs_mkdir` จริง 1 ครั้ง | |
| 5 | ก่อน `spark_submit_job` ต้องเรียก tool อะไรบ้างตามลำดับ และสถานะใดที่ถือว่า job สำเร็จ | instruction ของ server (save → validate → submit → status SUCCEEDED) | |
| 6 | ทำไม Claude ต้องโหลด schema (ToolSearch) ก่อน จึงเรียก tool ได้ | ข้อความ error หรือ step แรกที่เห็นในแชท | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 1 — parser: log บรรทัดนี้ใช้ parser ไหน (G1)

ไฟล์ lab: [lab1-parser.md](lab1-parser.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | บรรทัด sshd มี parser รองรับไหม `resolve` คืนค่าอะไรใน `selected`, `candidates`, `unknown_format` | JSON ที่ `log_skill_resolve` คืน (ขั้น 1) | |
| 2 | บรรทัด Suricata ได้ parser ตัวไหน score และ confidence เท่าไร | ตาราง candidates จาก `log_skill_resolve` (ขั้น 2) | |
| 3 | parser กลุ่ม netflow ได้ score 30 ทำไมจึงใช้ไม่ได้ | ฟิลด์ `parse_success` ของ candidate นั้น | |
| 4 | parser ที่เลือกใช้ fingerprint กี่ตัว, mapping กี่ฟิลด์, `required_output` กี่ฟิลด์ | YAML จาก `log_skill_get` ของ skill parser | |
| 5 | บรรทัด Suricata แรกหลัง parse ได้ `event_time`, `source_ip` → `destination_ip:port`, `signature`, `severity` เป็นค่าอะไร และ `event_time` แปลงมาจากฟิลด์ดิบใด | ผล `log_skill_test_parser` record ที่ `parse_status: parsed` | |
| 6 | ฟิลด์ที่ไม่อยู่ใน canonical schema (เช่น `alert_id`, `pcap_count`) ไปอยู่ที่ใด ถูกทิ้งไหม | โครง record ที่ parse แล้ว | |
| 7 | ถ้า record ขาดฟิลด์ใน `required_output` จะเกิดอะไร เติมศูนย์หรือเป็น `failed` | ส่วน `validation` ใน YAML + ผล test_parser ของบรรทัด sshd | |
| 8 | (ขั้น 3 ไม่บังคับ) draft parser ที่ร่าง เมื่อ test กับ auth.log ทั้ง 44 บรรทัด ผ่านกี่บรรทัด และ `list_drafts` เพิ่มจากเท่าไรเป็นเท่าไร | ผล `log_skill_test_parser` ทั้งไฟล์ + `log_skill_list_drafts` ก่อน/หลัง | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 2 — Spark report: จาก alert 340 บรรทัดเป็น ids-report-v1 (G2)

ไฟล์ lab: [lab2-spark-report.md](lab2-spark-report.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | ต้อง render ด้วย skill ชื่ออะไรจึงได้โค้ด ถ้าใส่ชื่อ workflow skill จะได้ error ว่าอะไร และ server เลือก `workflow_skill` ให้เองว่าอะไร | ผล `log_skill_render_spark_job` ทั้งรอบที่ผิดและรอบที่ถูก | |
| 2 | sha256 ของโค้ดที่ 4 จุด (render, save, validate expected, snapshot ของ job) มีค่าอะไร ตรงกันทุกจุดไหม | ค่าจาก `log_skill_render_spark_job`, `spark_save_job`, `log_skill_validate_spark_job`, `spark_job_status` | |
| 3 | argument 3 ตัวที่ส่งให้ job คืออะไร เป็น path แบบใด | argument ใน `spark_submit_job` | |
| 4 | job ใช้เวลาเท่าไร สถานะสุดท้ายและ exit_code คืออะไร | `spark_job_status` ครั้งสุดท้าย (เวลา submit → เวลาจบ) | |
| 5 | `total_records`, `parsed`, `failed` เท่าไร | report JSON ที่อ่านด้วย `hdfs_read_text` | |
| 6 | `event_time_min` → `event_time_max` ครอบคลุมช่วงใด | report JSON | |
| 7 | top_signatures 3 ตัวและจำนวนของแต่ละตัว | report JSON | |
| 8 | alert ทั้งหมดมาจาก source_ip กี่ตัว และ destination_ip 2 อันดับแรกคือใคร ที่เหลืออีกกี่ host ละกี่ alert | report JSON `top_source_ips`, `top_destination_ips` | |
| 9 | `alert_action` มีค่าอะไรบ้าง และหมายความว่า IDS ทำอะไรกับ traffic นั้น | report JSON + นิยามใน skill | |
| 10 | sha256 ของ report มี 2 ค่า (ไฟล์ใน HDFS กับที่ `validate_report` คืน) ทำไมต่างกัน | `hdfs_sha256` เทียบ `report_sha256` ของ `log_skill_validate_report` | |
| 11 | ในโค้ด PySpark ที่ render บรรทัดใดทำให้ record กลายเป็น `failed` และทำไมเขียน output ด้วย `errorifexists` | อ่านโค้ดจาก `spark_read_job` ระบุเลขบรรทัด | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 3 — correlate: alert ↔ Zeek conn ↔ PCAP (G2, วัตถุประสงค์ข้อ 2–3)

ไฟล์ lab: [lab3-correlate.md](lab3-correlate.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | alert 340 รายการมาจาก source_ip กี่ตัว คือใคร | `hdfs_query_records` group_by source_ip | |
| 2 | signature 3 ตัว แต่ละตัวมี count เท่าไร ปลายทางคือใคร พอร์ตและ protocol อะไร ช่วงเวลาเริ่ม–จบ | `hdfs_query_records` group_by [signature, source_ip] + time_field | |
| 3 | mean interval และ stddev ของแต่ละ signature เป็นเท่าไร stddev 0 บอกอะไร | สถิติเวลาจาก query เดียวกัน + เทียบ CV ของตัวอย่าง 2.6 | |
| 4 | correlate ได้ `matched_pairs`, `unmatched_left`, `unmatched_right` เท่าไร unmatched_right คือ traffic อะไร | ผล `hdfs_correlate_records` | |
| 5 | East-West มี 100 alert แต่จับคู่ได้กี่ conn ทำไมจำนวนไม่เท่ากัน | `matched_cohorts` + นิยาม 5-tuple | |
| 6 | ก่อน correlate ต้องรู้ชื่อฟิลด์จริงของ Zeek conn ว่าอะไร (ip/port/proto) ได้มาจากไหน | `hdfs_read_lines` 2 บรรทัดแรก | |
| 7 | Outbound Transfer ส่งข้อมูลไปที่ใด byte ออกรวมเท่าไร byte เข้ารวมเท่าไร อัตราส่วนบอกรูปแบบอะไร | `hdfs_query_records` filters + sum_fields orig_bytes/resp_bytes | |
| 8 | ใน PCAP มีกี่ packet ที่ตรง filter ทำไมไม่เท่ากับจำนวน conn (120) frame แรกเลขอะไร เวลาใด | `hdfs_pcap_packets` display_filter | |
| 9 | `interpretation` ที่ tool คืนมาว่าอะไร ทำไม alert กับ conn จึงไม่ใช่หลักฐานอิสระสองชิ้น | ฟิลด์ interpretation ของ correlate + ที่มาของไฟล์ทั้ง 2 | |
| 10 | 3 ระยะนี้เป็นเหตุการณ์เดียวกันหรือไม่ ใช้อะไรตัดสิน และ tool ตัดสินให้หรือเปล่า | asset เดียวกัน + ลำดับเวลา + ข้อความ `no incident verdict` | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 3c — baseline: หา host ที่ผิดจากเครื่องอื่นโดยไม่ใช้ signature (correlation แบบ 4)

ไฟล์ lab: [lab3c-baseline.md](lab3c-baseline.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | ทั้งไฟล์มี conn กี่รายการ ช่วงเวลาใด host ต้นทางกี่ตัว ปลายทางกี่ตัว พอร์ตอะไรบ้าง | `hdfs_query_records` ไม่มี group_by + distinct_fields + time_field | |
| 2 | แยกตามพอร์ตปลายทาง: พอร์ตใดมี host ต้นทาง 200 ตัว พอร์ตที่เหลือมาจากกี่ host และ byte ออกของพอร์ต 443 เทียบพอร์ต 80 เป็นอย่างไร | `hdfs_query_records` group_by id.resp_p | |
| 3 | query group_by id.orig_h ได้มากี่กลุ่มจากทั้งหมดกี่กลุ่ม `groups_truncated` เป็นอะไร host ผิดปกติอยู่ใน 100 กลุ่มนั้นไหม ทำไม | ผล query + ข้อจำกัด max_groups + ลำดับการเรียง | |
| 4 | แก้ข้อจำกัดนั้นอย่างไรจึงได้ baseline ครบ 200 host | ชุด `cidr_filters` ที่ใช้ | |
| 5 | เครื่องปกติ 1 เครื่องมี connection, byte ออก, byte เข้า, ปลายทาง distinct, พอร์ต distinct เท่าไร การกระจายกว้างแค่ไหน | ตาราง baseline จาก 5 query | |
| 6 | host 10.70.0.66 มี connection, byte ออก, ปลายทาง distinct, พอร์ต distinct เท่าไร | `hdfs_query_records` filters id.orig_h | |
| 7 | เทียบกับ baseline ผิดกี่เท่าในแต่ละ metric metric ใดที่ host นี้ *ต่ำกว่า* baseline และ rule แบบ threshold จะจับได้ไหม | ตารางเปรียบเทียบที่ผู้เรียนทำเอง | |
| 8 | ถ้าเรียง host ตามจำนวน connection มาก→น้อย 10.70.0.66 อยู่อันดับที่เท่าไร เหตุใดขั้น 3 จึงไม่เจอ | ตัวเลข connection ของ host เทียบ baseline | |
| 9 | เจอ host เดียวกับ lab 3 ไหม ตัวเลข byte ตรงกันไหม แล้วเป็น "หลักฐานอิสระ" หรือ "วิธีอิสระ" | เทียบกับผล lab 3 + ที่มาของไฟล์ (PCAP เดียวกัน) | |
| 10 | baseline นี้บอกได้ว่า host นี้ *ร้าย* ไหม tool คืน interpretation ว่าอะไร ขั้นต่อไปควรทำอะไร | ฟิลด์ interpretation + lab 4 / lab 3 ขั้น PCAP | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 3b — investigation handoff: จาก correlation report เป็นเอกสารส่งต่อ (M6.1, วัตถุประสงค์ข้อ 2)

ไฟล์ lab: [lab3b-handoff.md](lab3b-handoff.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | input events.log ระบุ candidate อะไร: asset_id, ip, ช่วงเวลา sequence, ช่วงห่าง c2→exfil และ exfil→lateral กี่วินาที, supporting roles กี่รายการ | `hdfs_read_text` events.log ฟิลด์ `investigation_candidates[0]` | |
| 2 | contract handoff v2 ผูกค่าคงที่อะไรไว้บ้าง (canonical_sha256, asset, priority, disposition) แล้วใช้กับ incident อื่นได้ไหม | `log_skill_read_resource` references/security-investigation-handoff-contract-v2.json | |
| 3 | render ด้วย skill ชื่ออะไร parser อะไร ได้ code_sha256 เท่าไร และ policy validate บังคับประโยคใดต้องมี/ห้ามมี | `log_skill_render_spark_job` + `log_skill_validate_spark_job` | |
| 4 | sha256 ของ report ที่ได้ใหม่กับ report รอบ 2026-08-20 ตรงกันไหม ขนาดไฟล์เท่าไร นี่พิสูจน์อะไร | `hdfs_sha256` ทั้ง 2 ไฟล์ | |
| 5 | case_id, priority, disposition, verdict ของ case คืออะไร verdict นี้แปลว่า "ยืนยันถูกโจมตี" หรือไม่ | report JSON | |
| 6 | timeline มีกี่รายการ แต่ละรายการเกิดเวลาใด มาจาก contract ต้นทางใด | report JSON `timeline` | |
| 7 | corroboration มีกี่รายการ รายการใด `simulation: true` และนับเป็นหลักฐานอิสระได้ไหม | report JSON `corroboration` | |
| 8 | caveats 4 ข้อคืออะไร | report JSON `caveats` | |
| 9 | `raw_view_records` 300,460 เป็น "จำนวน event" ได้ไหม report บอกไว้ว่าอย่างไร | report JSON `parent_evidence` | |
| 10 | source_sha256 ของหลักฐานใน timeline ตรงกับไฟล์ input ของรอบ correlation ทั้ง 5 ไฟล์ไหม | `hdfs_sha256` ของไฟล์ใน `/generic-security/coherent-pcap-correlation-20260820041327/input/` เทียบค่าใน report | |
| 11 | analyst ต้องทำอะไร 3 ข้อ และข้อใดที่ MCP ทำแทนไม่ได้ | report JSON `analyst_actions` | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 2b — dedupe + score: ให้ Claude เขียน PySpark เอง แล้วคนตรวจโค้ด (G2)

ไฟล์ lab: [lab2b-dedupe-score.md](lab2b-dedupe-score.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | ก่อน submit ทำนายจำนวน offense ต่อ signature และรวมทั้งหมด พร้อมวิธีคิดจากช่วงห่างของ alert และขนาด window | ตัวเลขจากสถิติ lab 3 (interval, จำนวน, เวลาเริ่ม) + การหารด้วย 600 s | |
| 2 | โค้ดที่ Claude เขียนใช้ window แบบ fixed หรือ sliding ต่างจากตัวอย่าง 7.2 อย่างไร และประกาศ deviation ไว้ตรงไหน | บรรทัดโค้ดจาก `spark_read_job` + docstring | |
| 3 | fingerprint สร้างจากฟิลด์ใดบ้าง ตัดกี่ตัวอักษร | บรรทัดโค้ด | |
| 4 | ผลจริง: `alerts_in`, `offenses_out`, `reduction_pct`, และ `sum_event_count` เท่ากับ alerts_in ไหม | report JSON + `hdfs_query_records` บน offenses (sum event_count) เป็นการตรวจอิสระ | |
| 5 | จำนวน offense จริงต่อ signature ตรงกับที่ทำนายไหม ถ้าไม่ตรง ต่างตรงไหน | `by_signature` ใน report เทียบคำทำนายข้อ 1 | |
| 6 | `by_route` แยกเป็นอะไรบ้าง ทำไม auto-close และ queue จึงเป็น 0 | report JSON + สูตร score | |
| 7 | `raw_score` และ `magnitude` มีค่า min–max เท่าไร ทำไม magnitude เท่ากันทุกรายการ แสดงวิธีคำนวณจาก base(severity) + 8×asset_crit | report JSON + สูตรในโค้ด | |
| 8 | เสนอวิธีแก้สูตรอย่างน้อย 1 วิธีที่ทำให้ beacon 10 ครั้งกับ SSH 4 ครั้งได้ score ต่างกัน | ข้อเสนอของผู้เรียน (ไม่มีคำตอบตายตัว) | |
| 9 | "ลด alert ได้ 88%" บอกได้ไหมว่า TP หลุดกี่ % ทำไม | ชุดข้อมูลมี label หรือไม่ | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 4 — enrich: IP ใน alert ติด threat feed ไหม (G3) — ร่าง ยังไม่ได้รัน

ไฟล์ lab: [lab4-enrich.md](lab4-enrich.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | feed ที่ดึงมามี URL, วันที่ดาวน์โหลด, sha256, จำนวน record, license อะไร และ Claude ขออนุญาตก่อนดาวน์โหลดไหม | บันทึก `feeds/hashes.json` + `hdfs_sha256` หลังเขียนขึ้น HDFS ตรงกับค่าที่คำนวณในเครื่อง | |
| 2 | record ของ Feodo มีฟิลด์อะไรบ้าง ฟิลด์ใดใช้ match กับ IP ใน alert | `hdfs_read_lines` ไฟล์ feed ใน HDFS | |
| 3 | 203.0.113.66 และ 10.70.0.66 อยู่ใน Feodo ไหม `matched_records` เท่าไร | `hdfs_query_records` filters/cidr_filters บน feed | |
| 4 | ทำไม IP ทั้งสองจึง *ไม่ควร* อยู่ใน feed ใดเลย (ช่วง IP เป็นอะไร) | RFC 5737 TEST-NET-3 และ RFC 1918 | |
| 5 | "ไม่เจอใน feed" แปลว่าปลอดภัย หรือแปลว่าไม่รู้ และต้องรายงานผล 0 ไหม | คำอธิบายของผู้เรียน | |
| 6 | EPSS ของ CVE-2024-3400 มีค่า `epss` และ `percentile` เท่าไร percentile หมายถึงอะไร | JSON จาก api.first.org | |
| 7 | ขั้นใดของ lab นี้อยู่นอก audit trail ของ MCP และผู้เรียนชดเชยด้วยอะไร | ลำดับ tool (WebFetch/curl อยู่ฝั่ง Claude Desktop) + hashes.json | |
| 8 | `hdfs_import_file` ใช้กับไฟล์บนเครื่องผู้เรียนได้ไหม ทำไม | description ของ tool | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

## Lab 5 — รายงาน: จาก ids-report-v1 เป็น dashboard และ PDF (G4) — ร่าง

ไฟล์ lab: [lab5-report.md](lab5-report.md)

| # | คำถาม | หลักฐานที่ต้องแสดง | คำตอบของฉัน |
| --- | --- | --- | --- |
| 1 | report ที่อ่านคือไฟล์ใด sha256 ของไฟล์เท่าไร และ `validate_report` ยังผ่านไหม | `hdfs_list` → `hdfs_read_text` → `hdfs_sha256` → `log_skill_validate_report` | |
| 2 | KPI 3 ตัว (total, parsed, failed) เท่าไร และตรงกับ lab 2 ไหม | report JSON | |
| 3 | signature 3 ตัวและจำนวน; destination 2 อันดับแรกและอีกกี่ host ที่เหลือ — chart ซ่อน 25 host นี้ไหม | report JSON + chart ใน dashboard | |
| 4 | sha256 ที่พิมพ์ท้ายหน้าใช้ค่าไหน (ไฟล์ หรือ validate_report) ทำไมสองค่าต่างกัน | `hdfs_sha256` เทียบ `report_sha256` | |
| 5 | job_id ที่พิมพ์ท้ายหน้าคืออะไร ตรงกับ job ที่ผลิต report นี้ไหม | `spark_list_jobs` หรือบันทึก lab 2 | |
| 6 | ตัวเลขทุกตัวใน PDF ชี้กลับไป field ใดใน JSON ได้ไหม มีตัวเลขใดที่ไม่มีใน report (เช่น % ของ traffic) ปนเข้ามาหรือไม่ | ตารางจับคู่ ตัวเลขใน PDF ↔ field ใน JSON | |
| 7 | narrative ใช้คำว่า "rule ตรง" หรือ "ถูกโจมตี" ข้อความใดเกินข้อมูล | อ่าน narrative ทีละประโยค | |
| 8 | รายงานนี้ให้ MTTD/MTTR ได้ไหม ทำไม และบอกผู้บริหารอย่างไร | ชุดข้อมูลมี ticket/นาฬิกาตอบสนองหรือไม่ | |

**Claude ผิดตรงไหนใน lab นี้ (จดเอง):**

