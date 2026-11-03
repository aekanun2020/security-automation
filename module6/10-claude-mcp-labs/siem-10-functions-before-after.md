# SIEM 10 ฟังก์ชัน — before & after ด้วย MCP ของ M6.10

ต่อจาก [Q&A Q18](../../docs/qa-2026-11-02-mcp-spark-hdfs.md) ที่สรุปว่า MCP ชุดนี้คือ "SIEM แบบ batch ที่ขาดหัวและขาดท้าย" เอกสารนี้ให้ผู้เรียนเห็นของจริงทีละฟังก์ชัน: ข้อมูล **ก่อน** เข้าขั้นนั้นหน้าตาเป็นอย่างไร และ **หลัง** ออกมาเป็นอะไร ทุกตัวอย่างมาจากชุด `incident-lab` และผลรันจริงใน lab 1–3b (ดึงจาก MCP เมื่อ 2026-11-03 และจาก `outputs/`) ส่วนที่ยังไม่ได้รันจะบอกว่าเป็นค่าที่คาด

ใช้คู่กับตารางใน Q18: คอลัมน์ "ใน QRadar" คือสิ่งที่ผู้เรียนจะเจอเมื่อย้ายไป SIEM จริง

## 1. Collection / Ingestion

**Collection คือ** การย้าย log จากที่ที่มันเกิด (sensor, เครื่องผู้ใช้) มาอยู่ในที่เก็บกลางที่เครื่องมือวิเคราะห์เข้าถึงได้ ในที่นี้คือจากไฟล์นอก HDFS มาเป็นไฟล์ใต้ `/mcp/...` เนื้อหาไฟล์ไม่เปลี่ยน เปลี่ยนแค่ที่อยู่และ metadata (owner, replication) นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Event Collector รับ syslog แบบ real-time, auto-discover log source หลัง ~25 event · **MCP:** `hdfs_import_file`, `hdfs_write_text` (batch) · **lab:** 0, 4

| | |
| --- | --- |
| **before** | ไฟล์อยู่นอก HDFS เช่น Suricata EVE บนเครื่อง sensor หรือ feed JSON ที่ Claude Desktop ดาวน์โหลดมา |
| **after** | ไฟล์อยู่ใต้ `/mcp/student/agentic-siem/incident-lab/input/` 6 ไฟล์ (ผล `hdfs_list`): pcap 60.9 MB, fortigate.log 47.5 MB, netflow 54.4 MB, zeek-conn 37.1 MB, suricata 154 KB, zeek-dns 52 KB พร้อม owner `spark`, replication 2 |

**ให้ผู้เรียนสังเกต** ไม่มี tool ไหนรับ UDP 514 ถ้าอยากได้ log ใหม่ต้องมีคนวางไฟล์ก่อน และ `hdfs_import_file` รับเฉพาะ source ฝั่ง server (lab 4 เตือนไว้) นี่คือ "หัวที่ขาด"

## 2. Parsing

**Parsing คือ** การแยก log 1 บรรทัดที่เป็น text ยาวติดกัน ออกเป็นฟิลด์ที่มีชื่อและชนิดข้อมูล (string, integer, ip) ในที่นี้คือจาก key=value 1 บรรทัด ไปเป็น JSON 24 ฟิลด์ ถ้ารูปแบบไม่ตรงกับที่ parser รู้จัก ผลคือ failed ไม่ใช่ฟิลด์ว่าง นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** DSM แยก raw เป็น field · **MCP:** `log_skill_resolve` → `log_skill_test_parser` (log-skill server) · **lab:** 1

**before** บรรทัดที่ 1 ของ `coherent-pcap-fortigate-100k.log` (key=value syslog, 1 บรรทัด)

```
date=2026-08-24 time=00:00:00 devname="FGT-LAB-SIM-01" devid="SYNTHETIC0000001" type="traffic" subtype="forward" level="notice" srcip=10.70.0.66 srcport=40000 srcintf="lan" dstip=10.70.0.53 dstport=53 dstintf="lan" proto=17 action="accept" policyname="SIM-C2-DNS-PASS" app="DNS" transip=10.70.0.66 transport=40000 sentbyte=49 rcvdbyte=65 sentpkt=1 rcvdpkt=1 eventtype="close" simulation="true" evidence_origin="pcap-derived" parentuid="C23Z1U11E2atSWbamf" zeekstate="SF"
```

**after** `log_skill_test_parser` (skill parse-fortinet-fortigate-logs, parser fortinet-fortigate-pcap-sim-7x) → `passed 1, failed 0, parse_status: parsed`

```json
{"vendor":"fortinet","product":"fortigate-pcap-sim","firmware":"7.x-compatible","log_type":"traffic",
 "event_category":"network_traffic","parser_id":"fortinet-fortigate-pcap-sim-7x","parser_version":"1.0.0",
 "device_name":"FGT-LAB-SIM-01","event_time":"2026-08-24 00:00:00",
 "source_ip":"10.70.0.66","source_port":40000,"destination_ip":"10.70.0.53","destination_port":53,
 "source_translated_ip":"10.70.0.66","source_translated_port":40000,
 "source_zone":"lan","destination_zone":"lan","event_action":"accept","application":"DNS",
 "policy_name":"SIM-C2-DNS-PASS","network_protocol":"17",
 "bytes_sent":49,"bytes_received":65,"packets_sent":1,"packets_received":1,"session_end_reason":"close",
 "raw_event":"date=2026-08-24 time=00:00:00 devname=... (เก็บต้นฉบับทั้งบรรทัด)"}
```

**ตัวอย่างที่ parse ไม่ได้** (lab 1 ขั้น 1) บรรทัด sshd `Failed password for invalid user admin from 198.51.100.1` → `resolve` คืน `unknown_format: true` และ `test_parser` คืน `ok: false, error: "required content fingerprint did not match"` ไม่มีการเติมค่าว่างให้

**ให้ผู้เรียนสังเกต** parser ไม่ทิ้งอะไร: `raw_event` เก็บทั้งบรรทัด และฟิลด์ที่ไม่อยู่ใน schema (`simulation`, `parentuid`) ไปอยู่ใน `vendor_fields` ของ parser อื่น ส่วน QRadar ก็เก็บ payload ต้นฉบับไว้เช่นกัน

## 3. Normalization

**Normalization คือ** การทำให้ event ต่างแหล่งเทียบหรือ join กันได้ มี 3 ชั้น: (1) ชื่อฟิลด์ ในที่นี้ `srcip`, `id.orig_h`, `source_ip` กลายเป็น `source_ip` ชื่อเดียว (2) ค่าในฟิลด์ ซึ่งตัวอย่างแสดงว่ายังไม่ทำ (`17` กับ `udp`, timezone ไม่สม่ำเสมอ) (3) หมวดเหตุการณ์ ในที่นี้คือ `event_category` network_traffic / network_connection / ids_alert และ `severity_summary` ที่แปลง severity 1 ของ Suricata เป็น critical ในข้อ 9 นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** QID map, normalized event (sourceIP, destinationIP, ...) · **MCP:** canonical schema ใน skill normalize-security-logs ที่ทุก parser ต้อง map เข้า · **lab:** 1, 3

**before** event เดียวกัน (connection uid `C23Z1U11E2atSWbamf` เวลา 1787529600) ถูกบันทึกโดย 3 แหล่ง ชื่อฟิลด์ต่างกันหมด

| ความหมาย | FortiGate | Zeek conn | Suricata alert |
| --- | --- | --- | --- |
| เวลา | `date=2026-08-24 time=00:00:00` | `"ts":1787529600.0` | `"ts":1787529600.0` |
| ต้นทาง | `srcip=10.70.0.66 srcport=40000` | `"id.orig_h":"10.70.0.66","id.orig_p":40000` | `"source_ip":"10.70.0.66","source_port":40000` |
| ปลายทาง | `dstip=10.70.0.53 dstport=53` | `"id.resp_h":"10.70.0.53","id.resp_p":53` | `"destination_ip":"10.70.0.53","destination_port":53` |
| protocol | `proto=17` | `"proto":"udp"` | `"network_protocol":"udp"` |
| byte ออก/เข้า | `sentbyte=49 rcvdbyte=65` | `"orig_bytes":49,"resp_bytes":65` | ไม่มี |

**after** ผล `test_parser` ของทั้ง 3 parser คืนชื่อเดียวกัน

| canonical field | FortiGate | Zeek conn | Suricata |
| --- | --- | --- | --- |
| `source_ip` / `source_port` | 10.70.0.66 / 40000 | 10.70.0.66 / 40000 | 10.70.0.66 / 40000 |
| `destination_ip` / `destination_port` | 10.70.0.53 / 53 | 10.70.0.53 / 53 | 10.70.0.53 / 53 |
| `event_time` | `2026-08-24 00:00:00` | `2026-08-24T00:00:00+00:00` | `2026-08-24T00:00:00+00:00` |
| `network_protocol` | **`"17"`** | `udp` | `udp` |
| `bytes_sent` / `bytes_received` | 49 / 65 | 49 / 65 | — |
| `event_category` | network_traffic | network_connection | ids_alert |
| `vendor_fields` | — | connection_uid, duration, orig_pkts, ... | alert_id, pcap_count |

**ให้ผู้เรียนสังเกต** normalization ยังไม่สมบูรณ์ 2 จุดและเป็นโจทย์ให้หา: (1) FortiGate ให้ `network_protocol = "17"` แต่ Zeek ให้ `udp` ถ้าเอามา group_by รวมกันจะได้ 2 กลุ่ม (2) `event_time` มี timezone ในสองแหล่ง ไม่มีในแหล่งเดียว ใน QRadar ปัญหาเดียวกันคือ QID ที่ map ไม่ครบจะไปอยู่ใน "Unknown event" และ lab 3 ที่ correlate ด้วย 5-tuple ทำได้เพราะขั้นนี้ทำให้ key ตรงกันก่อน

## 4. Enrichment

**Enrichment คือ** การเติมข้อมูลจากแหล่งภายนอก log เข้าไปใน record เพื่อให้ตัดสินได้ว่า IP หรือ asset นั้นสำคัญหรืออันตรายแค่ไหน ในที่นี้คือเอา IP ไปเทียบกับ threat feed และตารางความสำคัญของ asset ผลลัพธ์อาจเป็น "ไม่พบ" ก็ได้ นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Reference set, X-Force feed, Asset model · **MCP:** ไม่มี tool ดึง feed แต่ Claude Desktop ดึงแล้ว `hdfs_write_text` เข้าไป จากนั้น `hdfs_query_records` filter · **lab:** 4 (ร่าง ยังไม่รัน), 2b (asset criticality)

| | |
| --- | --- |
| **before** | alert บอกแค่ `destination_ip: 203.0.113.66` ไม่รู้ว่าเป็นใคร เป็น C2 ที่รู้จักหรือไม่ และ `source_ip: 10.70.0.66` สำคัญแค่ไหน |
| **after (คาด)** | `hdfs_query_records` บน Feodo ipblocklist filter `ip_address in [203.0.113.66, 10.70.0.66]` → `matched_records: 0` เพราะ 203.0.113.66 คือ TEST-NET-3 (RFC 5737) และ 10.70.0.66 เป็น private เขียน `feeds/hashes.json` วันที่ดาวน์โหลด + sha256 ของ feed |
| **after (รันจริงใน 2b)** | asset criticality ใส่เป็นตารางในโค้ด `ASSET_CRIT = {"10.70.0.66": 4}, default 2` ทำให้ score ของ 10.70.0.66 ได้ +32 |

**ให้ผู้เรียนสังเกต** "ไม่เจอใน feed" เป็นผลลัพธ์ที่ต้องรายงาน ไม่ใช่สรุปว่าสะอาด และขั้นนี้อยู่นอก audit trail ของ MCP (Claude Desktop ดาวน์โหลดเอง) จึงต้องบันทึก sha256 เอง ส่วน asset model ใน QRadar เป็นฐานข้อมูลที่อัปเดตได้ ของเราเป็น dict ในโค้ดที่ต้องแก้แล้ว save เป็น v2

## 5. Storage / Indexing

**Storage คือ** การเก็บ record ที่ parse แล้วในรูปแบบที่อ่านซ้ำได้เร็วและเล็กกว่าต้นฉบับ ในที่นี้คือจาก JSON text 154 KB เป็น Parquet 31 KB ที่มี schema ติดมา ส่วน indexing (ทำให้ค้นได้โดยไม่ต้องอ่านทั้งไฟล์) ชุดนี้ไม่มี นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Ariel database, index ตามฟิลด์ที่เลือก, retention policy · **MCP:** HDFS + Parquet จาก Spark job · **lab:** 2

| | |
| --- | --- |
| **before** | `coherent-pcap-suricata-alerts-340.jsonl` 154,267 byte, 340 บรรทัด JSON text, sha256 `9cd3513a…` |
| **after** | `/mcp/module7/lab2-ids/curated/part-*.snappy.parquet` 31 KB + `_SUCCESS` (เล็กลง 5 เท่า มี schema 16 ฟิลด์ตาม `field_coverage.mapped` ของ report) |

**ให้ผู้เรียนสังเกต** Parquet มี schema และบีบอัด แต่ **ไม่มี index** ทุก query ใน lab 3 คือ scan ทั้งไฟล์ (`hdfs_correlate_records` รายงาน `scan 100,000 records`) และไม่มี retention policy ลบไม่ได้โดยไม่ตั้งใจ (`errorifexists`) แต่ก็ไม่หมดอายุเอง ผู้เรียนต้องลบ `/m6-10/<ชื่อ>/` เองหลังจบคาบ

## 6. Correlation / Analytics

**Correlation คือ** การสร้างสัญญาณจากความสัมพันธ์ระหว่าง event ที่ event เดียวบอกไม่ได้ ตัวอย่างในเอกสารนี้แสดง 3 แบบ: join ข้ามแหล่งด้วย key ร่วม (5-tuple) และเวลาใกล้กัน (alert 340 ↔ conn 100,000 จับคู่ได้ 340 คู่), แบบแผนเวลา (stddev 0 = ยิงเป็นจังหวะคงที่) และ sequence คือ A แล้ว B แล้ว C ภายในเวลาที่กำหนดบน asset เดียว (C2 → exfil → lateral ห่างไม่เกิน 1800 s ซึ่งเป็น input ของข้อ 10) ส่วนแบบ threshold ใน window อยู่ในข้อ 7 และแบบ baseline (ไม่ใช้ signature) อยู่ใน [lab 3c](lab3c-baseline.md) นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Custom Rules Engine (CRE) ทำงาน streaming · **MCP:** `hdfs_correlate_records` (join สองไฟล์ด้วย key + เวลา), `hdfs_query_records` (สถิติเวลา), Spark workflow correlate-security-evidence-with-spark · **lab:** 3, 3b

**before** สองไฟล์แยกกัน: alerts 340 record กับ Zeek conn 100,000 record ที่ยังไม่รู้ว่าเกี่ยวกัน

**after** `hdfs_correlate_records` keys 5-tuple, max_delta 1 s

| ตัวเลข | ค่า |
| --- | --- |
| matched_pairs | 340 |
| unmatched_left (alert ที่ไม่มี conn) | 0 |
| matched_right / unmatched_right | 265 / 99,735 |
| time delta | −0.005 … 0.0 s |
| matched_cohorts | C2 DNS 120↔120, Outbound 120↔120, East-West 100 alert ↔ **25** conn |

และ `hdfs_query_records` group_by signature พร้อม time stats ให้รูปแบบเวลาที่ CRE จะใช้เขียน rule

| signature | mean interval | stddev |
| --- | --- | --- |
| C2 DNS | 60.0 s | 0.0 |
| Outbound Transfer | 10.0 s | 0.0 |
| East-West | 2.4 s | 4.3 |

**ให้ผู้เรียนสังเกต** CRE ของ QRadar ตัดสิน "rule ตรง" ทันทีที่ event เข้า แต่ของเรารันหลังข้อมูลครบแล้ว (batch) และ tool คืน `interpretation: "shared origin is not independent corroboration"` ให้ด้วย เพราะ alert กับ conn มาจาก PCAP เดียวกัน ส่วนคำถาม "ทำไม East-West 100 alert จับได้ 25 conn" คือโจทย์ของ lab 3

## 7. Alerting

**Alerting คือ** การยุบ event ที่ซ้ำกันเป็นก้อนเดียว ให้คะแนนความรุนแรง และตัดสินว่าก้อนนั้นต้องมีคนดูหรือไม่ ในที่นี้คือ alert 340 บรรทัด กลายเป็น offense 39 รายการ แต่ละรายการมี fingerprint, จำนวน event, score และ route (escalate / queue / auto-close) นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Offense รวม event ที่เกี่ยวกันเป็นก้อนเดียว, magnitude 1–10, dedupe อัตโนมัติ · **MCP:** ไม่มี engine ให้ ต้องเขียน PySpark เอง (lab 2b) · **lab:** 2b

| | |
| --- | --- |
| **before** | alert 340 บรรทัด severity 1 ทุกบรรทัด ถ้าส่งเข้า queue ตรง ๆ คนต้องเปิด 340 ครั้ง |
| **after** | offense 39 รายการ (ลด 88.53%) `sum_event_count = 340` ตรวจสอบได้ ตัวอย่างรายการแรก: fingerprint `cd71af772d9c38bb` window 00:00–00:09, event_count 10, raw_score 127 → magnitude 100 → route escalate |

**by_signature** C2 DNS 12 offense / 120 event, East-West 25 / 100, Outbound 2 / 120 · **by_route** escalate 39, queue 0, auto-close 0

**ให้ผู้เรียนสังเกต** ตัวเลข magnitude 100 ทุกตัวคือบทเรียน: สูตร 7.2 ชนเพดานก่อนคิด burst จึง**ไม่แยกลำดับความสำคัญ** และ report นี้ไม่มี contract ใน skill server (`lab2b-offense-report-v0`) ความน่าเชื่อถือจึงต่ำกว่า lab 2 โดยออกแบบ ใน QRadar offense magnitude มาจาก relevance × severity × credibility ที่ engine คิดให้

## 8. Search / Investigation

**Investigation คือ** การถามคำถามเฉพาะเจาะจงกับข้อมูลที่เก็บไว้ เพื่อตอบว่าเกิดอะไร ไปไหน เท่าไร ในที่นี้คือ filter ด้วย IP คู่หนึ่ง แล้ว group และ sum byte จากนั้นลงไปดูระดับ packet ใน PCAP เพื่อยืนยันตัวเลขเดียวกัน นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** AQL, Log Activity tab, pivot จาก IP ไป user · **MCP:** `hdfs_query_records` (filters, group_by, sum, CIDR), `hdfs_pcap_packets` (TShark display filter), `hdfs_read_lines` · **lab:** 3

**before** คำถามของ analyst: "Outbound Transfer ส่งข้อมูลไปไหน กี่ byte จริงไหม" ซึ่งใน QRadar จะพิมพ์ AQL เช่น `SELECT destinationport, SUM(bytes) FROM flows WHERE sourceip='10.70.0.66' AND destinationip='203.0.113.66' GROUP BY destinationport`

**after** `hdfs_query_records` zeek conn filters `{id.orig_h: 10.70.0.66, id.resp_h: 203.0.113.66}` group_by `id.resp_p` sum `[orig_bytes, resp_bytes]`

| | ค่า |
| --- | --- |
| connections | 120 (พอร์ต 443 ทั้งหมด) |
| orig_bytes รวม | 6,010,330 (≈ 6.0 MB ออก) |
| resp_bytes รวม | 240 (≈ 2 byte ต่อครั้ง กลับ) |

ยืนยันระดับ packet ด้วย `hdfs_pcap_packets` filter `ip.src == 10.70.0.66 && ip.dst == 203.0.113.66 && tcp.dstport == 443` → 480 packet (120 conn × 4: SYN, ACK, data, FIN) frame แรก #241 เวลา 02:10:00.000

**ให้ผู้เรียนสังเกต** ทำได้เท่า AQL แต่ไม่มี query language ให้คนพิมพ์เอง ทุกคำถามต้องผ่าน Claude แปลงเป็น argument ของ tool และ tool เตือนว่า "packet count is not connection count" QRadar ก็มี flows กับ events แยกตารางด้วยเหตุผลเดียวกัน

## 9. Reporting / Dashboard

**Reporting คือ** การสรุป record จำนวนมากเป็นตัวเลขไม่กี่ตัวที่คนอ่านได้ (นับ, จัดอันดับ, ช่วงเวลา) ตามรูปแบบที่ตกลงไว้ล่วงหน้า ในที่นี้คือ Parquet 340 แถว กลายเป็น JSON 1 บรรทัดที่มี top_signatures, top_destination_ips, severity_summary และผ่านการตรวจว่าครบตาม contract นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Reports (PCI, ISO template), Dashboard · **MCP:** report contract (`ids-report-v1`) ผ่าน `log_skill_validate_report` แล้ว Claude Desktop ทำ Artifact / PDF · **lab:** 2 (รันจริง), 5 (ร่าง)

**before** curated Parquet 340 แถว ไม่มีใครอ่านรู้เรื่อง

**after** `report/part-*.txt` 2,175 byte JSON 1 บรรทัด ผ่าน `validate_report: valid true` (ตัดมาบางส่วน)

```json
{"report_contract_version":"ids-report-v1",
 "parser":{"id":"suricata-eve-alert-json-v1","vendor":"oisf","product":"suricata","log_type":"ids"},
 "total_records":340,"parse_quality":{"parsed":340,"failed":0},
 "event_time_min":"2026-08-24 00:00:00","event_time_max":"2026-08-24 02:44:00",
 "top_signatures":[{"value":"LAB13 Coherent C2 DNS","count":120},
                   {"value":"LAB13 Coherent Outbound Transfer","count":120},
                   {"value":"LAB13 Coherent East-West Remote Service","count":100}],
 "top_source_ips":[{"value":"10.70.0.66","count":340}],
 "top_destination_ips":[{"value":"10.70.0.53","count":120},{"value":"203.0.113.66","count":120},
                        {"value":"10.70.1.1","count":4}, "... อีก 24 host ละ 4"],
 "severity_summary":{"critical":340,"high":0,"medium":0,"low_or_info":0}}
```

**after ขั้นถัดไป (lab 5 คาด)** dashboard KPI 340 / 340 / 0, bar chart 120 / 120 / 100, PDF 1 หน้าที่ท้ายหน้าระบุ job `30d2a9d4…` และ sha256 `08e4e229…`

**ให้ผู้เรียนสังเกต** report บอกสถิติ ไม่บอกว่าเกิด incident (`alert_action: allowed` 340 = IDS เห็นแต่ไม่ block) narrative ที่ Claude เขียนต้องใช้คำว่า "rule ตรง" และตัวเลขทุกตัวต้องชี้กลับมาที่ JSON นี้ได้ และไม่มี MTTD/MTTR เพราะไม่มี ticket

## 10. Case / Incident Management

**Case management คือ** การเปลี่ยนผลวิเคราะห์เป็นงานที่มีเจ้าของ มีสถานะ และมีที่บันทึกการตัดสินใจ ในที่นี้ทำได้ถึงแค่ "ใบส่งต่อ" ที่ระบุ asset, timeline, หลักฐาน และสิ่งที่ analyst ต้องทำ แต่ไม่มี owner, ไม่มี state ที่เปลี่ยนได้ และไม่มีที่บันทึกผลว่า confirm หรือ dismiss นิยามเต็มนอกกรอบตัวอย่าง: [glossary หมวด 6](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

**QRadar:** Offense Manager (assign, note, close), QRadar SOAR · **MCP:** ไม่มี ใกล้ที่สุดคือ handoff document จาก build-security-investigation-handoff-with-spark · **lab:** 3b

**before** correlation report 1 บรรทัด (`events.log` 3,882 byte) ที่มี `investigation_candidates[0]`: asset-066, sequence 01:59:00 → 02:40:00

**after** `security-investigation-handoff-v2` 3,433 byte, sha256 `a803c6b7…` **เท่ากับรอบ 2026-08-20 ทุก byte** (deterministic)

```json
{"case_id":"case-v2-8d98cfda8bc05c11-asset-066","asset_id":"asset-066","entity_ip":"10.70.0.66",
 "priority":"high","disposition":"needs-review","verdict":"rule-hit",
 "timeline":[{"sequence":1,"event_time":"2026-08-24 01:59:00","role":"dns_c2","source_sha256":"ca45f68b…"},
             {"sequence":2,"event_time":"2026-08-24 02:10:00","role":"network_exfil","source_sha256":"aa1067e7…"},
             {"sequence":3,"event_time":"2026-08-24 02:40:00","role":"east_west_lateral","source_sha256":"3b547b6d…"}],
 "corroboration":[{"role":"ids_alert","records":340,"simulation":false},
                  {"role":"firewall_sim","records":265,"simulation":true}],
 "analyst_actions":["validate asset identity, ownership, and clock synchronization",
                    "review endpoint, identity, DNS, flow, IDS, and appliance-native firewall evidence",
                    "confirm or dismiss the multi-stage rule hit and document rationale"],
 "caveats":["Rule hit only; not a confirmed incident or compromise.", "..."]}
```

**สิ่งที่ยังไม่มี** เทียบกับ Offense Manager

| ความสามารถ | QRadar | MCP |
| --- | --- | --- |
| assign ให้ analyst | ✔ | ไม่มีฟิลด์ owner |
| state (open → in progress → closed) | ✔ | มีแค่ `needs-review` ค่าเดียว ไม่เปลี่ยน |
| note / comment | ✔ | ไม่มี |
| ปิด offense พร้อม reason | ✔ | `analyst_actions` ข้อ 3 บอกให้ทำ แต่ไม่มีที่บันทึก |
| ส่ง SOAR playbook | ✔ | ต้องส่ง JSON นี้เข้า TheHive/Jira เอง นอก MCP |

**ให้ผู้เรียนสังเกต** handoff คือ "ใบส่งต่อ" ไม่ใช่ case และ template v2 ผูกค่าคงที่กับ asset-066 ใช้กับ incident อื่นไม่ได้ นี่คือ "ท้ายที่ขาด" และเป็นเหตุผลที่ M6.1 (TheHive, SOAR) ยังไม่บรรลุ

## สิ่งที่อยู่ทุกขั้น

สามเรื่องที่ไม่ใช่ฟังก์ชันใดฟังก์ชันหนึ่ง แต่โผล่ในตัวอย่างข้างบนและ SIEM ทุกตัวต้องมี นิยามเต็มอยู่ใน [glossary หมวด 6 ตารางเรื่องข้ามขั้น](../../docs/glossary.md#6-ฟังก์ชันของ-siem)

| เรื่อง | เห็นได้จากตัวอย่างข้อ | หลักฐาน |
| --- | --- | --- |
| เวลา 2 ชนิด | 2, 3 | record เดียวมีทั้ง `event_time: 2026-08-24 00:00:00` (จาก log) และ `ingest_time: 2026-11-03T01:50:54` (ตอนรัน parser) rule ใช้ตัวแรก audit ใช้ตัวหลัง |
| provenance | 5, 9, 10 | sha256 ของ input `9cd3513a…`, code `000a3147…`, report `08e4e229…` ใน `hashes.json`; `raw_event` เก็บทั้งบรรทัด; handoff ใหม่ sha256 เท่ารอบ 2026-08-20 |
| feedback loop | 7, 10 | lab 2b ลด alert 88% แต่วัด TP ที่หลุดไม่ได้เพราะไม่มี label; ข้อ 10 ไม่มีที่บันทึก confirm / dismiss จึงไม่มีอะไรย้อนกลับไปปรับ score |

## สรุปภาพรวม

| # | ฟังก์ชัน | before | after | รันจริง |
| --- | --- | --- | --- | --- |
| 1 | Collection | ไฟล์นอก HDFS | 6 ไฟล์ใต้ `/mcp/student/.../input/` | ✅ (วางไว้ล่วงหน้า) |
| 2 | Parsing | FortiGate kv 1 บรรทัด | 24 ฟิลด์ + raw_event | ✅ 2026-11-03 |
| 3 | Normalization | srcip / id.orig_h / source_ip | `source_ip` ชื่อเดียว 3 แหล่ง | ✅ 2026-11-03 |
| 4 | Enrichment | IP เปล่า | matched_records 0 + asset_crit 4 | ⏳ lab 4 / ✅ 2b |
| 5 | Storage | JSONL 154 KB | Parquet 31 KB | ✅ job 30d2a9d4 |
| 6 | Correlation | 2 ไฟล์แยก | matched_pairs 340, stddev 0.0 | ✅ |
| 7 | Alerting | 340 alert | 39 offense | ✅ job 291d645c |
| 8 | Investigation | คำถาม | 6,010,330 byte, 480 packet | ✅ |
| 9 | Reporting | Parquet | ids-report-v1 valid | ✅ / ⏳ PDF |
| 10 | Case mgmt | correlation report | handoff needs-review | ✅ แต่ไม่ใช่ case |

สองช่องที่ MCP ทำแทนไม่ได้เลย (1 real-time, 10 case) คือจุดที่ผู้เรียนต้องเห็นเองว่า ถ้าองค์กรมี QRadar อยู่แล้ว MCP ชุดนี้คือเครื่องมือเสริมสำหรับขั้น 2–9 แบบ batch ไม่ใช่ตัวแทน SIEM
