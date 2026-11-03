# Lab 3 — correlate: alert ↔ Zeek conn ↔ PCAP (G2, วัตถุประสงค์ข้อ 2–3)

**หัวข้อ** M6.2 (correlation), M5.2 (Zeek, PCAP), incident analysis · **เวลา** 45 นาที · **ข้อมูล** Suricata alerts + Zeek conn 100k + PCAP 61 MB ใน HDFS

## โจทย์

alert จาก IDS บอกว่า "มี rule ตรง" แต่ยังไม่ใช่หลักฐาน ผู้เรียนต้องให้ Claude (1) สรุปรูปแบบเวลาของ alert แต่ละ signature (2) จับคู่ alert กับ connection จริงใน Zeek ด้วย 5-tuple (3) ยืนยันระดับ packet ใน PCAP และ (4) วัดปริมาณข้อมูลที่ออกไป โดยไม่ใช้ Spark เลย (ทุก tool เป็น HDFS scan)

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ คำตอบอยู่ในส่วนเฉลยด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | alert 340 รายการมาจาก source_ip กี่ตัว คือใคร | `hdfs_query_records` group_by source_ip |
| 2 | signature 3 ตัว แต่ละตัวมี count เท่าไร ปลายทางคือใคร พอร์ตและ protocol อะไร ช่วงเวลาเริ่ม–จบ | `hdfs_query_records` group_by [signature, source_ip] + time_field |
| 3 | mean interval และ stddev ของแต่ละ signature เป็นเท่าไร stddev 0 บอกอะไร | สถิติเวลาจาก query เดียวกัน + เทียบ CV ของตัวอย่าง 2.6 |
| 4 | correlate ได้ `matched_pairs`, `unmatched_left`, `unmatched_right` เท่าไร unmatched_right คือ traffic อะไร | ผล `hdfs_correlate_records` |
| 5 | East-West มี 100 alert แต่จับคู่ได้กี่ conn ทำไมจำนวนไม่เท่ากัน | `matched_cohorts` + นิยาม 5-tuple |
| 6 | ก่อน correlate ต้องรู้ชื่อฟิลด์จริงของ Zeek conn ว่าอะไร (ip/port/proto) ได้มาจากไหน | `hdfs_read_lines` 2 บรรทัดแรก |
| 7 | Outbound Transfer ส่งข้อมูลไปที่ใด byte ออกรวมเท่าไร byte เข้ารวมเท่าไร อัตราส่วนบอกรูปแบบอะไร | `hdfs_query_records` filters + sum_fields orig_bytes/resp_bytes |
| 8 | ใน PCAP มีกี่ packet ที่ตรง filter ทำไมไม่เท่ากับจำนวน conn (120) frame แรกเลขอะไร เวลาใด | `hdfs_pcap_packets` display_filter |
| 9 | `interpretation` ที่ tool คืนมาว่าอะไร ทำไม alert กับ conn จึงไม่ใช่หลักฐานอิสระสองชิ้น | ฟิลด์ interpretation ของ correlate + ที่มาของไฟล์ทั้ง 2 |
| 10 | 3 ระยะนี้เป็นเหตุการณ์เดียวกันหรือไม่ ใช้อะไรตัดสิน และ tool ตัดสินให้หรือเปล่า | asset เดียวกัน + ลำดับเวลา + ข้อความ `no incident verdict` |

## prompt ที่ผู้เรียนพิมพ์

```
จาก suricata alerts ใน incident-lab: สรุปตาม signature และ source_ip พร้อมสถิติเวลา
แล้วจับคู่ทุก alert กับ zeek conn ด้วย 5-tuple (ip/port ต้นทาง-ปลายทาง + protocol) ยอมคลาด 1 วินาที
```

```
alert "Outbound Transfer" ส่งข้อมูลไปไหน กี่ byte ยืนยันใน PCAP ด้วย
```

## ลำดับ tool ที่ควรเห็น

1. `hdfs_query_records` path alerts, format jsonl, group_by [signature, source_ip], time_field ts
2. `hdfs_read_lines` zeek conn 2 บรรทัด — เพื่อรู้ชื่อฟิลด์จริง (`id.orig_h`, `id.resp_p`, `proto`) ก่อน correlate
3. `hdfs_correlate_records` left = alerts (keys source_ip, source_port, destination_ip, destination_port, network_protocol; time ts; group_by signature), right = zeek conn (keys id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto; time ts), max_delta 1
4. `hdfs_query_records` zeek conn, filters {id.orig_h: 10.70.0.66, id.resp_h: 203.0.113.66}, group_by id.resp_p, sum_fields [orig_bytes, resp_bytes]
5. `hdfs_pcap_packets` display_filter `ip.src == 10.70.0.66 && ip.dst == 203.0.113.66 && tcp.dstport == 443`

## เฉลย (รันจริง 2026-11-02)

**ขั้น 1 — 3 ระยะของเหตุการณ์** (alerts 340 ทั้งหมดจาก 10.70.0.66, source_sha256 9cd3513a…)

| signature | count | ปลายทาง | ช่วงเวลา (UTC 2026-08-24) | mean interval | stddev |
| --- | --- | --- | --- | --- | --- |
| C2 DNS | 120 | 10.70.0.53:53 udp | 00:00:00 → 01:59:00 (119 นาที) | **60.0 s** | **0.0** |
| Outbound Transfer | 120 | 203.0.113.66:443 tcp | 02:10:00 → 02:29:50 (19.8 นาที) | **10.0 s** | **0.0** |
| East-West Remote Service | 100 | 10.70.1.1–25 tcp (พอร์ตหมุนตาม host: 22 ×9 host / 445 ×8 / 3389 ×8) | 02:40:00 → 02:44:00 (4 นาที) | 2.4 s | 4.3 |

stddev 0 ของสองระยะแรกคือ "beacon" แบบเครื่องจักร (เทียบ CV ของตัวอย่าง 2.6 ใน M5.2) ระยะที่สามคือ fan-out ไป 25 host ละ 4 ครั้ง

**ขั้น 3 — correlate** (right sha256 82736842…, scan 100,000 records)

| ตัวเลข | ค่า |
| --- | --- |
| matched_pairs | **340** |
| matched_left (alert) | 340 — unmatched_left **0** |
| matched_right (conn) | 265 — unmatched_right 99,735 (traffic ปกติ) |
| left ที่จับคู่ได้หลายตัว | 0 |
| time delta ที่พบ | −0.005 … 0.0 s |

matched_cohorts: C2 DNS 120 alert ↔ 120 conn; Outbound 120 ↔ 120; East-West 100 alert ↔ **25 conn** (4 alert ต่อ 1 conn เพราะ 5-tuple ซ้ำ — คำถามให้ผู้เรียน: ทำไม)

`interpretation` ที่ tool คืน: "shared origin is not independent corroboration" — alert กับ conn มาจาก PCAP เดียวกัน จึงไม่ใช่หลักฐานอิสระสองชิ้น

**ขั้น 4 — ปริมาณข้อมูลออก** conn 10.70.0.66 → 203.0.113.66:443 จำนวน 120 ครั้ง: `orig_bytes` รวม **6,010,330** (≈ 6.0 MB ออก) ต่อ `resp_bytes` รวม **240** (≈ 2 byte ต่อครั้ง กลับ) ทุก 10 วินาที — รูปแบบ asymmetric upload

**ขั้น 5 — PCAP** (sha256 fa9d5c21…) filter ตรง **480 packet** (120 conn × 4 packet: SYN, ACK, data, FIN) frame แรก #241 ที่ 02:10:00.000 payload_length 0 (`protocol_observation: not_established` คือ handshake)

## จุดที่คนต้องทำ

- ตัดสินว่า 3 ระยะนี้เป็นเหตุการณ์เดียวกันหรือไม่ (asset เดียวกัน, ลำดับเวลาต่อเนื่อง) — tool ไม่ตัดสินให้ (`no incident verdict`)
- นิยาม "หลักฐานอิสระ": PCAP เป็นต้นทางของทั้ง alert และ conn ดังนั้นต้องหาแหล่งที่สาม (เช่น FortiGate log ในชุดเดียวกัน) ก่อนสรุป
- ตั้ง threshold: 6 MB ออกใน 20 นาทีผิดปกติสำหรับองค์กรนี้หรือไม่ ต้องรู้ baseline

## Claude ผิดตรงไหนได้บ้าง

- correlate ด้วยชื่อฟิลด์เดาเอง (`src_ip`) โดยไม่อ่าน sample ก่อน → "Missing requested fields fail" ตามกติกา tool
- สรุปว่า "ถูกโจมตีแน่นอน ข้อมูลรั่ว 6 MB" ทั้งที่ชุดข้อมูลเป็น synthetic และ tool บอกว่าไม่ตัดสิน
- นับ packet เป็นจำนวน connection (tool เตือนไว้: packet count is not connection count)
