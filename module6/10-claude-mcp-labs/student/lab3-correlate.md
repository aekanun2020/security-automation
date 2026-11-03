# Lab 3 — correlate: alert ↔ Zeek conn ↔ PCAP (G2, วัตถุประสงค์ข้อ 2–3)

**หัวข้อ** M6.2 (correlation), M5.2 (Zeek, PCAP), incident analysis · **เวลา** 45 นาที · **ข้อมูล** Suricata alerts + Zeek conn 100k + PCAP 61 MB ใน HDFS

## สถานการณ์

รายงานจาก lab 2 บอกว่ามีสามก้อน C2 DNS, Outbound Transfer, East-West Remote Service และทั้งหมดมาจากเครื่อง 10.70.0.66 น้องรู้แค่ว่า rule ตรง ยังไม่รู้ว่าสามก้อนเป็นเรื่องเดียวกันไหม และ alert แต่ละตัวมี connection จริงรองรับหรือเป็น alert ลอย คำถามที่พา lab นี้คือ ร้อยสามก้อนนี้เข้าด้วยกันตามเวลาได้ไหม ข้อมูลออกไปเท่าไรจริง และถ้าเปิด packet ดูจะเห็นอย่างที่ Zeek บอกไหม

## โจทย์

alert จาก IDS บอกว่า "มี rule ตรง" แต่ยังไม่ใช่หลักฐาน ผู้เรียนต้องให้ Claude (1) สรุปรูปแบบเวลาของ alert แต่ละ signature (2) จับคู่ alert กับ connection จริงใน Zeek ด้วย 5-tuple (3) ยืนยันระดับ packet ใน PCAP และ (4) วัดปริมาณข้อมูลที่ออกไป โดยไม่ใช้ Spark เลย (ทุก tool เป็น HDFS scan)

## prompt ที่ผู้เรียนพิมพ์

```
จาก suricata alerts ใน incident-lab: สรุปตาม signature และ source_ip พร้อมสถิติเวลา
แล้วจับคู่ทุก alert กับ zeek conn ด้วย 5-tuple (ip/port ต้นทาง-ปลายทาง + protocol) ยอมคลาด 1 วินาที
```

```
alert "Outbound Transfer" ส่งข้อมูลไปไหน กี่ byte ยืนยันใน PCAP ด้วย
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง บันทึกในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | alert 340 รายการนี้เรื่องเดียวกันไหม มาจากเครื่องเดียวหรือหลายเครื่อง | `hdfs_query_records` alerts group_by source_ip | ตรวจ |
| 2 | เครื่องนั้นทำอะไรบ้าง เรียงตามเวลา มีกี่ระยะ แต่ละระยะเริ่มและจบเมื่อไร ไปหาใคร | `hdfs_query_records` group_by [signature, source_ip] + time_field: count, ปลายทาง, พอร์ต, protocol, เวลาเริ่ม–จบ | ตรวจ |
| 3 | จังหวะแบบนี้คนทำหรือโปรแกรมทำ | `time.mean_interval_seconds` และ `time.population_stddev_seconds` ของแต่ละระยะ (เทียบ CV ของตัวอย่าง 2.6) | ตรวจ |
| 4 | ที่ IDS ร้อง มี connection จริงรองรับไหม หรือเป็น alert ลอย ๆ | `hdfs_correlate_records` alert ↔ Zeek conn ด้วย 5-tuple: `matched_pairs`, `matched_right_records`, `unmatched_left_records`, `unmatched_right_records` (ต้องอ่านชื่อฟิลด์จริงของ Zeek ด้วย `hdfs_read_lines` ก่อน) | ตรวจ |
| 5 | ทำไม lateral มี 100 alert แต่ connection แค่ 25 IDS นับซ้ำหรือเราเข้าใจผิด | `matched_cohorts` + นิยาม 5-tuple | ตรวจ |
| 6 | ข้อมูลออกไปเท่าไร ไปที่ไหน เป็นการอัปโหลดหรือดาวน์โหลด และใน packet จริงเห็นอย่างนั้นไหม | `hdfs_query_records` conn ไปปลายทางนั้น sum orig_bytes/resp_bytes + `hdfs_pcap_packets` (จำนวน packet ≠ จำนวน conn) | ตรวจ |
| 7 | alert กับ conn มาจาก sensor เดียวกัน แล้วเรามีหลักฐานกี่ชิ้นจริง ๆ | ฟิลด์ `interpretation` ที่ correlate คืน + ที่มาของไฟล์ทั้งสอง (PCAP เดียวกัน) | ตัดสิน |
| 8 | ตอนนี้เรียกว่า incident ได้ไหม ถ้ายัง ขาดอะไร และใครต้องตัดสิน | ข้อ 1–7 รวมกัน + ข้อความ `no incident verdict` ของ tool | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. `hdfs_query_records` path alerts, format jsonl, group_by [signature, source_ip], time_field ts
2. `hdfs_read_lines` zeek conn 2 บรรทัด — เพื่อรู้ชื่อฟิลด์จริง (`id.orig_h`, `id.resp_p`, `proto`) ก่อน correlate
3. `hdfs_correlate_records` left = alerts (keys source_ip, source_port, destination_ip, destination_port, network_protocol; time ts; group_by signature), right = zeek conn (keys id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto; time ts), max_delta 1 (tool รับ `max_delta_seconds` 0..60 และ `max_examples` 1..5 เท่านั้น ใส่ 0 จะ error `delta 0..60 seconds, examples 1..5`)
4. `hdfs_query_records` zeek conn, filters {id.orig_h: <source_ip จากขั้น 1>, id.resp_h: <destination_ip ของ Outbound Transfer จากขั้น 1>}, group_by id.resp_p, sum_fields [orig_bytes, resp_bytes]
5. `hdfs_pcap_packets` display_filter `ip.src == <source_ip> && ip.dst == <destination_ip> && tcp.dstport == <port>`

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
| 8 | | | |

## จุดที่คนต้องทำ

- ตัดสินว่า 3 ระยะนี้เป็นเหตุการณ์เดียวกันหรือไม่ (asset เดียวกัน, ลำดับเวลาต่อเนื่อง) — tool ไม่ตัดสินให้ (`no incident verdict`)
- นิยาม "หลักฐานอิสระ": PCAP เป็นต้นทางของทั้ง alert และ conn ดังนั้นต้องหาแหล่งที่สาม (เช่น FortiGate log ในชุดเดียวกัน) ก่อนสรุป
- ตั้ง threshold: ปริมาณ byte ออกที่ค้นได้ภายในช่วงเวลานั้น ผิดปกติสำหรับองค์กรนี้หรือไม่ ต้องรู้ baseline (lab 3c)

## Claude ผิดตรงไหนได้บ้าง

- ใส่ `max_examples: 0` เพื่อลด output แล้วเจอ error ช่วง 1..5 → ใช้ 1 (เกิดจริงตอนรันซ้ำ 2026-11-03)
- correlate ด้วยชื่อฟิลด์เดาเอง (`src_ip`) โดยไม่อ่าน sample ก่อน → "Missing requested fields fail" ตามกติกา tool
- สรุปว่า "ถูกโจมตีแน่นอน ข้อมูลรั่ว x MB" ทั้งที่ชุดข้อมูลเป็น synthetic และ tool บอกว่าไม่ตัดสิน
- นับ packet เป็นจำนวน connection (tool เตือนไว้: packet count is not connection count)
