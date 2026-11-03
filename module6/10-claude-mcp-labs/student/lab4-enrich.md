# Lab 4 — enrich: IP ใน alert ติด threat feed ไหม (G3)

**หัวข้อ** M5.4 (ดึง API สาธารณะ), M5.5 (ingest feed, match indicator), M6.3 (EPSS 8.5) · **เวลา** 45 นาที

## โจทย์

MCP ทั้งสองตัวออกอินเทอร์เน็ตไม่ได้ แต่ Claude Desktop ทำได้ ผู้เรียนต้องให้ Claude ดึง feed ที่ไม่ต้องมี key เขียนขึ้น HDFS แล้วใช้ `hdfs_query_records` เช็คว่า IP ปลายทางใน alert (203.0.113.66) อยู่ใน feed หรือไม่ พร้อมบันทึกวันที่และ sha256 ของ feed เพราะขั้นนี้อยู่นอก audit trail ของ MCP

## สิ่งที่ต้องค้นให้ได้

ผู้เรียนต้องตอบทุกข้อเป็นลายลักษณ์อักษร และทุกคำตอบต้องชี้กลับไปที่ผลของ tool (ชื่อ tool + ฟิลด์หรือบรรทัดที่อ่านมา) ไม่รับคำตอบที่ Claude สรุปให้โดยไม่มี tool รองรับ บันทึกคำตอบในส่วน "บันทึกคำตอบ" ด้านล่าง

| # | คำถาม | หลักฐานที่ต้องแสดง |
| --- | --- | --- |
| 1 | feed ที่ดึงมามี URL, วันที่ดาวน์โหลด, sha256, จำนวน record, license อะไร และ Claude ขออนุญาตก่อนดาวน์โหลดไหม | บันทึก `feeds/hashes.json` + `hdfs_sha256` หลังเขียนขึ้น HDFS ตรงกับค่าที่คำนวณในเครื่อง |
| 2 | record ของ Feodo มีฟิลด์อะไรบ้าง ฟิลด์ใดใช้ match กับ IP ใน alert | `hdfs_read_lines` ไฟล์ feed ใน HDFS |
| 3 | 203.0.113.66 และ 10.70.0.66 อยู่ใน Feodo ไหม `matched_records` เท่าไร | `hdfs_query_records` filters/cidr_filters บน feed |
| 4 | ทำไม IP ทั้งสองจึง *ไม่ควร* อยู่ใน feed ใดเลย (ช่วง IP เป็นอะไร) | RFC 5737 TEST-NET-3 และ RFC 1918 |
| 5 | "ไม่เจอใน feed" แปลว่าปลอดภัย หรือแปลว่าไม่รู้ และต้องรายงานผล 0 ไหม | คำอธิบายของผู้เรียน |
| 6 | EPSS ของ CVE-2024-3400 มีค่า `epss` และ `percentile` เท่าไร percentile หมายถึงอะไร | JSON จาก api.first.org |
| 7 | ขั้นใดของ lab นี้อยู่นอก audit trail ของ MCP และผู้เรียนชดเชยด้วยอะไร | ลำดับ tool (WebFetch/curl อยู่ฝั่ง Claude Desktop) + hashes.json |
| 8 | `hdfs_import_file` ใช้กับไฟล์บนเครื่องผู้เรียนได้ไหม ทำไม | description ของ tool |

## prompt ที่ผู้เรียนพิมพ์

```
ดึง Feodo Tracker ipblocklist (JSON) และ CISA KEV มาวางใน HDFS ที่ /m6-10/<ชื่อ>/feeds
บันทึกวันที่ดาวน์โหลดและ sha256 แล้วเช็คว่า 203.0.113.66 กับ 10.70.0.66 อยู่ใน Feodo ไหม
```

ต่อยอด:
```
ดึง EPSS ของ CVE-2024-3400 จาก api.first.org แล้วอธิบายว่า percentile หมายถึงอะไร
```

## ลำดับ tool ที่ควรเห็น

1. WebFetch หรือ Bash curl → `https://feodotracker.abuse.ch/downloads/ipblocklist.json` (Claude ต้องขออนุญาตก่อน)
2. แปลงเป็น JSONL บนเครื่อง (1 record ต่อบรรทัด) และคำนวณ sha256
3. `hdfs_mkdir` → `hdfs_write_text` (text ผ่าน argument; ไฟล์ใหญ่ต้องแบ่งก้อน) → `hdfs_sha256` เทียบ
4. `hdfs_query_records` path feed, filters {ip_address: [203.0.113.66, 10.70.0.66]} หรือ `cidr_filters`
5. EPSS: WebFetch `https://api.first.org/data/v1/epss?cve=CVE-2024-3400`

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

- อนุมัติการดาวน์โหลดทุกครั้ง และตรวจ license ของ feed จากหน้าของผู้ให้ feed เอง
- บันทึก `feeds/hashes.json` วันที่ + sha256 ตามกติกา repo
- ตัดสินว่า "ไม่เจอใน feed" แปลว่าปลอดภัยหรือแค่ไม่รู้

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า IP "สะอาด" เพราะไม่อยู่ใน feed
- ดาวน์โหลดโดยไม่ขออนุญาต หรือไม่บันทึก sha256
- ใช้ `hdfs_import_file` กับไฟล์บนเครื่องผู้เรียน (tool นี้รับ source ฝั่ง server เท่านั้น)
