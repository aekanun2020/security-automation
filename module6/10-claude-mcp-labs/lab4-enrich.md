# Lab 4 — enrich: IP ใน alert ติด threat feed ไหม (G3) — ร่าง ยังไม่ได้รัน

**หัวข้อ** M5.4 (ดึง API สาธารณะ), M5.5 (ingest feed, match indicator), M6.3 (EPSS 8.5) · **เวลา** 45 นาที · **สถานะ** ⏳ ร่าง — เฉลยจะเติมหลังรันเช้า 2026-11-03 เพราะต้องขออนุญาตดาวน์โหลดทุกครั้ง

## โจทย์

MCP ทั้งสองตัวออกอินเทอร์เน็ตไม่ได้ แต่ Claude Desktop ทำได้ ผู้เรียนต้องให้ Claude ดึง feed ที่ไม่ต้องมี key เขียนขึ้น HDFS แล้วใช้ `hdfs_query_records` เช็คว่า IP ปลายทางใน alert (203.0.113.66) อยู่ใน feed หรือไม่ พร้อมบันทึกวันที่และ sha256 ของ feed เพราะขั้นนี้อยู่นอก audit trail ของ MCP

## prompt ที่ผู้เรียนพิมพ์

```
ดึง Feodo Tracker ipblocklist (JSON) และ CISA KEV มาวางใน HDFS ที่ /m6-10/<ชื่อ>/feeds
บันทึกวันที่ดาวน์โหลดและ sha256 แล้วเช็คว่า 203.0.113.66 กับ 10.70.0.66 อยู่ใน Feodo ไหม
```

ต่อยอด:
```
ดึง EPSS ของ CVE-2024-3400 จาก api.first.org แล้วอธิบายว่า percentile หมายถึงอะไร
```

## คำถามที่ถาม Claude ต่อ

เมื่อ prompt แรกทำงานเสร็จ ให้พิมพ์คำถามข้างล่างถาม Claude ต่อทีละข้อ เหมือนถามเพื่อนร่วมทีมหน้า SIEM งานของผู้เรียนไม่ใช่ไปค้นเอง แต่คือตรวจคำตอบ Claude ต้องอ้างได้ว่าคำตอบมาจาก tool ใดและฟิลด์ใด (คอลัมน์ "คำตอบต้องอ้างอะไร") ถ้าตอบโดยไม่เรียก tool หรือไม่บอกที่มา ให้สั่งว่า "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้" และสุ่มเทียบตัวเลขอย่างน้อย 1 ค่าต่อ lab กับ output ดิบด้วยตาตัวเอง ข้อที่ประเภทเป็น **ตัดสิน** Claude เสนอได้ แต่คนเป็นผู้ตัดสินและเขียนเหตุผลเอง คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง

| # | พิมพ์ถาม Claude | คำตอบต้องอ้างอะไร | ประเภท |
| --- | --- | --- | --- |
| 1 | IP ปลายทางที่เครื่องเราส่งข้อมูลไป ใครในโลกรู้จักมันบ้าง ติด blacklist ไหม | `hdfs_query_records` บน feed Feodo ใน HDFS: `matched_records` | ตรวจ |
| 2 | ถ้าไม่ติด blacklist แปลว่าปลอดภัยไหม แล้วต้องรายงานผล 0 ไหม | คำอธิบายของผู้เรียน: ไม่รู้ ≠ สะอาด | ตัดสิน |
| 3 | IP ช่วงนี้ปกติเป็นของใคร เป็นไปได้ไหมที่จะอยู่ใน feed ใด | ช่วง IP ตาม RFC 5737 (TEST-NET-3) และ RFC 1918 | ตรวจ |
| 4 | feed ที่เราใช้สดแค่ไหน ดึงเมื่อไร ใครอนุมัติ และพิสูจน์ได้ไหมว่าไม่ถูกแก้ระหว่างทาง | วันที่, sha256 ที่คำนวณในเครื่องเทียบ `hdfs_sha256`, license, บันทึกการขออนุญาตใน `feeds/hashes.json` | ตรวจ |
| 5 | ช่องโหว่ CVE-2024-3400 ต้องรีบแพตช์แค่ไหนเทียบกับช่องโหว่อื่น | EPSS: `epss`, `percentile` จาก api.first.org | ตรวจ |
| 6 | ขั้นดึงข้อมูลจากอินเทอร์เน็ตอยู่นอกระบบ audit ของ MCP เราจะคุมอย่างไร | ลำดับ tool (WebFetch/curl ฝั่ง Claude Desktop) + hashes.json + ข้อจำกัดของ `hdfs_import_file` | ตัดสิน |

## ลำดับ tool ที่ควรเห็น

1. WebFetch หรือ Bash curl → `https://feodotracker.abuse.ch/downloads/ipblocklist.json` (Claude ต้องขออนุญาตก่อน)
2. แปลงเป็น JSONL บนเครื่อง (1 record ต่อบรรทัด) และคำนวณ sha256
3. `hdfs_mkdir` → `hdfs_write_text` (text ผ่าน argument; ไฟล์ใหญ่ต้องแบ่งก้อน) → `hdfs_sha256` เทียบ
4. `hdfs_query_records` path feed, filters {ip_address: [203.0.113.66, 10.70.0.66]} หรือ `cidr_filters`
5. EPSS: WebFetch `https://api.first.org/data/v1/epss?cve=CVE-2024-3400`

## เฉลย (รันจริง 2026-11-03 12:10 UTC)

- 203.0.113.66 อยู่ใน TEST-NET-3 (RFC 5737) และ 10.70.0.66 เป็น private → **ไม่ควรอยู่ใน feed ใด** ผลที่ถูกคือ matched_records 0 — นี่คือบทเรียน: enrichment ที่ไม่เจออะไรก็เป็นผลลัพธ์ที่ต้องรายงาน
- Feodo JSON record มีฟิลด์ `ip_address, port, status, hostname, as_number, as_name, country, first_seen, last_online, malware` (จาก [research notes](../../docs/research_notes/datasets-for-gap-labs/enrichment_feeds_and_qradar_formats.md))
- EPSS CVE-2024-3400 เมื่อ 2026-11-01: epss 0.99999, percentile 1.0 (ตรวจสดแล้วในรายงาน research; รันซ้ำ 2026-11-03 ได้ 0.999990000 / 1.000000000 date 2026-11-02)

**ผลรันจริง 2026-11-03** (curl บนเครื่องผู้สอน นอก audit ของ MCP แล้วเขียนเข้า HDFS)

| รายการ | ค่า |
| --- | --- |
| Feodo ipblocklist.json | **5 record เท่านั้น** (Emotet 1 offline, QakBot 4: online 1 offline 3) sha256 ต้นฉบับ ef1c98c8…; แปลงเป็น JSONL 1,211 byte sha256 3ecc94c1… ทั้งบนเครื่องและ `hdfs_sha256` หลัง `hdfs_write_text` |
| `hdfs_query_records` filters ip_address [203.0.113.66, 10.70.0.66] | scanned 5, matched_records **0** |
| CISA KEV | 1,826,755 byte, 1,766 CVE, catalogVersion 2026.10.30, sha256 3aa9cf3c…; มี CVE-2024-3400 dateAdded 2024-04-12 |
| KEV เข้า HDFS | **ไม่ได้** `hdfs_import_file` คืน `import source is unavailable or unstable: [Errno 2] No such file or directory: '/imports/kev.json'` (source ต้องอยู่ที่ /imports บน server) และ `hdfs_write_text` รับข้อความทั้งก้อนผ่าน argument ซึ่ง 1.8 MB ไม่เหมาะ ผู้เรียนทำได้แค่บันทึก sha256 + ผล lookup ใน hashes.json หรือแบ่งก้อนเอง |
| hashes.json | `/m6-10/<ชื่อ>/feeds/hashes.json` บันทึก fetched_at, url, license, sha256 ต้นฉบับ/JSONL, path ใน HDFS, ผล lookup |

บทเรียนเพิ่ม: feed ที่ "ว่าง" (5 record) ไม่ได้แปลว่า tool ผิด Feodo เผยแพร่เฉพาะ C2 ที่ยัง active ในช่วงนั้น ต้องบันทึกวันที่ดึงเสมอ

## จุดที่คนต้องทำ

- อนุมัติการดาวน์โหลดทุกครั้ง และตรวจ license ของ feed (Feodo CC0; KEV public domain)
- บันทึก `feeds/hashes.json` วันที่ + sha256 ตามกติกา repo
- ตัดสินว่า "ไม่เจอใน feed" แปลว่าปลอดภัยหรือแค่ไม่รู้

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า IP "สะอาด" เพราะไม่อยู่ใน feed
- ดาวน์โหลดโดยไม่ขออนุญาต หรือไม่บันทึก sha256
- ใช้ `hdfs_import_file` กับไฟล์บนเครื่องผู้เรียน (tool นี้รับ source ฝั่ง server ที่ `/imports/<source_name>` เท่านั้น error จริง: `No such file or directory: '/imports/kev.json'`)
- รายงานว่า "feed มีน้อยผิดปกติ น่าจะดึงผิด" ทั้งที่ Feodo แสดงเฉพาะ C2 ที่ active ในช่วงนั้น → ให้ดู `fetched_at` และ status ของ record
