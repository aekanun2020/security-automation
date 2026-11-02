# Lab 4 — enrich: IP ใน alert ติด threat feed ไหม (G3) — ร่าง ยังไม่ได้รัน

**หัวข้อ** M5.4 (ดึง API สาธารณะ), M5.5 (ingest feed, match indicator), M6.3 (EPSS 8.5) · **เวลา** 45 นาที · **สถานะ** ⏳ ร่าง — เฉลยจะเติมหลังรันเช้า 2026-11-03 เพราะต้องขออนุญาตดาวน์โหลดทุกครั้ง

## โจทย์

MCP ทั้งสองตัวออกอินเทอร์เน็ตไม่ได้ แต่ Claude Desktop ทำได้ ผู้เรียนต้องให้ Claude ดึง feed ที่ไม่ต้องมี key เขียนขึ้น HDFS แล้วใช้ `hdfs_query_records` เช็คว่า IP ปลายทางใน alert (203.0.113.66) อยู่ใน feed หรือไม่ พร้อมบันทึกวันที่และ sha256 ของ feed เพราะขั้นนี้อยู่นอก audit trail ของ MCP

## prompt ที่ผู้เรียนพิมพ์

```
ดึง Feodo Tracker ipblocklist (JSON) และ CISA KEV มาวางใน HDFS ที่ /module7/<ชื่อ>/feeds
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

## เฉลยที่คาด (ต้องยืนยันตอนรัน)

- 203.0.113.66 อยู่ใน TEST-NET-3 (RFC 5737) และ 10.70.0.66 เป็น private → **ไม่ควรอยู่ใน feed ใด** ผลที่ถูกคือ matched_records 0 — นี่คือบทเรียน: enrichment ที่ไม่เจออะไรก็เป็นผลลัพธ์ที่ต้องรายงาน
- Feodo JSON record มีฟิลด์ `ip_address, port, status, hostname, as_number, as_name, country, first_seen, last_online, malware` (จาก [research notes](../../docs/research_notes/datasets-for-gap-labs/enrichment_feeds_and_qradar_formats.md))
- EPSS CVE-2024-3400 เมื่อ 2026-11-01: epss 0.99999, percentile 1.0 (ตรวจสดแล้วในรายงาน research)

## จุดที่คนต้องทำ

- อนุมัติการดาวน์โหลดทุกครั้ง และตรวจ license ของ feed (Feodo CC0; KEV public domain)
- บันทึก `feeds/hashes.json` วันที่ + sha256 ตามกติกา repo
- ตัดสินว่า "ไม่เจอใน feed" แปลว่าปลอดภัยหรือแค่ไม่รู้

## Claude ผิดตรงไหนได้บ้าง

- บอกว่า IP "สะอาด" เพราะไม่อยู่ใน feed
- ดาวน์โหลดโดยไม่ขออนุญาต หรือไม่บันทึก sha256
- ใช้ `hdfs_import_file` กับไฟล์บนเครื่องผู้เรียน (tool นี้รับ source ฝั่ง server เท่านั้น)
