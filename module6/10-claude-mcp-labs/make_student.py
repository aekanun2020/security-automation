#!/usr/bin/env python3
"""สร้างฉบับผู้เรียน (student/) จากไฟล์ lab ของผู้สอนในโฟลเดอร์นี้

python3 make_student.py            # เขียน student/lab*.md และ student/README.md ใหม่ทั้งหมด

ฉบับผู้เรียนคือไฟล์เดียวกันทุกส่วน ยกเว้น
- ส่วน "## เฉลย…" ถูกแทนด้วย "## บันทึกคำตอบ" (ตารางเปล่าตามจำนวนข้อใน "คำถามที่ถาม Claude ต่อ")
- ข้อความใน REPLACE ถูกแทน เพราะส่วนอื่น (ลำดับ tool, จุดที่คนต้องทำ) ของบางไฟล์เผยคำตอบ
- หัวไฟล์ตัดสถานะ "ร่าง" ออก และ path ของผู้สอน /module7/... เปลี่ยนเป็น /m6-10/<ชื่อ>/...
แก้ไฟล์ผู้สอนแล้วรันสคริปต์นี้ซ้ำ ห้ามแก้ student/ ด้วยมือ
"""
import pathlib, re, sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "student"
ORDER = ["lab0-tools.md", "lab1-parser.md", "lab2-spark-report.md", "lab3-correlate.md",
         "lab3c-baseline.md", "lab3b-handoff.md", "lab2b-dedupe-score.md", "lab4-enrich.md", "lab5-report.md"]
TIME = {"lab0-tools.md": "20 นาที", "lab1-parser.md": "30 นาที", "lab2-spark-report.md": "45 นาที",
        "lab3-correlate.md": "45 นาที", "lab3c-baseline.md": "30 นาที", "lab3b-handoff.md": "40 นาที",
        "lab2b-dedupe-score.md": "60 นาที", "lab4-enrich.md": "45 นาที (ถ้าเหลือเวลา)", "lab5-report.md": "45 นาที (ถ้าเหลือเวลา)"}

# ข้อความในส่วนที่ไม่ใช่เฉลย แต่บอกค่าที่ผู้เรียนต้องค้นเอง → แทนด้วยคำชี้ว่าให้ดูฟิลด์ใด
REPLACE = {
"lab1-parser.md": [
 ("→ `unknown_format: true`", "→ อ่านค่า `selected`, `candidates`, `unknown_format`"),
 ("(lab 2 จะให้ตัวเลข 340/340)", "(lab 2 จะให้ตัวเลข total/parsed/failed)"),
 ("- เลือก netflow parser เพราะ score 30 \"ก็ยังมีคะแนน\" → ชี้ว่า parse_success เป็น false", "- เลือก parser ที่ได้ score ต่ำ \"เพราะก็ยังมีคะแนน\" → ให้ดูฟิลด์ `parse_success` ของ candidate นั้นก่อน"),
],
"lab2-spark-report.md": [
 ("(skill = **parse-suricata-eve-alerts**, parser_id) | skill | code + `code_sha256` |", "(skill, parser_id) | skill | code + `code_sha256` — ถ้าได้ error ให้อ่านข้อความแล้วคิดว่าต้องใช้ skill ชนิดใด |"),
 ("`matches_trusted_template: true` + 15 checks", "`matches_trusted_template: true` + รายการ checks"),
 ("- ตีความ: `alert_action = allowed` ทั้ง 340 แปลว่า IDS เห็นแต่ไม่ block", "- ตีความค่า `alert_action` ที่ได้: IDS block หรือแค่เห็น"),
],
"lab2b-dedupe-score.md": [
 ("· **ข้อมูล** curated Parquet จาก lab 2 (`/module7/lab2-ids/curated`)", "· **ข้อมูล** curated Parquet จาก lab 2 ของตัวเอง (`/m6-10/<ชื่อ>/lab2-ids/curated`)"),
 ("(`module7_lab2b_offense_v1.py`; แก้แล้วต้องเป็น v2 ไม่ทับ)", "(`<ชื่อ>_lab2b_offense_v1.py`; แก้แล้วต้องเป็น v2 ไม่ทับ)"),
 ("(โค้ดเฉลยเป็น fixed `floor(epoch/600)` ซึ่ง**ต่างจาก 7.2** ที่เป็น sliding deque — Claude ต้องประกาศ deviation ใน docstring)", "(ตัวอย่าง 7.2 เป็น sliding deque — ถ้าโค้ดต่างจากนั้น Claude ต้องประกาศ deviation ใน docstring)"),
 ("\"ลด alert ได้ 88% ดีมาก\"", "\"ลด alert ได้ x% ดีมาก\""),
],
"lab3-correlate.md": [
 ("filters {id.orig_h: 10.70.0.66, id.resp_h: 203.0.113.66}", "filters {id.orig_h: <source_ip จากขั้น 1>, id.resp_h: <destination_ip ของ Outbound Transfer จากขั้น 1>}"),
 ("`ip.src == 10.70.0.66 && ip.dst == 203.0.113.66 && tcp.dstport == 443`", "`ip.src == <source_ip> && ip.dst == <destination_ip> && tcp.dstport == <port>`"),
 ("- ตั้ง threshold: 6 MB ออกใน 20 นาทีผิดปกติสำหรับองค์กรนี้หรือไม่ ต้องรู้ baseline", "- ตั้ง threshold: ปริมาณ byte ออกที่ค้นได้ภายในช่วงเวลานั้น ผิดปกติสำหรับองค์กรนี้หรือไม่ ต้องรู้ baseline (lab 3c)"),
 ("\"ถูกโจมตีแน่นอน ข้อมูลรั่ว 6 MB\"", "\"ถูกโจมตีแน่นอน ข้อมูลรั่ว x MB\""),
],
"lab3b-handoff.md": [
 ("→ เห็น `investigation_candidates[0]`: asset-066, 10.70.0.66, sequence 01:59:00 → 02:40:00, c2_to_exfil 660 s, exfil_to_lateral 1800 s, supporting roles 5, exclusion_summary ทุกค่า 0", "→ อ่าน `investigation_candidates[0]` ให้ครบ: asset, ip, ช่วงเวลา sequence, ช่องว่างเวลาระหว่างระยะ, supporting roles, exclusion_summary"),
 ("(จะเห็นว่า contract ผูกค่าคงที่: canonical_sha256 `8d98cfda…`, case_id, asset-066, priority high, disposition needs-review)", "(ดูว่า contract ผูกค่าคงที่อะไรไว้บ้าง และค่าใดที่ไม่ได้มาจาก input)"),
 ("skill = **parse-security-investigation-report**, parser = coherent-pcap-investigation-report-json-v2 → code_sha256 `160f6057…`", "ด้วย skill ของ parser ที่อ่าน investigation report (หาด้วย `log_skill_resolve` หรือ `log_skill_search` ไม่ใช่ workflow skill ตามบทเรียน lab 2) → code_sha256"),
 ("(policy security-investigation-handoff-spark-job-v1: ต้องมี \"not a confirmed incident or compromise\", ห้าม requests/http)", "(อ่าน policy ที่ใช้ตรวจว่าบังคับให้มีประโยคใด และห้ามอะไร)"),
 ("— handoff ให้แค่ needs-review;", "— ดู disposition ที่ handoff ให้;"),
 ("template v2 ผูกค่าคงที่กับ asset-066 —", "template v2 ผูกค่าคงที่กับ asset ตัวเดียว —"),
 ("ทั้งที่ verdict คือ rule-hit และ disposition คือ needs-review", "ทั้งที่ verdict และ disposition ใน report ไม่ได้บอกเช่นนั้น"),
 ("- นับ corroboration จำลอง (firewall_sim) เป็นหลักฐานอิสระ", "- นับ corroboration ที่ `simulation: true` เป็นหลักฐานอิสระ"),
],
"lab3c-baseline.md": [
 ("| ภาพรวมทั้งไฟล์: 201 host ต้นทาง, 207 ปลายทาง, 6 พอร์ต |", "| ภาพรวมทั้งไฟล์: จำนวน conn, ช่วงเวลา, host ต้นทาง/ปลายทาง, พอร์ต |"),
 ("| พอร์ต 80 มี 200 host; พอร์ตอื่นทั้งหมดมาจาก host เดียว |", "| พอร์ตใดมี host ต้นทางหลายตัว พอร์ตใดมาจาก host น้อยตัว |"),
 ("| `groups_truncated: true`, 201 กลุ่ม แต่ได้มา 100 — **host ผิดปกติไม่อยู่ในนี้** |", "| อ่าน `group_count` และ `groups_truncated` ก่อนสรุป — ได้มาครบทุกกลุ่มไหม |"),
 ("| `cidr_filters` {id.orig_h: 10.70.20.0/22}, …24.0/22, 28.0/22, 32.0/22, 36.0/22 | baseline ครบ 200 host ทีละ 40 |", "| `cidr_filters` แบ่งช่วง IP ให้แต่ละก้อนไม่เกิน 100 host | baseline ครบทุก host ทีละก้อน |"),
 ("(ขอ 201 จะได้ error `max_groups 1..100`) และกลุ่มเรียงตาม count มากไปน้อย ดังนั้น host ที่มี connection **น้อยกว่า** เครื่องปกติจะหลุดจาก 100 อันดับแรกเสมอ ต้องแบ่งถามด้วย CIDR", "(ขอเกินจะได้ error `max_groups 1..100`) และกลุ่มเรียงตาม count มากไปน้อย ผู้เรียนต้องคิดเองว่า host แบบไหนจะหลุดจาก 100 อันดับแรก และจะถามอย่างไรให้ครบทุก host"),
 ("mean จะโดนลากขึ้นเป็น 58,163 (×2) และ stddev จะพังทันที", "mean และ stddev จะเปลี่ยนไปมาก (ลองคำนวณทั้งสองแบบ)"),
 ("ตารางข้างบนแสดงว่าตัวที่คนมักเลือกก่อน (connection count) เป็นตัวเดียวที่พลาด", "ตารางที่ทำเองจะบอกว่า metric ที่คนมักเลือกก่อนจับได้หรือไม่"),
 ("ชุดนี้ baseline แคบมาก (57 byte) จนทุกวิธีให้คำตอบเดียวกัน", "ถ้า baseline แคบมากจนทุกวิธีให้คำตอบเดียวกัน"),
 ("6 MB ออกใน 20 นาทีอาจเป็น backup agent ก็ได้", "byte ออกจำนวนมากในเวลาสั้นอาจเป็น backup agent ก็ได้"),
 ("\"ไม่พบ outlier ทุกเครื่องส่งประมาณ 28 KB\"", "\"ไม่พบ outlier ทุกเครื่องส่งใกล้เคียงกัน\""),
 ("- ขอ `max_groups` 201 แล้วเจอ error", "- ขอ `max_groups` เกิน 100 แล้วเจอ error"),
 (" (เกิดจริงตอนรันเฉลย)", ""),
],
"lab4-enrich.md": [
 ("ตรวจ license ของ feed (Feodo CC0; KEV public domain)", "ตรวจ license ของ feed จากหน้าของผู้ให้ feed เอง"),
],
"lab5-report.md": [
 ("อ่าน report ที่ /module7/lab2-ids/report", "อ่าน report ที่ /m6-10/<ชื่อ>/lab2-ids/report"),
 ("→ ไฟล์ PDF ในโฟลเดอร์ module6/10-claude-mcp-labs/outputs/", "→ ไฟล์ PDF ในโฟลเดอร์งานของผู้เรียน"),
 ("- นิยามนาฬิกา: MTTD/MTTR คำนวณไม่ได้จากชุดนี้เพราะไม่มี ticket — ต้องบอกผู้บริหารว่ารายงานนี้ไม่มี metric นั้น", "- นิยามนาฬิกา: ดูว่าชุดข้อมูลมีเวลาเปิด/ปิด ticket หรือไม่ แล้วตัดสินว่ารายงานนี้ให้ MTTD/MTTR ได้ไหม และบอกผู้บริหารตามนั้น"),
],
}

README = """# ฉบับผู้เรียน M6.10 — SOC Automation ด้วย Claude + MCP

ไฟล์ในโฟลเดอร์นี้สร้างจากไฟล์ของผู้สอนด้วย `make_student.py` **อย่าแก้ด้วยมือ** โครงเดียวกับฉบับผู้สอนทุกส่วน ยกเว้นส่วน "เฉลย" ถูกแทนด้วย "บันทึกคำตอบ" ให้กรอกเอง ศัพท์ที่ไม่คุ้นดูใน [glossary](../../../docs/glossary.md)

## วิธีใช้ทีละ lab

1. **อ่าน "โจทย์"** ว่า lab นี้ปิด gap อะไรของ SOC
2. **พิมพ์ prompt แรก** ตามส่วน "prompt ที่ผู้เรียนพิมพ์" ใน Claude Desktop ที่ต่อ MCP ทั้งสองตัว เปลี่ยน `<ชื่อ>` เป็นชื่อตัวเองทุกครั้ง (namespace `/m6-10/<ชื่อ>/`) เพราะ Spark เขียนแบบ `errorifexists` ทับของคนอื่นไม่ได้
3. **ดู tool ที่ Claude เรียก** เทียบกับ "ลำดับ tool ที่ควรเห็น" ถ้า Claude ตอบโดยไม่เรียก tool หรือข้ามขั้น ให้สั่งใหม่ และจดลงส่วน "Claude ผิดตรงไหนได้บ้าง" ว่าเกิดข้อใดจริง
4. **พิมพ์คำถามใน "คำถามที่ถาม Claude ต่อ" ทีละข้อ** เหมือนถามเพื่อนร่วมทีม ไม่ต้องไปค้นเอง แต่ทุกคำตอบต้องอ้าง tool และฟิลด์ (คอลัมน์ "คำตอบต้องอ้างอะไร" บอกว่าควรเป็นอะไร) ถ้า Claude ตอบลอย ๆ ให้สั่ง "อ่านจาก tool แล้วบอกฟิลด์ที่ใช้"
5. **กรอก "บันทึกคำตอบ"** ทีละข้อ: Claude ตอบว่าอะไร อ้างอะไร และคุณตรวจแล้วตรงไหม อย่างน้อย 1 ข้อต่อ lab ต้องเทียบตัวเลขกับ output ดิบด้วยตาตัวเอง (เช่น เปิด report JSON ด้วย `hdfs_read_text` แล้วดูค่าเอง) ข้อประเภท **ตัดสิน** Claude เสนอได้ แต่คำตัดสินและเหตุผลต้องเป็นของคุณ
6. **ทำ "จุดที่คนต้องทำ"** ข้อเหล่านี้ Claude ทำแทนไม่ได้ (อนุมัติ, ตรวจ sha256, ตัดสิน confirm/dismiss, นิยาม baseline) เขียนคำตัดสินและเหตุผลไว้ท้าย "บันทึกคำตอบ"
7. **ส่งไฟล์ lab ที่กรอกแล้ว** (markdown ทั้งไฟล์) ให้ผู้สอนตรวจกับส่วน "เฉลย" ของไฟล์ชื่อเดียวกันในโฟลเดอร์แม่

## กติกาการตอบ

- ตัวเลขทุกตัวต้องมาจากผลของ tool ไม่รับตัวเลขที่ Claude "ประเมิน" หรือสรุปเองโดยไม่มี tool รองรับ และห้ามเอาคำถามทั้งตารางยัดใส่ prompt แรกให้ Claude ตอบรวดเดียว ต้องถามทีละข้อแล้วตรวจทีละข้อ
- ไม่เชื่อผล Spark job จนกว่า `spark_job_status` คืน `SUCCEEDED` และ report ต้องผ่าน `log_skill_validate_report`
- ข้อที่เป็นการตัดสินใจ (นิยาม "ปกติ", threshold, confirm/dismiss, เรียกว่า incident ได้หรือยัง) ไม่มีคำตอบตายตัว แต่ต้องอ้างตัวเลขที่ค้นได้
- เมื่อ Claude สรุปว่า "ถูกโจมตี" ให้ย้อนดูว่า tool คืน `interpretation: no incident verdict` หรือไม่ แล้วแก้คำสรุปให้ตรงกับหลักฐาน

## ลำดับทำ (ครึ่งวัน)

| ลำดับ | lab | เวลา | จำนวนคำถาม |
| --- | --- | --- | --- |
{rows}

lab 2b ต้องผ่าน lab 2 ก่อน (ใช้ Parquet ของตัวเอง) lab 3c และ 3b ต่อจาก lab 3 lab 5 ใช้ report จาก lab 2 ของตัวเอง

[กลับโฟลเดอร์ผู้สอน](../README.md)
"""

def convert(name: str) -> tuple[str, str, int]:
    text = (HERE / name).read_text(encoding="utf-8")
    parts = re.split(r"(?m)^(?=## )", text)
    head, secs = parts[0], parts[1:]
    qsec = next(s for s in secs if s.startswith("## คำถามที่ถาม Claude ต่อ"))
    n = len(re.findall(r"(?m)^\| \d+ \|", qsec))
    out = [head]
    for s in secs:
        if s.startswith("## เฉลย"):
            rows = "\n".join(f"| {i} | | | |" for i in range(1, n + 1))
            out.append("## บันทึกคำตอบ\n\nกรอกทีละข้อตามเลขในตาราง \"คำถามที่ถาม Claude ต่อ\" "
                       "คอลัมน์ 2 คือสิ่งที่ Claude ตอบ (ย่อได้ แต่ตัวเลขต้องตรง) คอลัมน์ 3 คือ tool และฟิลด์ที่ Claude อ้าง "
                       "ถ้า Claude ไม่อ้าง ให้สั่งถามใหม่ก่อนกรอก คอลัมน์ 4: ข้อประเภท ตรวจ ให้เขียนว่าเทียบกับ output ดิบแล้วตรงไหม "
                       "(อย่างน้อย 1 ข้อต่อ lab ต้องเทียบจริง) ข้อประเภท ตัดสิน ให้เขียนคำตัดสินของตัวเองและเหตุผล\n\n"
                       "| # | Claude ตอบว่า | อ้าง tool → ฟิลด์ | ตรวจแล้วตรงไหม / ตัดสินว่าอย่างไร |\n| --- | --- | --- | --- |\n" + rows + "\n\n")
            continue
        if s.startswith("## คำถามที่ถาม Claude ต่อ"):
            s = s.replace(" คำตอบที่คาดอยู่ในส่วนเฉลยด้านล่าง", " บันทึกในส่วน \"บันทึกคำตอบ\" ด้านล่าง")
        out.append(s)
    t = "".join(out)
    t = re.sub(r" — ร่าง( ยังไม่ได้รัน)?$", "", t, count=1, flags=re.M)
    t = re.sub(r" · \*\*สถานะ\*\* ⏳ ร่าง[^\n]*", "", t)
    for old, new in REPLACE.get(name, []):
        if old not in t:
            sys.exit(f"{name}: ไม่พบข้อความที่ต้องแทน (ไฟล์ผู้สอนเปลี่ยน ต้องแก้ REPLACE): {old[:60]}")
        t = t.replace(old, new)
    title = t.splitlines()[0].lstrip("# ").strip()
    return t, title, n

def main() -> None:
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.md"):
        old.unlink()
    rows = []
    for i, name in enumerate(ORDER, 1):
        t, title, n = convert(name)
        (OUT / name).write_text(t, encoding="utf-8")
        short = title.split(" — ")[0]
        rows.append(f"| {i} | [{short} {title.split(' — ', 1)[1].split(':')[0]}]({name}) | {TIME[name]} | {n} |")
        print(f"{name}: {n} คำถาม")
    (OUT / "README.md").write_text(README.replace("{rows}", "\n".join(rows)), encoding="utf-8")
    print("student/README.md")

if __name__ == "__main__":
    main()
