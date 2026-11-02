# M5.2 Log Analysis Automation

**ความเกี่ยวข้องกับ log analysis:** ระดับ 1 — log analysis โดยตรง (หัวข้อแกนของทั้ง Module 5 และ 6)

- รับอินพุตจาก: M5.1 (regex, Counter, deque, CLI)
- ส่งต่อให้: M6.2 ใช้ schema ECS/OCSF เดียวกันในการ normalize alert; M6.4 วัด visibility coverage จาก data source ที่ parse ได้

รายละเอียดเต็ม (แหล่งต้นฉบับ, งานเขียนในชุมชน, โค้ด, references): [รายงาน research ส่วนที่ 2](../../docs/python-security-automation-research.md)

## บทอ่านประกอบ

- [combined log กับการรวม log ใน SIEM คนละเรื่องกัน](reading-combined-log-vs-siem.md) อธิบายความต่างระหว่างชื่อรูปแบบ combined ของ web log กับการรวม log หลายแหล่งใน SIEM และเหตุใด M5.2 จึงจบที่ ECS/OCSF

## แหล่งต้นฉบับ

- RFC 5424 The Syslog Protocol (PRI = facility×8 + severity)
- Apache `mod_log_config` (common/combined) และ nginx `ngx_http_log_module` (`escape=json`)
- Windows EVTX ตาม spec ของ libevtx (Joachim Metz)
- ArcSight CEF Implementation Standard และ IBM LEEF
- Elastic Common Schema 9.5.0 และ OCSF 1.9.0 (Linux Foundation ตั้งแต่ พ.ย. 2024)
- NIST SP 800-92 Rev. 1 (initial public draft ต.ค. 2023 ยังไม่ final)
- งานวิชาการ: Drain (ICWS 2017), loglizer (ISSRE 2016), DeepLog (CCS 2017), Loghub (ISSRE 2023), Elastic beaconing framework (2023)

## งานเขียนและเครื่องมือยอดนิยมในชุมชน security

จำนวนดาว GitHub เป็นค่าโดยประมาณ ณ 2026-11-01

- python-evtx (≈786), pyevtx-rs, Plaso (≈2.2k)
- pySigma (≈604) และ sigma-cli (≈220)
- Drain3 (≈904), loglizer (≈1.4k), loghub (≈2.9k), awesome-log-analysis (≈810)
- ZAT (≈456), RITA (≈667) สำหรับ Zeek และ beacon
- Chainsaw (≈3.7k) และ Hayabusa (≈3.4k) ไว้เปรียบเทียบ (Rust)

## ตัวอย่างโค้ด (ระดับ 2: แยกเป็นไฟล์และ smoke-test แล้ว)

โค้ดคัดจากรายงานโดยไม่แก้ตรรกะ ยกเว้น 2.2b ที่แก้บรรทัด import หนึ่งบรรทัด (ระบุไว้ใน header ของไฟล์) ทุกไฟล์มี header บอกที่มาและสถานะ

```bash
./run_smoke_tests.sh        # สร้าง .venv (+ .venv-evtx) และรันทุกตัวอย่างกับ samples/
```

| ตัวอย่าง | ไฟล์ | sample | ผล smoke-test (2026-11-02, Python 3.12.7, pandas 3.1.0) |
| --- | --- | --- | --- |
| 2.1 | `2_1_authlog_bruteforce.py` | `samples/auth.log` | ผ่าน: ตรวจพบ 203.0.113.9 (5 failures ใน 60 s) และไม่เตือน IP ที่ล้มเหลวแบบกระจาย |
| 2.2 | `2_2_evtx_failed_logon.py` | ไม่มี .evtx ใน repo | compile และ import python-evtx 0.8.1 ผ่าน ยังไม่ได้รันกับไฟล์จริง |
| 2.2b | `2_2b_evtx_rs_eventid_counts.py` | ไม่มี .evtx ใน repo | compile ผ่านหลังแก้ import (ดูข้อค้นพบ) ยังไม่ได้รันกับไฟล์จริง |
| 2.3 | `2_3_syslog_to_pandas.py` | `samples/syslog.log` | ผ่าน: นับ app และ resample severity ≤ 3 ต่อ 5 นาทีได้ แต่มีข้อควรระวังเรื่องปี (ดูข้อค้นพบ) |
| 2.4 | `2_4_drain3_templates.py` | `samples/syslog.log` | ผ่าน: Drain3 0.9.11 สร้าง 13 template และจัดบรรทัด "possible exploit attempt" เป็น template หายากอันดับ 1 |
| 2.5 | `2_5_pysigma_convert.py` | rule ฝังในไฟล์ | ผ่าน: pySigma 2.0.2 + backend-splunk 3.0.0 ให้ `EventID=1 Image="*\\whoami.exe"` |
| 2.6 | `2_6_zeek_beacon_candidates.py` | `samples/conn.log` | ผ่าน: ZAT 0.4.9 พบ 10.0.0.25 → 203.0.113.200:443 (40 conns, gap 60 s, CV 0.011) และไม่พบคู่ที่ jitter |
| 2.7 | `2_7_access_log_pandas.py` | `samples/access.log` | ผ่าน: พบ scanner 203.0.113.50 (404 rate 0.91), user agent หายาก 6 ตัว, hot spot 500 ที่ /api/items |

sample ทั้งสี่ไฟล์เป็นข้อมูลสังเคราะห์ (IP ในช่วง TEST-NET) ที่ฝังสิ่งให้ตรวจพบไว้ชัดเจน ไม่ใช่ log จริง

### ข้อค้นพบจาก smoke-test ที่รายงาน research ไม่ได้ระบุ

1. **2.2b import path ในรายงานใช้ไม่ได้กับ evtx 0.15.0**: รายงานเขียน `from evtx.parser import PyEvtxParser` แต่แพ็กเกจปัจจุบัน export ที่ top-level จึงต้องใช้ `from evtx import PyEvtxParser` ทดสอบใน venv ที่ติดตั้ง evtx อย่างเดียว
2. **python-evtx และ pyevtx-rs ติดตั้งร่วม venv บน macOS ไม่ได้**: python-evtx ติดตั้งเป็นโฟลเดอร์ `Evtx/` ส่วน pyevtx-rs เป็น `evtx/` บน APFS แบบ case-insensitive (และ Windows) สองโฟลเดอร์รวมเป็นอันเดียว ทำให้ `import evtx` ล้มเหลวด้วย ModuleNotFoundError ทั้งที่ pip แสดงว่าติดตั้งแล้ว จึงแยกเป็น `requirements-evtx-rs.txt` และ `.venv-evtx`
3. **2.3 บรรทัด syslog แบบดั้งเดิม (ไม่มีปี) ได้ปี 0001**: `pd.to_datetime(..., format="mixed")` ใน pandas 3.1 ตีความ `Mar  1 08:00:30` เป็นปี 1 ไม่ใช่ปีปัจจุบัน บรรทัด RFC 5424 ไม่กระทบ ควรเติมปีก่อน parse (เหมือนที่ 2.1 ทำด้วย `YEAR`) เหมาะเป็นแบบฝึกหัดให้ผู้เรียนแก้ โค้ดในไฟล์คงไว้ตามรายงาน
4. **2.4 ออกแบบมาสำหรับ syslog แบบดั้งเดิม**: การตัด header ด้วย `line.split(": ", 1)` ไม่ตัด header ของบรรทัด RFC 5424 ทำให้ข้อความเดียวกันถูกแยกเป็นสอง template (มีและไม่มี header) ใน sample ที่ผสมสองรูปแบบ ควร parse header ด้วย regex จาก 2.3 ก่อนส่งเข้า Drain3
5. **2.2 ยังไม่ได้รันกับไฟล์จริง** เพราะไม่มี .evtx ใน repo ผู้สอนควรหาไฟล์ตัวอย่าง (เช่นจาก test suite ของ python-evtx หรือเครื่อง Windows ในแล็บ) มารันก่อนใช้สอน

### รายการตัวอย่าง

- ตัวอย่าง 2.1 ตรวจ burst ของ failed login ใน auth.log (sliding window)
- ตัวอย่าง 2.2 อ่าน EVTX ด้วย python-evtx ดึง Event ID 4625
- ตัวอย่าง 2.3 syslog (RFC 5424 และแบบดั้งเดิม) → pandas resample
- ตัวอย่าง 2.4 template mining ด้วย Drain3
- ตัวอย่าง 2.5 แปลง Sigma rule ด้วย pySigma
- ตัวอย่าง 2.6 Zeek conn.log → pandas หา beacon ด้วย ZAT
- ตัวอย่าง 2.7 access log → pandas: อัตรา 404 ต่อ IP, รายชั่วโมง, user agent หายาก

## หมายเหตุจากการค้นคว้า

ลำดับการสอนที่ research เสนอ: raw text (syslog, combined) → binary (EVTX) → vendor interchange (CEF) → normalization (ECS/OCSF) และให้ผู้เรียน map record ใด ๆ เข้า field ของ ECS/OCSF ได้ threshold ในตัวอย่าง (5 ครั้ง/60–300 วินาที, CV < 0.3) เป็นธรรมเนียมของชุมชน ไม่ใช่มาตรฐาน
