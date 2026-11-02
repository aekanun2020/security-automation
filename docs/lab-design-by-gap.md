# Lab design ตาม gap (G1–G6) สำหรับ Module 5–6

ออกแบบ lab จาก "ช่องว่างที่มีหลักฐานว่ามีอยู่จริงใน SOC ที่มี SIEM สำเร็จรูปแล้ว" ไม่ใช่ไล่ตามหัวข้อใน course outline หัวข้อของ outline ยังอยู่ครบแต่ถูกใช้เป็นคลังทักษะที่แต่ละ lab ดึงไปใช้ เอกสารนี้ต่อยอดจากสามแหล่งใน repo นี้

- หลักฐานของ gap และตัวอย่างโค้ด: [python-security-automation-research.md](python-security-automation-research.md)
- ชุดข้อมูลจริงที่เลือกให้แต่ละ lab และรูปแบบ QRadar: [datasets-for-gap-labs.md](datasets-for-gap-labs.md)
- บริบทผู้เรียน (NT cyfence ใช้ IBM QRadar และ McAfee/Trellix ESM): [nt-siem-landscape.md](nt-siem-landscape.md)
- คำย่อและชื่อเฉพาะทุกคำในเอกสารนี้: [glossary.md](glossary.md)

ข้อมูลทั้งหมด ณ 2026-11-02 ตัวเลขที่ใช้ตั้งโจทย์มาจากแหล่งที่อ้างในรายงานข้างต้น ไม่มีตัวเลขใดเป็นมาตรฐาน

## หลักการออกแบบ

1. **ทุก lab เริ่มจากตัวเลข "ก่อน" และจบด้วยตัวเลข "หลัง"** (จำนวน alert, % false positive, ชั่วโมงที่ใช้ทำรายงาน, % coverage) ตาม MITRE 11 Strategies ข้อ 10 และ SOC-CMM Metrics 101 ผู้เรียนกลุ่มที่ทำ SIEM มานานจะเห็นคุณค่าจากตัวเลขนี้
2. **output ต้องเป็น QRadar-shaped โดยไม่ต้องมี QRadar ในห้อง**: emit เป็น LEEF 2.0, query เป็น AQL, ticket ตาม schema ของ offense ผู้เรียนที่มี QRadar Community Edition (ฟรี, 100 EPS) ทดสอบจริงได้ที่บ้าน
3. **ใช้ข้อมูลจริงเมื่อมี และสร้างข้อมูลสังเคราะห์แบบ parameterized เมื่อไม่มี** โดยระบุให้ผู้เรียนรู้ว่าตัวเลขพารามิเตอร์มาจากไหน
4. **deterministic ก่อน ML**: ทุก lab ทำแบบ rule-based ให้ได้ก่อน แล้วค่อยถามว่า ML หรือ AI เพิ่มอะไร (G6 เป็นที่เดียวที่เปรียบเทียบตรง ๆ)
5. **ทักษะตั้งบน open schema** (RFC 5424, ECS/OCSF, LEEF, Sigma, STIX, Navigator layer) เพราะผู้ผลิตเปลี่ยนตลอด: QRadar SaaS ถูกขายและหมดอายุ เม.ย. 2026, McAfee SIEM กลายเป็น Trellix

## ภาพรวม

| lab | gap | หลักฐานว่า gap มีจริง | ชุดข้อมูลหลัก | ตัวเลขก่อน/หลัง | ทักษะจาก outline |
| --- | --- | --- | --- | --- | --- |
| L1 | G1 log ที่ SIEM ไม่มี parser | SANS 2025: 42% dump data ลง SIEM โดยไม่มีแผน | SecRepo nginx, Loghub Linux/OpenSSH, EVTX-to-MITRE-Attack, Cowrie | % บรรทัดที่ parse ได้และ map เข้า LEEF/ECS ครบฟิลด์ | M5.1, M5.2 |
| L2 | G2 alert overload | Critical Start: เกือบครึ่งของ SOC มี FP ≥ 50% | Microsoft GUIDE (alert จริง 1.6M + label TP/FP/BP) | จำนวน alert ที่ถึง analyst และ TP ที่หลุด | M6.2, M6.4 |
| L3 | G3 enrichment ทำมือ | NT cyfence ระบุแผนพัฒนาเครื่องมือ automation (2022) | KEV, NVD, EPSS, Feodo, Spamhaus DROP, Tor, InternetDB, ip-api, ATT&CK TAXII (ไม่ต้องมี key) | นาทีต่อ alert ก่อน/หลัง และ % alert ที่ได้ context ครบ | M5.3, M5.4, M5.5 |
| L4 | G4 รายงานทำมือ | SANS 2025: 69% รายงาน metrics ด้วยมือ | UCI ServiceNow incident log + synthetic offense export | ชั่วโมงทำรายงานต่อสัปดาห์ | M6.3, M6.4 |
| L5 | G5 detection ล็อกกับ vendor | QRadar SaaS EOL เม.ย. 2026; McAfee → Trellix | SigmaHQ + pySigma QRadar AQL backend + OTRF Security-Datasets | % ATT&CK coverage และจำนวน rule ที่ย้าย backend ได้ | M5.2, M6.4, M6.3 |
| L6 | G6 AI/ML ใช้แบบไม่ปรับ | SANS 2025: 42% ใช้ AI/ML out of the box และพึงพอใจต่ำสุด | Loghub HDFS_v1 (+ HDFS_100k), BGL | precision/recall ของ rule เทียบ ML | M5.2 |

ลำดับที่แนะนำ: L1 → L3 → L2 → L4 → L5 → L6 (L1 เป็นฐานของทุก lab; L3 ก่อน L2 เพราะ score ใน L2 ใช้ผล enrichment; L5–L6 ต้องการความคุ้นเคยกับ pipeline แล้ว) ปรับลำดับใหม่ได้หลังได้ผลแบบสอบถามท้ายเอกสาร

---

## L1 — log แปลกเข้า QRadar (G1)

**โจทย์** ทีมได้รับ log จากระบบที่ QRadar ไม่มี DSM ให้ สามรูปทรง: combined access log, BSD syslog/auth.log, และ EVTX ต้องทำให้ทุกบรรทัดกลายเป็น event ที่ QRadar อ่านได้

**ชุดข้อมูล** (รายละเอียดและ license ในรายงาน datasets ส่วน G1)
- SecRepo `self.logs` nginx access log จริง (CC BY 4.0) https://www.secrepo.com/
- Loghub `Linux` และ `OpenSSH` จาก Zenodo record 8196385 (CC-BY-4.0, ดาวน์โหลดตรง)
- mdecrevoisier/EVTX-to-MITRE-Attack (CC0, อัปเดต 2026) สำหรับ EVTX
- CyberLab Cowrie honeypot JSON (Zenodo 3687527, CC-BY-4.0) เป็นโบนัสรูปทรง JSON
- สำรอง: Harvard Dataverse nginx (CC0), sbousseaden/EVTX-ATTACK-SAMPLES, SecRepo honeypot.json

**ขั้นตอน**
1. วัด "ก่อน": นับบรรทัดทั้งหมดและบรรทัดที่ regex เบื้องต้น (ตัวอย่าง 1.1, 2.1) จับได้ บันทึก % ที่ parse ไม่ได้
2. เขียน parser ต่อรูปทรง (regex จาก 1.1/2.1/2.3, python-evtx จาก 2.2) ให้ได้ dict ต่อ event
3. map เข้า ECS (source.ip, user.name, event.outcome, http.response.status_code, …) ตามตัวอย่าง 2.3/2.7 แล้ว emit เป็น **LEEF 2.0** หนึ่งบรรทัดต่อ event ใช้ `devTime` แบบ epoch 13 หลักเพื่อไม่ต้องใส่ `devTimeFormat` (รูปแบบ header และ attribute ตามเอกสาร IBM ที่คัดไว้ในรายงาน datasets)
4. ตรวจความถูกต้องด้วย test: จำนวน event เข้า = ออก, ฟิลด์บังคับไม่ว่าง, timestamp parse ได้ทุกบรรทัด (บทเรียนจาก smoke-test 2.3 เรื่องปี 0001)
5. วัด "หลัง": % บรรทัดที่ map ได้ครบ และรายการฟิลด์ที่ map ไม่ได้ (เป็น backlog ให้ DSM)
6. (ถ้ามี QRadar CE) ส่ง LEEF ผ่าน syslog แล้วดูว่า auto-discovery สร้าง log source หลังประมาณ 25 event ตามเอกสาร IBM

**ส่งมอบ** `parse_*.py`, `to_leef.py`, ไฟล์ LEEF ตัวอย่าง, รายงาน coverage ของฟิลด์

**ข้อควรระวัง** Loghub "Windows" เป็น CBS.log ไม่ใช่ EVTX; ไม่มี LEEF corpus สาธารณะ เป้าหมายต้องยึดเอกสาร IBM; ไม่มี dataset RFC 5424 แท้ ๆ ถ้าต้องการให้สร้างจาก BSD ด้วยสคริปต์

---

## L2 — ลด alert ก่อนถึงคน (G2)

**โจทย์** ได้รับ alert stream ที่มีซ้ำและ false positive มาก ต้องออกแบบ fingerprint, sliding-window dedupe และ composite score แล้วพิสูจน์ด้วยตัวเลขว่าลดภาระโดยไม่ทิ้ง true positive

**ชุดข้อมูล**
- หลัก: Microsoft GUIDE (Kaggle) alert จริง 1.6M รายการ, 1M incident, label `IncidentGrade` = TP/BP/FP, มี `DetectorId`, `AlertTitle`, `MitreTechniques`, entity (IP, SHA256, URL, account) อ้างอิง arXiv 2407.09017
- สำรอง: AIT-ADS (Zenodo 8263181, CC BY 4.0, 96 MB) alert 2.66M จาก Wazuh/Suricata/AMiner พร้อม label ตาม attack phase
- ไม่มี QRadar offense export สาธารณะ ให้ใช้ schema ของ `/api/siem/offenses` (ในรายงาน datasets) เป็นรูปแบบ output

**ขั้นตอน**
1. วัด "ก่อน": alert ต่อวัน, สัดส่วน TP/BP/FP, จำนวน DetectorId ที่สร้าง alert มากสุด 10 อันดับ (ตัวอย่าง 9.3)
2. ออกแบบ fingerprint = hash(DetectorId, entity หลัก, ปลายทาง) ตามแนวในรายงาน research ส่วน M6.2 แล้ว dedupe ใน sliding window (ตัวอย่าง 7.2) ทดลอง window 5/15/60 นาที
3. สร้าง composite score จาก severity ของ detector, ความถี่ของ entity, และผล enrichment จาก L3 (KEV/EPSS/DROP/Feodo)
4. วัด "หลัง": alert ที่ถึง analyst ลดกี่ % และ **TP ที่ถูก dedupe หรือ score ต่ำจนหลุด** กี่ % (ต้องรายงานทั้งสองค่า)
5. normalize ผลเป็น OCSF Detection Finding (ตัวอย่าง 7.1) และ map เป็นฟิลด์ offense ของ QRadar

**ส่งมอบ** `dedupe_score.py`, ตารางผลต่อ window, กราฟ TP-loss vs reduction

**ข้อควรระวัง** label BP ของ GUIDE มี noise; ขนาดไฟล์บน Kaggle ยืนยันไม่ได้ ควรเตรียม subset ไว้ให้ผู้เรียน; ตัวเลข window 5–15 นาทีในวงการมาจากผู้ผลิตรายเดียว ให้ผู้เรียนทดลองเอง

---

## L3 — enrich อัตโนมัติ (G3)

**โจทย์** alert หนึ่งรายการมี IP, โดเมน, hash, CVE ต้องได้ context ครบภายในไม่กี่วินาทีโดยไม่ต้องเปิดเว็บทีละอัน และทนต่อ rate limit

**ชุดข้อมูล/แหล่ง** (ทั้งหมดเรียกจริงแล้วเมื่อ 2026-11-02 โดยไม่ต้องมี key)
- CVE: CISA KEV JSON, NVD CVE API 2.0 (คืน CVSS และฟิลด์ `cisaExploitAdd`), FIRST EPSS API
- IP: abuse.ch Feodo Tracker (CC0), Spamhaus DROP, Tor exit list, Shodan InternetDB, ip-api (45/นาที, มี header `X-Rl`/`X-Ttl` และตอบ 429)
- โดเมน: Tranco top-1M เป็น baseline ความ benign
- TTP: MITRE ATT&CK ผ่าน TAXII 2.1 (50 req/10 นาที)
- สำรองที่ต้องสมัคร key ฟรีรายคน: AbuseIPDB (1,000/วัน), VirusTotal (500/วัน, 4/นาที), OTX
- หลีกเลี่ยง: URLhaus/ThreatFox/MalwareBazaar ต้อง Auth-Key ตั้งแต่ 30 มิ.ย. 2025 และ URL เก่าคืน 410; GreyNoise ใช้ในห้องเรียนไม่ได้

**ขั้นตอน**
1. วัด "ก่อน": จับเวลา analyst enrich alert หนึ่งรายการด้วยมือ (เปิด 4–5 เว็บ) บันทึกนาที
2. ดาวน์โหลด feed แบบไฟล์ (KEV, Feodo, DROP, Tor, Tranco) ครั้งเดียวแล้ว hit-test offline ด้วย pandas (ตัวอย่าง 4.4, 5.8)
3. เรียก API แบบ online (NVD, EPSS, ip-api, InternetDB) ผ่าน `requests.Session` + `Retry` ที่เคารพ `Retry-After` (ตัวอย่าง 4.1, 4.2) เก็บ secret ด้วย pydantic-settings (3.5) และตั้งเวลา refresh feed ด้วย `schedule` (3.4)
4. ประกอบเป็นฟังก์ชัน `enrich(alert) -> dict` ที่ให้ผล deterministic และ cache ผลซ้ำ
5. วัด "หลัง": วินาทีต่อ alert, % alert ที่ได้ context ครบ, จำนวนครั้งที่ชน 429 และ retry สำเร็จ
6. ส่งผล enrichment เข้า L2 เป็น input ของ composite score

**ส่งมอบ** `enrich.py`, `feeds/` พร้อมวันที่ดาวน์โหลด, ตารางเวลาก่อน/หลัง

**ข้อควรระวัง** ตัวเลข rate limit ของ NVD (5/50 ต่อ 30 วินาที) ยืนยันจากหน้าทางการไม่ได้; ip-api เป็น HTTP และห้ามใช้เชิงพาณิชย์; ห้ามให้ผู้เรียนใส่ key จริงลง repo

---

## L4 — รายงานรายสัปดาห์จาก export (G4)

**โจทย์** ทำรายงาน MTTD/MTTA/MTTR, FP ต่อ rule และ SLA จาก export ให้เสร็จด้วยคำสั่งเดียวทุกสัปดาห์

**ชุดข้อมูล**
- หลัก: UCI "Incident management process enriched event log" (ServiceNow จริง, CC BY 4.0, 24,918 incident, timestamp `opened_at → sys_created_at → resolved_at → closed_at`, `priority`, `made_sla`, `reassignment_count`) สำหรับกลไก lifecycle
- คู่กัน: GUIDE สำหรับ FP-rate ต่อ `DetectorId`
- สำรองและใกล้ QRadar ที่สุด: **synthetic offense/ticket generator แบบ parameterized** โดยใช้ตัวเลขที่เผยแพร่: funnel ของ Red Canary (419M lead → 8.5M event → 110k threat จาก 1,700 องค์กร), สัดส่วนของ NCSA (0.01% true attack / 49% benign / 27% attempt) และสัดส่วน TP/FP/BP ของ GUIDE ใช้ schema ของ offense (`id`, `start_time`, `last_updated_time`, `severity`, `magnitude`, `status`, `closing_reason_id`) จากรายงาน datasets
- ไม่มี SOC ticket export จริงที่มี ack/resolve พร้อม disposition เปิดเผยที่ไหน ต้องบอกผู้เรียนตรง ๆ

**ขั้นตอน**
1. วัด "ก่อน": ให้ผู้เรียนทำรายงานสัปดาห์หนึ่งด้วย spreadsheet แล้วจับเวลา
2. นิยาม "นาฬิกา" ให้ชัดก่อนคำนวณ (event time, detect time, ack time, resolve time) ตามตัวอย่าง 9.2 เพราะ SOC-CMM และ SANS ไม่ได้กำหนดตายตัว
3. คำนวณ MTTD/MTTA/MTTR แบบ mean, median, p90 และ weekly resample (9.2), FP-rate ต่อ rule และ ranking สำหรับ tuning (9.3), SLA-breach % จาก `made_sla`
4. render เป็น HTML → PDF ด้วย Jinja2 + WeasyPrint (8.1) พร้อม chart (8.2) และ DOCX สำหรับผู้บริหาร (8.3)
5. ตั้ง scheduled job รายสัปดาห์ (3.4) และ dashboard ด้วย Streamlit (9.4)
6. วัด "หลัง": เวลาที่ใช้ต่อสัปดาห์ และจำนวน metric ที่ได้เพิ่มจากเดิม

**ส่งมอบ** `metrics.py`, template รายงาน, PDF ตัวอย่าง, `generate_synthetic_offenses.py` พร้อมเอกสารที่มาของพารามิเตอร์

**ข้อควรระวัง** UCI log ไม่มี rule name และ disposition จึงต้อง join กับ GUIDE หรือ synthetic; timeline ของ VCDB เป็น duration ไม่ใช่ timestamp จึงไม่เหมาะ; Kibana/Grafana reporting API เป็น internal/unstable จึงดึงข้อมูลดิบมาทำเอง

---

## L5 — detection ที่ไม่ล็อกกับ vendor (G5)

**โจทย์** เขียน detection เป็น Sigma แปลงเป็น AQL ของ QRadar (และ Splunk/Elastic เพื่อพิสูจน์ว่าย้ายได้) ทดสอบกับ telemetry ที่มี label แล้ววัด ATT&CK coverage

**ชุดข้อมูล/เครื่องมือ**
- SigmaHQ/sigma: 3,161 rule, 2,817 มี ATT&CK tag ระดับ technique, license DRL 1.1 (ใช้และแก้ได้พร้อม attribution)
- sigma-cli 4.0.0 + **IBM/pySigma-backend-QRadar-AQL** (MIT, commit ล่าสุด ต.ค. 2026; pipeline `qradar-aql-fields` หรือ `qradar-aql-payload`) และ backend Splunk/Elastic เพื่อเปรียบเทียบ
- telemetry สำหรับทดสอบ: OTRF Security-Datasets (YAML มี `attack_mappings`), EVTX-to-MITRE-Attack (CC0), NextronSystems/evtx-baseline (goodware สำหรับวัด FP)
- coverage: `sigma analyze attack` → Navigator layer, DeTT&CT 2.2.0 (visibility + detection สองแกน), mitreattack-python navlayers

**ขั้นตอน**
1. วัด "ก่อน": รายการ rule ที่ทีมมีใน QRadar (หรือ subset ที่สมมติ) map เป็น technique ด้วยมือแล้วนับ % coverage เทียบ technique ทั้งหมด (9.1)
2. เขียน rule ใหม่ 3–5 ข้อเป็น Sigma จากเหตุการณ์ใน L1/L2 แล้ว `sigma convert -t ibm-qradar-aql -p qradar-aql-payload` (ตัวอย่าง 2.5 สำหรับ Splunk ใช้ pattern เดียวกัน)
3. ทดสอบ rule กับ EVTX ที่มี label (expected positive) และ evtx-baseline (expected negative) ด้วย python-evtx (2.2) นับ TP/FP ต่อ rule
4. สร้าง Navigator layer (8.4) จาก rule ที่ผ่านการทดสอบ และสร้าง DeTT&CT YAML ให้คะแนน visibility ของ data source ที่มีจริงจาก L1
5. วัด "หลัง": % coverage เพิ่มกี่ technique, rule กี่ข้อแปลงได้ทั้งสาม backend โดยไม่แก้, เวลาเขียน rule ต่อข้อ

**ส่งมอบ** โฟลเดอร์ `rules/` (Sigma), `aql/` (ผลแปลง), layer JSON, รายงาน TP/FP ต่อ rule

**ข้อควรระวัง** backend ของ IBM ไม่มี release บน PyPI ใหม่ตั้งแต่ปลายปี 2023 (ติดตั้งจาก GitHub) และต้อง content pack Properties Dictionary บน QRadar จริง; label ATT&CK ของ EVTX เป็นระดับไฟล์ ไม่ใช่ระดับ event; ไลเซนส์ของ OTRF Security-Datasets ขัดแย้งกันระหว่าง LICENSE (MIT) และ README (GPL-3.0); ไม่มีตัวอย่าง AQL ฉบับทางการของ IBM ในรายงาน (403) ให้ใช้ output ของ backend เป็นตัวอย่างที่ valid

---

## L6 — วัดก่อนเชื่อ: rule-based เทียบ classical ML (G6)

**โจทย์** บนข้อมูลที่มี ground truth เดียวกัน rule ที่ analyst เขียนเองทำได้เท่าไร และ ML แบบคลาสสิกทำได้เท่าไร ก่อนจะตัดสินใจเชื่อ AI/ML ที่มากับผลิตภัณฑ์

**ชุดข้อมูล**
- หลัก: Loghub HDFS_v1 (anomaly label ระดับ block) เริ่มจาก HDFS_100k ใน repo loglizer (MIT) แล้วขยายไปไฟล์เต็มบน Zenodo 8196385; BGL (label ต่อบรรทัด) เป็นชุดที่สอง
- benchmark ที่เผยแพร่ให้เทียบ: loglizer รายงาน Decision Tree P/R/F1 ประมาณ 0.998 และ One-Class SVM recall 0.222 บน HDFS
- สำรอง: SR-BH 2020 (web, CC0, label ต่อ request) หรือ CSIC 2010 ถ้าต้องการโดเมน web; OpenStack (5.4 MB) ถ้าเครื่องอ่อน; LANL cyber1 (auth จริง + red team ground truth, ต้องขอทาง email) เป็น stretch goal
- หลีกเลี่ยง AIT-LDS ในห้องเรียนเชิงพาณิชย์ (CC-BY-NC-SA)

**ขั้นตอน**
1. วัด "ก่อน": รัน rule-based จากตัวอย่าง 2.1/2.7 (threshold ที่ผู้เรียนตั้งเอง) บน HDFS_100k คำนวณ precision/recall/F1 เทียบ label
2. ทำ template mining ด้วย Drain3 (2.4) แล้วใช้ Loghub-2.0 (Zenodo 8275861) เป็น ground truth ของ template เพื่อวัด parsing accuracy
3. สร้าง event count matrix แล้วรัน loglizer (Decision Tree, PCA, Isolation Forest) คำนวณ P/R/F1
4. เปรียบเทียบสามแนวทาง (rule, rare-template, ML) ในตารางเดียว พร้อมเวลา train และความอธิบายได้ของผล
5. วัด "หลัง": ผู้เรียนเขียนข้อสรุปหนึ่งย่อหน้าว่าจะเปิดใช้ AI/ML ของผลิตภัณฑ์ในกรณีใด และจะวัดอย่างไร (เชื่อมกลับไป SANS 2025: 42% ใช้แบบไม่ปรับแต่ง)

**ส่งมอบ** notebook เปรียบเทียบ, ตาราง P/R/F1, ข้อสรุป

**ข้อควรระวัง** loglizer มีประวัติเวอร์ชันล่าสุดปี 2019 และ deep-loglizer ไม่ดูแลตั้งแต่ 2023 ควรใช้แค่โมเดลคลาสสิก; license ของ Loghub บน GitHub จำกัด "research or academic work" ขณะที่ Zenodo เป็น CC-BY-4.0 ให้อ้าง Zenodo

---

## สิ่งที่ต้องยืนยันกับผู้เรียนก่อนเริ่ม

1. QRadar ของ NT เป็น on-prem หรือ SaaS (กระทบ L5 และสถานะ EOL) และรุ่นใด (กำหนดค่า header `Version` ของ REST API)
2. ผู้เรียนเข้าถึง export ของ offense/event ได้หรือไม่ ถ้าได้ L2 และ L4 ใช้ข้อมูลจริงขององค์กรแทน GUIDE/UCI ได้ (ต้อง anonymize)
3. McAfee/Trellix ESM ยังใช้งานอยู่หรือไม่ ถ้าใช่ L1 ควร emit CEF เพิ่มจาก LEEF
4. เครื่องผู้เรียนรัน QRadar CE ได้หรือไม่ (RAM 24 GB) ถ้าไม่ได้ L1/L5 จบที่ไฟล์ LEEF/AQL โดยไม่ต้อง ingest จริง
5. งานไหนที่กลุ่ม SIEM เก่าทำมืออยู่จริง เพื่อจัดลำดับ L1–L6 ใหม่

## แบบสอบถาม gap (ส่งก่อนเริ่มหลักสูตร)

ให้คะแนนความเจ็บ 1 (ไม่เป็นปัญหา) ถึง 5 (เป็นปัญหาทุกวัน) และระบุชั่วโมงที่ใช้ทำมือต่อสัปดาห์

| ข้อ | gap | คำถาม | คะแนน 1–5 | ชั่วโมง/สัปดาห์ |
| --- | --- | --- | --- | --- |
| 1 | G1 | มี log แหล่งไหนบ้างที่ SIEM ไม่มี parser ให้ และคุณต้อง parse เองหรือปล่อยทิ้ง | | |
| 2 | G2 | alert ที่คุณปิดเป็น false positive คิดเป็นกี่ % ของทั้งหมด และมี alert ซ้ำจาก rule เดิมบ่อยแค่ไหน | | |
| 3 | G3 | ต่อ alert หนึ่งรายการ คุณเปิดเว็บหรือเครื่องมือกี่ตัวเพื่อหา context (VT, AbuseIPDB, KEV, …) | | |
| 4 | G4 | รายงาน metrics รายสัปดาห์/เดือนทำด้วยวิธีใด ใช้เวลาเท่าไร | | |
| 5 | G5 | rule ที่คุณเขียนอยู่ในรูปแบบใด (AQL, correlation rule ของผลิตภัณฑ์, Sigma) และเคยวัด ATT&CK coverage ไหม | | |
| 6 | G6 | คุณเปิดใช้ AI/ML หรือ UBA ของผลิตภัณฑ์ไหม ปรับแต่งอะไรบ้าง และเชื่อผลมันแค่ไหน | | |

ข้อมูลเพิ่มเติม: ทำงานกับ SIEM มากี่ปี, ใช้ Python ระดับใด (ไม่เคย / อ่านออก / เขียนสคริปต์เองได้), เข้าถึง export ของ SIEM ได้หรือไม่

วิธีใช้ผล: จัดลำดับ lab ตามผลรวมคะแนน × ชั่วโมง ของแต่ละ gap; gap ที่คะแนนเฉลี่ยต่ำกว่า 2 ให้ลดเป็นแบบฝึกหัดเสริม

## สิ่งที่ยังไม่มีใน repo และต้องสร้าง

- `generate_synthetic_offenses.py` สำหรับ L4 (และใช้ใน L2 เป็น fallback)
- `to_leef.py` สำหรับ L1 (ยังไม่มีตัวอย่างในรายงาน research เป็นส่วนขยายที่ต้องติดป้ายว่าไม่ได้มาจากรายงาน)
- subset ของ GUIDE และ HDFS ที่ตัดให้พอรันบนเครื่องผู้เรียน พร้อมสคริปต์ที่ใช้ตัดเพื่อให้ทำซ้ำได้
- บทอ่านสั้น ๆ ประกอบแต่ละ lab แบบเดียวกับ reading-combined-log-vs-siem.md
