# อภิธานศัพท์ (Glossary) สำหรับ Module 5–6

คำย่อและชื่อเฉพาะที่ใช้ในเอกสารและ lab ของ repo นี้ นิยามสั้น 1–2 ประโยค ระบุว่าโผล่ใน lab ไหน และที่มาของนิยาม

แหล่งที่อ้าง: **[R]** = [รายงาน research หลัก](python-security-automation-research.md), **[D]** = [รายงาน datasets](datasets-for-gap-labs.md) (รวมเอกสาร IBM ที่คัดไว้), **[N]** = [บริบท SIEM ของ NT](nt-siem-landscape.md), **[L]** = [lab design](lab-design-by-gap.md), **[Q]** = [บันทึกถาม-ตอบ Q18](qa-2026-11-02-mcp-spark-hdfs.md), **[M]** = [before & after ของ M6.10](../module6/10-claude-mcp-labs/siem-10-functions-before-after.md) คำที่ติด **[นอกกรอบ]** คือคำทั่วไปที่รายงานไม่ได้นิยามไว้ตรง ๆ ผู้เขียนอธิบายจากความหมายที่ใช้กันทั่วไป

## 1. งาน SOC

| คำ | ความหมาย | โผล่ใน | ที่มา |
| --- | --- | --- | --- |
| SOC / CSOC | Security Operations Center ศูนย์เฝ้าระวังภัยไซเบอร์ 24x7 NT cyfence เรียกของตัวเองว่า CSOC (Cybersecurity Operations Center) | ทุก lab | [N] |
| SIEM | Security Information and Event Management ระบบรวม log จากหลายแหล่ง normalize หา pattern ตาม rule แล้วสร้าง alert ของ NT คือ IBM QRadar | ทุก lab | [R] M5.2, [N] |
| IBM QRadar | SIEM ของ IBM ที่ CSOC ของ NT cyfence ใช้ มีรุ่น on-prem (ยังอยู่กับ IBM) และ SaaS (ขายให้ Palo Alto หมดอายุ เม.ย. 2026) | L1, L2, L4, L5 | [N], [D] |
| QRadar Community Edition (CE) | รุ่นฟรีของ QRadar สำหรับทดลอง จำกัด 100 EPS / 5,000 FPM ต้องการ RAM 24 GB ใช้ทดสอบ LEEF และ AQL ที่บ้านได้ | L1, L5 | [D] |
| offense | ชื่อที่ QRadar ใช้เรียก alert ที่ถูกจัดกลุ่มและให้คะแนน (magnitude) แล้ว มี schema ของตัวเองผ่าน `/api/siem/offenses` | L2, L4 | [D] |
| DSM | Device Support Module parser สำเร็จรูปของ QRadar สำหรับ log แต่ละยี่ห้อ แหล่งที่ไม่มี DSM คือ gap G1 | L1 | [D] (เอกสาร IBM) |
| EPS / FPM | events per second และ flows per minute หน่วยที่ QRadar ใช้คิด license และขีดจำกัดของ CE | L1 | [D] |
| UBA | User Behavior Analytics ส่วนเสริมของ QRadar ที่ NT นำมาใช้ปี 2021 เพื่อหาพฤติกรรมผู้ใช้ผิดปกติ | L6 | [N] |
| McAfee SIEM / Trellix ESM | SIEM อีกตัวที่ NT cyfence ระบุว่าใช้ (2022) McAfee Enterprise Security Manager เปลี่ยนชื่อเป็น Trellix ESM ตั้งแต่ 2022 | L1 | [N] |
| SOAR | Security Orchestration, Automation and Response ระบบต่อ playbook อัตโนมัติ Gartner บัญญัติปี 2017 และจัด standalone SOAR เป็น obsolete ในปี 2024 | L2 | [R] M6.1 |
| EDR / XDR / MDR | Endpoint Detection and Response (บน endpoint), Extended DR (รวมหลายแหล่ง), Managed DR (จ้างผู้ให้บริการเฝ้าระวัง) NT ร่วมกับ Cynclair ด้าน MDR ปี 2024 | บริบท | [N], [R] M6.1 |
| alert / incident / ticket / case | alert = สิ่งที่ rule ยิงออกมา; incident = เหตุการณ์ที่ยืนยันแล้วว่าต้องจัดการ; ticket/case = รายการติดตามงานใน Jira หรือ TheHive | L2, L4 | [R] M6.2 [นอกกรอบ] บางส่วน |
| TP / FP / BP | true positive (ภัยจริง), false positive (rule ยิงผิด), benign positive (เกิดจริงแต่ไม่เป็นภัย เช่นงาน admin) GUIDE ใช้ label สามค่านี้ | L2, L4, L6 | [D] G2 |
| MTTD / MTTA / MTTR | mean time to detect / acknowledge / respond เวลาเฉลี่ยจากเหตุเกิด → ตรวจพบ → มีคนรับ → แก้เสร็จ ต้องนิยาม "นาฬิกา" ก่อนคำนวณ | L4 | [R] M6.4 ตัวอย่าง 9.2 |
| dwell time | เวลาที่ผู้โจมตีอยู่ในระบบก่อนถูกพบ M-Trends 2025 median 11 วัน, 2026 14 วัน | L4 | [R] M6.4 |
| SLA | Service Level Agreement เวลาที่สัญญาว่าจะตอบสนอง ใช้คำนวณ % breach จากฟิลด์ `made_sla` ของ UCI | L4 | [D] G4 |
| alert fatigue / alert overload | ภาวะ alert มากจน analyst รับไม่ไหว Critical Start พบเกือบครึ่งของ SOC มี FP ≥ 50% | L2 | [R] M6.2 |
| SOC-CMM / Metrics 101 | กรอบวัดวุฒิภาวะ SOC ของ Rob van Os และเอกสารนิยาม metric (เช่น % false positives, % ATT&CK coverage) | L4, L5 | [R] M6.4 |
| MITRE 11 Strategies | หนังสือฟรีของ MITRE (2022) ว่าด้วยการสร้าง SOC ระดับโลก ข้อ 10 คือ "วัดผลเพื่อปรับปรุง" | L4 | [R] M6.4 |

## 2. รูปแบบ log และ schema

| คำ | ความหมาย | โผล่ใน | ที่มา |
| --- | --- | --- | --- |
| syslog (RFC 5424 / BSD) | รูปแบบ log มาตรฐานของ Unix/เครือข่าย RFC 5424 มี header ชัด (PRI, version, timestamp ISO) ส่วนแบบดั้งเดิม (BSD, RFC 3164) ไม่มีปีใน timestamp | L1, M5.2 ตัวอย่าง 2.3 | [R] M5.2 |
| PRI / facility / severity | ตัวเลขหน้า syslog `<34>` คำนวณจาก facility × 8 + severity severity 0–7 (0 ร้ายแรงสุด) | L1 | [R] M5.2 |
| combined log | รูปแบบ access log ของ Apache/nginx ที่มี Referer และ User-agent ต่อท้าย Common Log Format ไม่ใช่ "การรวม log" | L1, M5.1 | [R] M5.2, [บทอ่าน](../module5/02-log-analysis-automation/reading-combined-log-vs-siem.md) |
| EVTX | ไฟล์ Windows Event Log แบบ binary XML อ่านด้วย python-evtx หรือ pyevtx-rs Event ID 4625 = logon ล้มเหลว | L1, L5 | [R] M5.2 ตัวอย่าง 2.2 |
| CEF | Common Event Format ของ ArcSight รูปแบบบรรทัด `CEF:0|vendor|product|...` ใช้ถ้า NT ยังใช้ Trellix ESM | L1 | [R] M5.2 |
| LEEF | Log Event Extended Format ของ IBM รูปแบบที่ QRadar อ่านได้โดยไม่ต้องมี DSM header `LEEF:2.0|Vendor|Product|Version|EventID|` ตามด้วย attribute key=value | L1 | [D] (เอกสาร IBM) |
| devTime | attribute ของ LEEF สำหรับเวลาเกิดเหตุ ถ้าใส่เป็น epoch 13 หลักไม่ต้องระบุ `devTimeFormat` | L1 | [D] |
| ECS | Elastic Common Schema (รุ่น 9.5.0) ชุดชื่อฟิลด์กลาง เช่น `source.ip`, `user.name` กำลังรวมเข้า OpenTelemetry | L1, L2 | [R] M5.2 |
| OCSF | Open Cybersecurity Schema Framework (รุ่น 1.9.0, Linux Foundation) schema กลางอีกตัว Detection Finding มี class_uid 2004 | L1, L2 | [R] M5.2, M6.2 |
| normalize / normalization | นิยามเต็มอยู่ใน [หมวด 6 ฟังก์ชันของ SIEM](#6-ฟังก์ชันของ-siem) แถว Normalization (schema กลางที่ใช้คือ ECS/OCSF/LEEF หรือ canonical schema ของ skill server) | L1, L2, M6.10 | [R] M5.2, [Q] |
| JSON lines (.jsonl) | ไฟล์ที่แต่ละบรรทัดเป็น JSON หนึ่ง object ใช้เป็น output ของ parser และ input ของตัวอย่าง 1.3 | L1 | [R] M5.1 |
| Zeek conn.log | log การเชื่อมต่อเครือข่ายจาก Zeek (เดิมชื่อ Bro) เป็น TSV มี header `#fields` อ่านด้วย ZAT | M5.2 ตัวอย่าง 2.6 | [R] M5.2 |

## 3. detection และ threat intelligence

| คำ | ความหมาย | โผล่ใน | ที่มา |
| --- | --- | --- | --- |
| detection rule | เงื่อนไขที่ SIEM ใช้ยิง alert เขียนได้ในภาษาของผลิตภัณฑ์ (เช่น AQL) หรือแบบกลาง (Sigma) | L5 | [R] M5.2 |
| Sigma | รูปแบบ rule แบบ YAML ที่ไม่ผูกกับผลิตภัณฑ์ repo SigmaHQ มี 3,161 rule ภายใต้ DRL 1.1 แปลงไปยัง SIEM ต่าง ๆ ด้วย pySigma/sigma-cli | L5, M5.2 ตัวอย่าง 2.5 | [R] M5.2, [D] G5 |
| pySigma / sigma-cli / backend | library และ CLI สำหรับแปลง Sigma backend คือ plugin ต่อ SIEM เช่น `ibm-qradar-aql` ของ IBM, Splunk, Elastic | L5 | [D] G5 |
| AQL | Ariel Query Language ภาษา query ของ QRadar คล้าย SQL เช่น `SELECT * FROM events WHERE ...` | L5 | [D] |
| MITRE ATT&CK | ฐานความรู้พฤติกรรมผู้โจมตี จัดเป็น tactic (เป้าหมาย เช่น TA0002 Execution) และ technique (วิธี เช่น T1059) เผยแพร่เป็น STIX ผ่าน TAXII | L5, L2 | [R] M5.5 |
| ATT&CK Navigator / layer | เว็บแอปของ MITRE สำหรับระบายสี technique และไฟล์ JSON (layer format v4.5) ที่ใช้แสดง coverage | L5, M6.3 ตัวอย่าง 8.4 | [R] M6.3 |
| coverage / visibility | coverage = technique ที่มี rule ตรวจจับ; visibility = technique ที่มี data source ให้มองเห็น SOC-CMM นิยามทั้งสองเป็น % | L5 | [R] M6.4 |
| DeTT&CT | เครื่องมือของ Rabobank ให้คะแนน data source, visibility และ detection แล้วออกเป็น Navigator layer | L5 | [R] M6.4, [D] G5 |
| STIX / TAXII | STIX 2.1 = รูปแบบข้อมูล threat intel แบบ JSON; TAXII 2.1 = โปรโตคอลรับส่ง STIX ผ่าน HTTP | M5.5 | [R] M5.5 |
| IOC | Indicator of Compromise เช่น IP, โดเมน, hash ที่เคยพบในการโจมตี ดึงจากข้อความด้วย iocextract | L3, M5.5 | [R] M5.5 |
| threat intelligence (CTI) | ข้อมูลเกี่ยวกับผู้โจมตีและ IOC ที่เอามา enrich alert มี lifecycle 6 ขั้นตามที่ SANS FOR578 สอน | L3 | [R] M5.5 |
| MISP / OTX / OpenCTI | แพลตฟอร์มแชร์ threat intel: MISP (open source, มี PyMISP), AlienVault OTX (ฟรี), OpenCTI (open source) | M5.5 | [R] M5.5 |
| enrichment | นิยามเต็มอยู่ใน [หมวด 6 ฟังก์ชันของ SIEM](#6-ฟังก์ชันของ-siem) แถว Enrichment (แหล่งที่ใช้ใน lab: Feodo, KEV, EPSS, asset criticality) | L3, M6.10 lab 4, 2b | [R] M5.4, M5.5, [Q] |
| CVE / CVSS / EPSS | CVE = รหัสช่องโหว่; CVSS = คะแนนความรุนแรง 0–10 (รุ่น 4.0 ปัจจุบัน); EPSS = ความน่าจะเป็นที่จะถูกโจมตีจริงใน 30 วัน จาก FIRST | L3 | [R] M5.4, M6.3 |
| CISA KEV | Known Exploited Vulnerabilities รายการช่องโหว่ที่ถูกใช้โจมตีจริงจาก CISA ดาวน์โหลด JSON ได้โดยไม่ต้องมี key (1,766 รายการ ณ ต.ค. 2026) | L3 | [R] M5.4, [D] G3 |
| NVD | National Vulnerability Database ของ NIST มี API 2.0 ให้ query CVE พร้อม CVSS | L3 | [R] M5.4 |
| Feodo Tracker / Spamhaus DROP / Tor exit list | รายการ IP ที่เป็น botnet C2, เครือข่ายที่ควร block, และ exit node ของ Tor ดาวน์โหลดเป็นไฟล์ได้โดยไม่ต้องมี key | L3 | [D] G3 |
| VirusTotal / AbuseIPDB | บริการตรวจ hash/URL และ reputation ของ IP ต้องมี key ฟรี (VT 500/วัน, AbuseIPDB 1,000/วัน) | L3 | [R] M5.4 |
| Pyramid of Pain / Kill Chain / Diamond Model | โมเดลคลาสสิกของ CTI: IOC ชนิดไหนทำให้ผู้โจมตีเจ็บกว่ากัน, ลำดับขั้นการโจมตี 7 ขั้น, ความสัมพันธ์ผู้โจมตี-เหยื่อ-โครงสร้าง-ความสามารถ | M5.5 | [R] M5.5 |

## 4. เครื่องมือและชุดข้อมูล

| คำ | ความหมาย | โผล่ใน | ที่มา |
| --- | --- | --- | --- |
| Drain3 | library ทำ template mining คือจัดกลุ่มบรรทัด log ที่โครงเหมือนกันเป็น template เดียว ใช้หา template หายาก | L6, M5.2 ตัวอย่าง 2.4 | [R] M5.2 |
| loglizer / DeepLog | loglizer = ชุด ML คลาสสิก (Decision Tree, PCA, Isolation Forest) สำหรับ log anomaly; DeepLog = งานวิจัย deep learning ปี 2017 | L6 | [R] M5.2 |
| Loghub / HDFS_v1 / BGL | ชุด log สาธารณะ 19 ชุดของ LogPAI บน Zenodo (CC-BY-4.0) HDFS และ BGL มี label ผิดปกติ ใช้เป็น benchmark | L6 | [D] G6 |
| Microsoft GUIDE | ชุด alert จริง 1.6 ล้านรายการจาก SOC ลูกค้า Microsoft 6.1k องค์กร มี label TP/FP/BP | L2, L4 | [D] G2 |
| UCI ServiceNow incident log | ชุด ticket จริงจาก ServiceNow 24,918 incident มี timestamp เปิด/รับ/แก้/ปิด | L4 | [D] G4 |
| OTRF Security-Datasets | telemetry จำลองการโจมตีพร้อม ATT&CK mapping ใช้ทดสอบ rule | L5 | [D] G5 |
| Cowrie / honeypot | honeypot จำลอง SSH/Telnet ที่บันทึกการโจมตีเป็น JSON ชุด CyberLab บน Zenodo | L1 | [D] G1 |
| SecRepo | เว็บรวม log ด้านความปลอดภัยของ Mike Sconzo มี access log จริงของ site รายวัน (CC BY 4.0) | L1 | [D] G1 |
| Wazuh / Elastic / Splunk | แพลตฟอร์ม SIEM/XDR อื่นที่ใช้เป็นต้นน้ำในโปรเจ็กต์ Module 6 (Wazuh และ Elastic ฟรี) | M6 | [R] M6.1 |
| TheHive / Cortex / Shuffle / n8n | TheHive = ระบบ case, Cortex = ตัว enrich (analyzer), Shuffle และ n8n = ตัวต่อ workflow ทั้งหมดมี entry point Python | M6.1 | [R] M6.1 |
| Jira | ระบบ ticket ที่ตัวอย่าง 7.4 ใช้ escalate | L2, M6.2 | [R] M6.2 |
| pandas | library Python สำหรับข้อมูลตาราง ใช้คำนวณ metric และ resample ตามเวลา | ทุก lab | [R] M5.1 |
| Jinja2 / WeasyPrint / python-docx | template HTML, แปลง HTML เป็น PDF, สร้างไฟล์ Word ใช้ทำรายงาน | L4 | [R] M6.3 |
| Streamlit | library ทำ dashboard เว็บจาก Python | L4 | [R] M6.4 |
| FastAPI | framework เขียน HTTP API ใช้รับ webhook ในตัวอย่าง 7.1 | L2 | [R] M6.2 |

## 5. เทคนิคใน Python และวิธีทำงาน

| คำ | ความหมาย | โผล่ใน | ที่มา |
| --- | --- | --- | --- |
| regex / named group | regular expression และการตั้งชื่อส่วนที่จับได้ `(?P<ip>\S+)` เพื่ออ่านผลเป็น dict | L1, M5.1 | [R] M5.1 |
| sliding window | การนับเหตุการณ์ในช่วงเวลาที่เลื่อนไปเรื่อย ๆ (เช่น 5 ครั้งใน 60 วินาที) ทำด้วย deque | L2, M5.2 ตัวอย่าง 2.1 | [R] M5.2 |
| fingerprint / dedupe | สร้าง hash จากฟิลด์หลักของ alert (rule, entity, ปลายทาง) แล้วตัด alert ที่ hash ซ้ำใน window | L2 | [R] M6.2 |
| composite score / risk score | คะแนนรวมจากหลายปัจจัย (ความรุนแรง, ความถี่, ผล enrichment) ใช้จัดลำดับ alert | L2 | [R] M6.2 |
| threshold | ค่าตัด เช่น 5 ครั้ง/60 วินาที หรือ 404 rate > 50% ทุกค่าใน repo นี้เป็นธรรมเนียมของชุมชน ไม่ใช่มาตรฐาน | L1, L2, L6 | [R] M5.2 |
| beaconing / CV | การที่ malware ติดต่อ C2 เป็นจังหวะสม่ำเสมอ ตรวจด้วย coefficient of variation ของช่วงเวลา (ค่าต่ำ = สม่ำเสมอ) | M5.2 ตัวอย่าง 2.6 | [R] M5.2 |
| precision / recall / F1 | สัดส่วน alert ที่ถูกจริง, สัดส่วนภัยจริงที่จับได้, และค่าเฉลี่ยของสองอย่าง ใช้เทียบ rule กับ ML | L6 | [R] M5.2 |
| retry / backoff / rate limit | ลองใหม่เมื่อ API ล้มเหลวโดยเว้นช่วงเพิ่มขึ้น และเคารพขีดจำกัดจำนวนครั้ง (HTTP 429, header Retry-After) | L3 | [R] M5.4 ตัวอย่าง 4.1 |
| API key / token / OAuth2 | วิธียืนยันตัวกับ API: key คงที่ใน header, token ที่หมดอายุ (JWT), หรือ OAuth2 client credentials QRadar ใช้ token ใน header `SEC` | L3 | [R] M5.4, [D] |
| webhook | URL ที่ระบบหนึ่ง POST ข้อมูลมาให้เมื่อเกิดเหตุ ใช้รับ alert จาก SIEM | L2 | [R] M6.2 |
| idempotent | ทำซ้ำกี่ครั้งผลเหมือนเดิม จำเป็นเมื่อ script อาจถูกรันซ้ำจาก retry | L3 | [R] M5.3 |
| venv / requirements.txt | สภาพแวดล้อม Python แยกต่อโปรเจ็กต์ และไฟล์รายการ library ที่ต้องติดตั้ง | ทุก lab | [R] M5.3 [นอกกรอบ] |
| smoke-test | การรันทดสอบขั้นต่ำเพื่อยืนยันว่าโค้ดทำงานได้กับข้อมูลตัวอย่าง ทุกหัวข้อใน repo มี `run_smoke_tests.sh` | ทุก lab | [นอกกรอบ] |
| illustrative | ป้ายบนตัวอย่างโค้ดที่เขียนขึ้นจาก API ที่มีเอกสาร ไม่ได้คัดจากแหล่งใดตรง ๆ และยังไม่ได้รันในรอบ research | ทุก lab | [R] |
| synthetic / parameterized synthetic | ข้อมูลที่สร้างขึ้นเอง โดยใช้ตัวเลขรวมที่เผยแพร่ (เช่น funnel ของ Red Canary) เป็นพารามิเตอร์ ใช้แทนข้อมูลจริงที่ไม่มีใครเปิดเผย | L4 | [D], [L] |

## 6. ฟังก์ชันของ SIEM

ลำดับ 10 ขั้นที่วงการใช้ (จาก Q18) นิยามในตารางนี้เป็นนิยามเต็มตามที่ผู้ปฏิบัติงาน SIEM เข้าใจ ไม่จำกัดเฉพาะส่วนที่ lab แสดง ส่วนนิยามแบบจำกัดกรอบตัวอย่างอยู่ใน [before & after ของ M6.10](../module6/10-claude-mcp-labs/siem-10-functions-before-after.md) คำที่คุณอาจเคยใช้แทน: extraction (= collection หรือ parsing แล้วแต่บริบท), manage (= investigation + reporting + case management รวมกัน)

| ฟังก์ชัน | ความหมาย | ใน QRadar | ใน MCP M6.10 | โผล่ใน | ที่มา |
| --- | --- | --- | --- | --- | --- |
| Collection / Ingestion | รับ log และ flow จากแหล่งต้นทางเข้าสู่ที่เก็บกลางอย่างต่อเนื่อง ผ่าน syslog (UDP/TCP/TLS), agent, API pull หรือไฟล์ พร้อมระบุตัวตนแหล่ง (log source), ประทับเวลาที่รับ (ingest time), กันหาย (buffer, ack) และควบคุมปริมาณ (EPS/FPM) event กับ flow เป็นคนละสาย | Event Collector, QFlow, Log Source, auto-discovery หลัง ~25 event, สิทธิ์ EPS/FPM | `hdfs_import_file`, `hdfs_write_text` แบบ batch เท่านั้น ไม่มี listener real-time | lab 0, 4 | [Q], [M], [D] (เอกสาร IBM) |
| Parsing | แยก raw event 1 รายการ (อาจหลายบรรทัด) เป็นฟิลด์ที่มีชื่อและชนิดข้อมูล ตามรูปแบบของ vendor และ firmware นั้น พร้อมระบุชนิดเหตุการณ์ (event ID) และผลการ parse (parsed / partial / failed) โดยคง raw payload ไว้ | DSM (Device Support Module) ต่อ vendor, DSM Editor สำหรับแหล่งที่ไม่มี DSM, event ที่ parse ไม่ได้เป็น "Stored" / SIM Generic | `log_skill_resolve` เลือก parser จาก fingerprint, `log_skill_test_parser` รัน parser 12 skill / 21 parser id; ไม่ตรงคือ failed ไม่เติมค่าว่าง | lab 1 | [Q], [M], [D] |
| Normalization | ทำให้ event ต่างแหล่งเทียบกันได้ 3 ชั้น: (1) ชื่อฟิลด์เดียวกัน (srcip / id.orig_h → source_ip) (2) ค่าในฟิลด์ใช้ vocabulary เดียวกัน (17 → udp, เวลาเป็น UTC, severity สเกลเดียว, ทิศทาง source = ผู้เริ่ม) (3) จัดหมวดเหตุการณ์ด้วย taxonomy กลาง (เช่น network_traffic / ids_alert หรือ high-/low-level category) | QID map ให้ชนิดเหตุการณ์, normalized event (sourceIP, destinationIP, username…), high-level / low-level category, magnitude scale | canonical security-event schema ใน skill normalize-security-logs; ชั้น 1 และ 3 (event_category) ทำแล้ว ชั้น 2 ยังไม่ครบ (FortiGate ให้ `"17"` Zeek ให้ `udp`, timezone ไม่สม่ำเสมอ) | lab 1, 3 | [Q], [M], [R] M5.2 |
| Enrichment | เติมข้อมูลจากนอก log เข้า record หรือ alert เพื่อให้ตัดสินได้: บริบทภายใน (asset criticality, เจ้าของ, identity IP → user, geo, DNS/WHOIS), ภายนอก (threat intel reputation, CVE/KEV/EPSS) ทำได้ทั้งตอน ingest และตอน query และต้องติดอายุ/ความเชื่อมั่นของ indicator ผล "ไม่พบ" เป็นผลลัพธ์ที่ต้องรายงาน ไม่ใช่สะอาด | Reference set / reference data, X-Force feed, Asset model, identity จาก AD/DHCP | ไม่มี tool ดึง feed; Claude Desktop ดึงแล้ว `hdfs_write_text` จากนั้น `hdfs_query_records` filter; asset criticality เป็น dict ในโค้ด lab 2b | lab 4, 2b | [Q], [M], [R] M5.4, M5.5 |
| Storage / Indexing | เก็บทั้ง raw และ parsed ในรูปที่อ่านซ้ำได้เร็วและเล็กกว่าต้นฉบับ มี index ให้ค้นโดยไม่สแกนทั้งหมด มี retention / lifecycle (hot → warm → cold → ลบ) ตามกฎหมายและนโยบาย ควบคุมสิทธิ์เข้าถึง และพิสูจน์ได้ว่าไม่ถูกแก้ (immutability, hash) | Ariel database (events, flows), indexed property, retention bucket | HDFS + Parquet ที่มี schema; **ไม่มี index** ทุก query เป็น scan; ไม่มี retention อัตโนมัติ; integrity ด้วย `hdfs_sha256` และ `errorifexists` | lab 2, 3 | [Q], [M] |
| Correlation / Analytics | หาความสัมพันธ์ระหว่าง event เพื่อสร้างสัญญาณที่ event เดียวบอกไม่ได้ มี 4 แบบหลัก: (1) ตรงเงื่อนไขเดียว (match) (2) นับเกิน threshold ใน window (3) ลำดับ A แล้ว B ภายใน T บน entity เดียว (sequence) (4) ผิดไป baseline / UBA / ML และการ join ข้ามแหล่งด้วย key ร่วม (5-tuple, asset, user) + เวลา ใน SIEM ทำแบบ streaming ขณะ event เข้า | Custom Rules Engine (CRE), building block, rule test แบบ event / flow / common / offense, UBA app | `hdfs_query_records` (threshold, สถิติเวลา), `hdfs_correlate_records` (join 5-tuple ± เวลา), skill correlate-security-evidence-with-spark (sequence C2 → exfil → lateral ภายใน 1800 s บน asset_id) ทั้งหมดเป็น batch | lab 3, 3b, 2b | [Q], [M], [R] M6.2 |
| Alerting | เปลี่ยนผล correlation เป็นสิ่งที่คนต้องดู: ยุบ event ซ้ำเป็นก้อนเดียว (dedupe / coalescing), ให้คะแนน (severity ของเหตุ × ความเกี่ยวข้องกับเรา × ความน่าเชื่อถือของแหล่ง), จัด priority, กันซ้ำ (suppression / throttle), แล้วส่งต่อ (route: escalate / queue / auto-close, email, ticket, SOAR) และปรับจาก false positive ที่ย้อนกลับมา | Offense (รวม event ตาม index เช่น source IP), magnitude 1–10 จาก relevance × severity × credibility, offense coalescing, response (email, SNMP, reference set) | ไม่มี engine ให้ ต้องเขียน PySpark เอง (lab 2b: fingerprint → window 600 s → score → route) report ไม่มี contract ใน skill server | lab 2b | [Q], [M], [R] M6.2 |
| Search / Investigation | ถามคำถามเฉพาะเจาะจงกับข้อมูลที่เก็บไว้เพื่อตอบว่า เกิดอะไร ไปไหน เท่าไร กระทบใครอีก: filter / aggregate, pivot จาก entity หนึ่งไปอีก entity (IP → user → host), ดู raw payload และ packet, สร้าง timeline, และ threat hunting ที่เริ่มจากสมมติฐานไม่ใช่ alert | AQL บน events / flows, Log Activity และ Network Activity tab, quick filter, right-click pivot, saved search | `hdfs_query_records` (filter, group_by, sum, CIDR), `hdfs_pcap_packets` (TShark display filter), `hdfs_read_lines`; ไม่มี query language ให้คนพิมพ์ตรง ทุกคำถามผ่าน Claude | lab 3 | [Q], [M], [D] (AQL) |
| Reporting / Dashboard | สรุป record จำนวนมากเป็นตัวเลขไม่กี่ตัวตามรูปแบบที่ตกลงล่วงหน้า แยกตามผู้รับ (compliance เช่น PCI/ISO, ผู้บริหาร, ทีมปฏิบัติการ), ตามกำหนดการ, แสดงแนวโน้มข้ามช่วงเวลา และวัดตัว SOC เอง (MTTD / MTTR, alert ต่อ analyst, FP ต่อ rule) ตัวเลขทุกตัวต้องชี้กลับไปข้อมูลต้นทางได้ | Reports (template, schedule, PDF), Dashboard, Pulse app | report contract (ids-report-v1 ฯลฯ) ผ่าน `log_skill_validate_report` แล้ว Claude Desktop ทำ Artifact / PDF; ไม่มี MTTD / MTTR เพราะไม่มี ticket | lab 2, 5 | [Q], [M], [R] M6.3, M6.4 |
| Case / Incident Management | เปลี่ยน alert ที่ผ่านการ triage เป็นงานที่มีเจ้าของ (assign), สถานะที่เปลี่ยนได้ (open → in progress → closed), SLA, บันทึก note และหลักฐานแนบ, เชื่อม case ที่เกี่ยวกัน, audit ว่าใครทำอะไรเมื่อไร, และปิดด้วย disposition (TP / FP / benign) ที่ป้อนกลับไปปรับ rule และ score; ขั้นถัดไปคือส่ง playbook ให้ SOAR | Offense Manager (assign, note, close reason, protect), QRadar SOAR (เดิม Resilient) | ไม่มี ใกล้สุดคือ handoff document (skill build-security-investigation-handoff-with-spark) ที่ให้ asset, timeline, หลักฐาน, analyst_actions แต่ไม่มี owner, state, note และที่บันทึก confirm / dismiss | lab 3b | [Q], [M], [R] M6.1 |

**เรื่องข้ามขั้น** ที่ไม่ใช่ฟังก์ชันใดฟังก์ชันหนึ่ง แต่ SIEM ทุกตัวต้องมีและตัวอย่างใน lab แสดงอยู่

| คำ | ความหมาย | ใน QRadar | ใน MCP M6.10 | โผล่ใน | ที่มา |
| --- | --- | --- | --- | --- | --- |
| event time / ingest time | เวลา 2 ชนิดของทุก record: เวลาที่เหตุเกิดบนอุปกรณ์ (event time, จาก log เอง) กับเวลาที่ SIEM รับเข้า (ingest time) ต่างกันได้จากนาฬิกาเพี้ยน, timezone, buffer หรือส่งย้อนหลัง (late-arriving) rule และ report ต้องประกาศว่าใช้เวลาไหน | `starttime` (รับ) กับ `devicetime` (เกิด) ใน Ariel, `devTime` ใน LEEF | parser คืนทั้ง `event_time` (2026-08-24 จาก log) และ `ingest_time` (2026-11-03 ตอนรัน) ใน record เดียว | lab 1, 2 | [M], [D] (devTime) |
| provenance / integrity | พิสูจน์ได้ว่าข้อมูลและโค้ดที่ใช้ไม่ถูกแก้ระหว่างทาง: เก็บ raw payload แบบแก้ไม่ได้, hash ทุกขั้น (input → code → output), audit log ว่าใครรันอะไร เป็นข้อกำหนด compliance และจำเป็นเมื่อผลต้องใช้เป็นหลักฐาน | payload ต้นฉบับใน Ariel, audit log ของ console, report ที่ลงนามเวลา | sha256 chain: template → render → `spark_save_job` → snapshot ของ job → report → `hashes.json`; `raw_event` ในทุก record; idempotency key; handoff ที่ deterministic (sha256 ตรงข้ามรอบ) | lab 2, 3b | [M], [R] M5.3 |
| feedback loop | ผลการปิด case (TP / FP / benign) ต้องย้อนกลับไปปรับ rule, threshold, score และ allowlist มิฉะนั้น alert volume จะโตโดยคุณภาพไม่ดีขึ้น ต้องมี label จาก case จึงวัด precision ของ rule ได้ | close reason ของ offense, rule response ที่เขียน reference set, tuning จาก false positive | ไม่มี label ใน incident-lab จึงวัด TP ที่หลุดจาก dedupe 88% ไม่ได้ (lab 2b บอกให้รายงานว่าวัดไม่ได้) และไม่มีที่บันทึก disposition (ข้อ 10) | lab 2b, 3b | [M], [R] M6.4 |

## คำที่ยังไม่มีในรายการ

ถ้าพบคำที่ไม่เข้าใจในเอกสารหรือ lab ให้เพิ่มในไฟล์นี้ตามกลุ่ม พร้อมระบุที่มา เพื่อให้ผู้เรียนรุ่นถัดไปไม่ต้องเจอปัญหาเดิม
