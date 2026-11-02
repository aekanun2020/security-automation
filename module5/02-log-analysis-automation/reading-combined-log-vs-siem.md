# บทอ่าน: "combined" log กับการรวม log ใน SIEM คนละเรื่องกัน

หัวข้อ M5.2 · เวลาอ่านประมาณ 5 นาที · เนื้อหาทุกข้ออ้างอิงจาก[รายงาน research ของหลักสูตร](../../docs/python-security-automation-research.md) (รวบรวม 2026-11-01)

คำว่า "combine" โผล่ในหลักสูตรนี้สองความหมายที่ไม่เกี่ยวกัน ความหมายแรกคือ **ชื่อรูปแบบ** ของ web server log หนึ่งบรรทัด ความหมายที่สองคือ **การรวม log จากหลายแหล่ง** ไว้ที่เดียว ซึ่งเป็นงานของ SIEM ผู้เรียนที่แยกสองอย่างนี้ได้จะเข้าใจว่าทำไม M5.2 ถึงจบที่เรื่อง schema

## 1. "combined" คือชื่อรูปแบบ ไม่ใช่การรวม

บรรทัดนี้มาจาก `samples/access.log` ที่ใช้ในตัวอย่าง 1.1 และ 2.7

```
198.51.100.35 - - [01/Mar/2026:00:14:26 +0000] "GET /static/app.js HTTP/1.1" 200 237 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0"
```

ตามเอกสาร Apache `mod_log_config` รูปแบบพื้นฐานคือ **Common Log Format** `%h %l %u %t "%r" %>s %b` (host, identity, user, time, request, status, bytes) ส่วน **combined** คือ Common บวกอีกสองฟิลด์ท้ายบรรทัด ได้แก่ `"%{Referer}i"` และ `"%{User-agent}i"` ชื่อ combined จึงหมายถึง "ฟิลด์ครบขึ้น" ของ log หนึ่งบรรทัด ไม่ใช่การเอาหลายไฟล์มารวมกัน ([mod_log_config](https://web.mit.edu/manual/mod/mod_log_config.html))

nginx กำหนด `log_format combined` ไว้ล่วงหน้าและใช้เป็นค่า default ของ `access_log` โดยมีตัวเลือก `escape=json` ตั้งแต่รุ่น 1.11.8 สำหรับกรณีที่ค่าในฟิลด์มีเครื่องหมายคำพูด ([ngx_http_log_module](https://nginx.org/en/docs/http/ngx_http_log_module.html))

นัยต่อการเขียนโค้ด: regex `COMBINED` ในตัวอย่าง 1.1 มี named group ครบ 9 ฟิลด์ตามนิยามนี้ ถ้า server ตั้ง `log_format` เป็นอย่างอื่น regex ต้องเปลี่ยนตาม นี่คือเหตุผลที่ M5.2 ให้ผู้เรียนอ่าน spec ของรูปแบบก่อนเขียน parser เสมอ (syslog ตาม RFC 5424, EVTX ตาม spec ของ libevtx, CEF ตาม Implementation Standard)

## 2. การรวม log จากหลายแหล่งคือ SIEM และต้อง normalize ก่อน

SOC ไม่ได้อ่าน access log ไฟล์เดียว แต่รับ syslog จาก Linux, EVTX จาก Windows, CEF จากอุปกรณ์เครือข่าย และ JSON จาก cloud พร้อมกัน ระบบที่รวม log เหล่านี้ไว้ที่เดียวเพื่อค้นหา เขียน detection rule และเก็บย้อนหลังคือ SIEM

ปัญหาคือแต่ละรูปแบบเรียกสิ่งเดียวกันคนละชื่อ IP ต้นทางเป็น `%h` ใน combined, เป็น `IpAddress` ใน EVTX event 4625 และเป็น `src` ใน CEF ถ้ารวมเข้า SIEM ทั้งอย่างนั้น detection rule หนึ่งข้อจะใช้ข้ามแหล่งไม่ได้ ทางออกคือ **normalize** ทุก record เป็น schema กลางก่อน ซึ่ง research ชี้ไปที่สองตัว

- **Elastic Common Schema (ECS)** รุ่น 9.5.0 "defines a common set of fields to be used when storing event data in Elasticsearch" และกำลังถูกรวมเข้า OpenTelemetry ([ECS reference](https://www.elastic.co/docs/reference/ecs))
- **OCSF** รุ่น 1.9.0 เป็นโครงการของ Linux Foundation ตั้งแต่ พ.ย. 2024 ([ocsf-schema](https://github.com/ocsf/ocsf-schema))

หลักฐานว่า schema เหล่านี้คือภาษาของ SIEM: โครงการ Sigma เรียกตัวเองว่า "Generic Signature Format for SIEM Systems" และ pipeline ของ pySigma/sigma-cli เช่น `-p ecs_windows` แปลง rule ให้ใช้ชื่อฟิลด์ของ ECS ([SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)) ตัวอย่าง 2.5 ในหัวข้อนี้คือการแปลงดังกล่าว ดังนั้นลำดับการสอนของ M5.2 ที่ research เสนอจึงเป็น raw text → EVTX → CEF → **ECS/OCSF** โดยเป้าหมายปลายทางคือผู้เรียน map record ใด ๆ เข้าฟิลด์ของ ECS หรือ OCSF ได้

## 3. รวมอย่างเดียวไม่พอ

SANS SOC Survey 2025 รายงานว่า "42% of SOCs dump all incoming data into a SIEM, often without a retrieval or management plan" ([SANS SOC Survey 2025](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)) และ NIST SP 800-92 Rev. 1 (ร่างสาธารณะ ต.ค. 2023) วางตัวเป็น "Cybersecurity Log Management Planning Guide" คือแนะนำให้วางแผนว่าจะเก็บอะไร นานเท่าไร เพื่ออะไร ก่อนเริ่มรวม ([NIST SP 800-92r1 ipd](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd))

สำหรับผู้เรียน ข้อนี้แปลว่าทักษะ parse และ normalize ใน M5.2 ไม่ได้หายไปเมื่อองค์กรมี SIEM แต่กลายเป็นงานออกแบบว่า log แต่ละแหล่งจะถูก map เข้า schema อย่างไร และจะใช้ตอบคำถามอะไร

## 4. แล้วต่อจากนี้

log ที่ normalize แล้วคือสิ่งที่ SIEM ใช้สร้าง alert และ alert เหล่านั้นคือจุดเริ่มต้นของ Module 6 ดังนั้นทักษะ parse และ normalize ที่ฝึกในหัวข้อนี้จะถูกใช้ต่อ ไม่ได้จบในตัวเอง

## สรุป

| คำ | หมายถึง | อยู่ตรงไหนในหลักสูตร |
| --- | --- | --- |
| combined log | รูปแบบ web log หนึ่งบรรทัดที่มี Referer และ User-agent | ตัวอย่าง 1.1, 2.7 และ `samples/access.log` |
| รวม log (log aggregation) | เก็บ log หลายแหล่งไว้ที่เดียว คืองานของ SIEM | นอกหัวข้อนี้ จะกลับมาใน Module 6 |
| normalize | แปลงทุกแหล่งเป็น ECS หรือ OCSF เพื่อให้ rule ใช้ข้ามแหล่งได้ | ปลายทางของ M5.2 และตัวอย่าง 2.5 |

## นอกขอบเขตของบทอ่านนี้

รายงาน research ไม่ได้ครอบคลุมสถาปัตยกรรมภายในของ SIEM (collector, indexing, retention, licensing) และไม่ได้เปรียบเทียบผลิตภัณฑ์ SIEM ข้อความข้างต้นจึงพูดถึง SIEM เฉพาะในฐานะปลายทางของการ normalize เท่านั้น
