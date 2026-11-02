# SIEM ที่ NT ใช้: ข้อมูลสาธารณะที่ค้นได้ (ณ 2026-11-02)

เอกสารนี้แยกจากรายงาน research ของหลักสูตร เป็นผลการค้นข้อมูลเปิดเกี่ยวกับผู้เรียน (บุคลากร NT) เพื่อปรับตัวอย่างใน Module 5–6 ให้ตรงกับเครื่องมือที่ผู้เรียนใช้จริง ทุกข้อมาจากเอกสารเผยแพร่ของ NT/NT cyfence และข่าวผู้ผลิต ยังไม่ได้ยืนยันกับผู้เรียนโดยตรง

## สรุป

- **ศูนย์ CSOC ของ NT cyfence (ฝั่งบริการลูกค้า) ใช้ IBM QRadar** ยืนยันจากหน้าบริการปัจจุบัน และ **McAfee SIEM** (ปัจจุบันคือ Trellix Enterprise Security Manager) ตามบทความของ NT cyfence ปี 2022
- **ไม่พบรุ่น/เวอร์ชัน ปีจัดซื้อ หรืออายุสัญญา** จากประกาศจัดซื้อ (e-GP, tor.scap), ข่าวผู้ผลิต, ประกาศรับสมัครงาน หรือ LinkedIn
- **ไม่พบข้อมูล SOC ภายในองค์กรของ NT เอง** (ฝั่ง IT ของบริษัท) ซึ่งอาจเป็นคนละระบบกับ CSOC ที่ให้บริการลูกค้า
- หน้าบริการปัจจุบันกล่าวถึงเฉพาะ QRadar จึงยืนยันไม่ได้ว่า McAfee/Trellix ยังใช้อยู่ในปี 2025–2026

## หลักฐาน

| ข้อค้นพบ | แหล่ง | วันที่ |
| --- | --- | --- |
| "ใช้ Product และ Tool ของ IBM Qradar ซึ่งถือว่าเป็นผู้นำทางด้าน Security (อ้างอิงจาก Gartner ปี 2020)"; เก็บ log 90 วัน สำรองไป DR site; CSIRT ลงพื้นที่ 4 ครั้ง/ปี; certification ของทีม Security+, CCNA, CCNP, CEH, CHFI, OSSA, OPST, CISSP | [NT cyfence: Cybersecurity Monitoring](https://www.cyfence.com/services/cyber-security-monitoring/) | หน้าปัจจุบัน (footer 2026) |
| "เครื่องมือหลักที่ใช้ในการเก็บรวบรวม และประมวลผลข้อมูล even log ได้แก่ McAfee SIEM และ IBM Qradar" บวก threat intelligence, ระบบ incident ticket, เครื่องมือเก็บหลักฐานดิจิทัล และ "มีแผนในการพัฒนาเครื่องมืออื่นๆ ที่เข้ามาช่วยในการจัดการกับภัยคุกคามทางด้านไซเบอร์แบบ automation"; analyst แบ่ง 3 ระดับ ประสบการณ์ >14 ปี | [NT cyfence CSOC แตกต่างจาก CSOC ทั่วไปอย่างไร](https://www.cyfence.com/article/nt-cyfence-csoc-different-with-another-csoc/) | 17 พ.ค. 2022 |
| ผู้จัดการฝ่ายธุรกิจความปลอดภัยเทคโนโลยีสารสนเทศ NT เล่าใน IBM Cloud Digital Masterclass ว่า SOC มีแพลตฟอร์มอยู่แล้ว และในปี 2021 นำ IBM QRadar ที่มี UBA (User Behavior Analytics) และ Watson มาเสริม | [IBM cloud: Business Case Modernizing the SOC](https://www.cyfence.com/news-activity/ibm-cloud-online-talk-business-case-modernizing-soc-with-cyfence/) | 23 มี.ค. 2021 |
| NT ลงนามกับ Cynclair ขยายบริการ 3 ด้าน: Cybersecurity Academy, พัฒนา platform, Managed Detection & Response ไม่ระบุชื่อผลิตภัณฑ์ (ผลิตภัณฑ์ของ Cynclair คือ Azurites OpenXDR) | [Brand Inside](https://brandinside.asia/nt-cynclair-nt-cyfence/), [TheReporterAsia](https://thereporter.asia/2024/10/nt-cyfence-cybersecurity/), [Cynclair](https://www.cynclair.com/) | ต.ค. 2024 |
| NT เปิด CyberXpert Center เพื่อพัฒนาบุคลากร cybersecurity ไม่ระบุแพลตฟอร์ม | [ntplc.co.th](https://www.ntplc.co.th/news/detail/nt-opens-cyberxpert-center) | 24 ธ.ค. 2025 |
| บทความ SIEM ของ NT cyfence อธิบาย SIEM ทั่วไป ไม่ระบุผลิตภัณฑ์ที่ใช้ | [SIEM หัวใจของการตรวจจับภัยคุกคามไซเบอร์](https://www.cyfence.com/it-security/what-is-siem/) | 6 ต.ค. 2022 |
| บริการ Secure Log Management ของ NT ไม่ระบุผลิตภัณฑ์ (AES-128, สำรองไป DR site, รองรับ พ.ร.บ. คอมพิวเตอร์ 2560) | [ntplc.co.th: Secure Log Management](https://www.ntplc.co.th/enterprise/products-and-services/digital/secure-log-management) | หน้าปัจจุบัน |

## บริบทตลาดที่กระทบการสอน (ข่าวผู้ผลิต ไม่ใช่ข้อมูลของ NT)

- IBM ขายธุรกิจ QRadar SaaS ให้ Palo Alto Networks (ปิดดีล ก.ย. 2024) QRadar SaaS หมดอายุ 14 เม.ย. 2026 และมีเส้นทางย้ายไป Cortex XSIAM ส่วน QRadar on-premises ยังอยู่กับ IBM — [Palo Alto press](https://www.paloaltonetworks.com/company/press/2024/palo-alto-networks--closes-acquisition-of-ibm-s-qradar-saas-assets), [IBM divestiture notice](https://www.ibm.com/support/pages/ibm-qradar-siem-saassaas-divestiture-notification), [Palo Alto end-of-sale](https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-sale)
- McAfee Enterprise Security Manager เปลี่ยนชื่อเป็น Trellix ESM ตั้งแต่ปี 2022 — [Trellix SIEM 11.x upgrade guide](https://www.trellix.com/enterprise/en-us/assets/guides/gd-siem-11x-upgrade.pdf)

## นัยต่อ Module 5–6

- ผู้เรียนทั้งกลุ่มที่ทำ SIEM มานานและกลุ่มใหม่จะเจอ **QRadar** เป็นหลัก ตัวอย่างใน M5.2 และ M6.2 ควรมีการ map เข้า **LEEF** (รูปแบบ event ของ QRadar) นอกเหนือจาก ECS/OCSF รายงาน research มี IBM LEEF Format Guide ในรายการอ้างอิงแล้วแต่ยังไม่มีตัวอย่างโค้ด
- **QRadar REST API และ AQL ไม่อยู่ในรายงาน research** หากจะทำ integration ใน M5.4 ต้องเปิดรอบค้นคว้าเพิ่มตามเกณฑ์เดิม (แหล่งต้นฉบับ, งานเขียนในชุมชน, ตัวอย่างโค้ด, references)
- ข้อความ "มีแผนพัฒนาเครื่องมือแบบ automation" (2022) และความร่วมมือ MDR กับ Cynclair (2024) สอดคล้องกับเป้าหมายของ Module 6

## สิ่งที่ต้องยืนยันกับผู้เรียนก่อนใช้

1. รุ่น/เวอร์ชันของ QRadar ที่ใช้ และเป็น on-premises หรือ SaaS (กระทบเรื่อง end-of-life เม.ย. 2026)
2. McAfee/Trellix ESM ยังใช้อยู่หรือไม่ และใช้กับงานส่วนไหน
3. SOC ภายในของ NT ใช้ระบบเดียวกับ CSOC ของ NT cyfence หรือไม่
4. platform จากความร่วมมือ Cynclair ถูกนำมาใช้แล้วหรือยัง

## วิธีค้นที่ใช้

ค้นด้วย WebSearch/WebFetch เมื่อ 2026-11-02 ประมาณ 20 คำค้น ทั้งไทยและอังกฤษ ครอบคลุม: เว็บไซต์ NT และ NT cyfence, ข่าว (Bangkok Biz, MGR Online, TechTalkThai, Brand Inside, Blognone), ประกาศจัดซื้อ (e-GP ผ่าน search, tor.scap.co.th), ฐานข้อมูลซอฟต์แวร์องค์กร (appsruntheworld), ประกาศรับสมัครงานและ LinkedIn, ข่าวผู้ผลิต (IBM, Palo Alto, Trellix, Cynclair) ผลค้นจาก e-GP โดยตรงทำไม่ได้ผ่าน search engine ควรค้นในระบบ e-GP เองด้วยคำว่า SIEM / QRadar / Log Management ร่วมกับชื่อ NT, ทีโอที และ กสท
