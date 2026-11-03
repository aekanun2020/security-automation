# MCP tools ที่ใช้ใน lab — คำอธิบายไทยพร้อมต้นฉบับอังกฤษ

ผู้รับผิดชอบ: ครูเอ้ · ดึงจาก server จริง 2026-11-03 · ศัพท์ดูใน [glossary](../../docs/glossary.md)

เอกสารนี้มีไว้ให้ผู้เรียนรู้ว่า Claude มีเครื่องมืออะไรให้ใช้บ้างและแต่ละตัวทำอะไรได้แค่ไหน ทุก tool มี 3 ส่วน

- **ต้นฉบับ** คือข้อความ description ที่ server ประกาศให้ Claude อ่าน คัดมาทุกคำ ไม่แปล ไม่ตัด นี่คือสิ่งที่ Claude เห็นจริงตอนตัดสินใจเลือก tool
- **ภาษาไทย** คือคำอธิบายของผู้สอนว่า tool นี้ทำอะไร ใช้ตอนไหน และข้อจำกัดที่ต้องรู้
- **พารามิเตอร์** คือสิ่งที่ Claude ต้องส่งเข้าไป ตัวที่มี * คือบังคับ

มี 2 server รวม 37 tool แบ่งหน้าที่กันชัด Spark/HDFS server เป็น "มือ" ที่แตะข้อมูลและรันงานจริง ส่วน security skill server เป็น "กติกา" ที่บอกว่า parser ไหนได้รับอนุมัติ โค้ดต้องหน้าตาแบบไหน และรายงานถูกต้องไหม โดยไม่รันอะไรเลย

---

## Server 1: Spark/HDFS (23 tool)

### คำสั่งประจำ server

ต้นฉบับ

> Use spark_save_job then spark_validate_job before spark_submit_job. Use spark_read_job and spark_replace_job_text for small, auditable repairs. Poll spark_job_status and inspect spark_job_logs on failure. HDFS tools accept virtual paths relative to the restricted /mcp root, such as /lab/input.log, and return physical HDFS paths such as /mcp/lab/input.log. Pass the returned physical path unchanged to Spark; never pass the original virtual path to Spark or pass a returned /mcp path back to an HDFS tool. Spark files and settings are allowlisted. Never assume a submitted job succeeded until its status is SUCCEEDED.

ภาษาไทย: server บังคับลำดับ save → validate → submit และบอกว่าถ้าจะซ่อมโค้ดให้ใช้ read แล้ว replace ทีละจุดเพื่อให้ตรวจย้อนได้ เรื่อง path สำคัญมาก HDFS tool รับ path แบบ virtual (เช่น `/student/...`) แล้วคืน path แบบ physical (เช่น `/mcp/student/...`) ตอนส่งให้ Spark ต้องใช้ physical เท่านั้น และห้ามเอา physical กลับไปใส่ HDFS tool ประโยคสุดท้ายคือหัวใจของทุก lab คือห้ามเชื่อว่า job สำเร็จจนกว่า status จะเป็น SUCCEEDED

### กลุ่ม HDFS: ดูและอ่าน

#### hdfs_cluster_status

ต้นฉบับ
> Return HDFS capacity, block health, and DataNode counts.

ภาษาไทย: ดูสุขภาพของ HDFS ว่ามีพื้นที่เท่าไร DataNode ขึ้นกี่ตัว มี block หายหรือ replicate ไม่ครบไหม ใช้ตอนเริ่ม lab เพื่อยืนยันว่าระบบพร้อม ไม่มีพารามิเตอร์

#### hdfs_list

ต้นฉบับ
> List by virtual path below /mcp; do not include the /mcp prefix.

ภาษาไทย: ดูว่าใน directory มีไฟล์อะไรบ้าง เหมือน `ls` ใส่ path แบบ virtual ไม่ต้องมี `/mcp` นำหน้า

พารามิเตอร์: `path` (ค่าเริ่มต้น `/`)

#### hdfs_stat

ต้นฉบับ
> Get metadata by virtual path below /mcp; do not include the /mcp prefix.

ภาษาไทย: ดูข้อมูลของไฟล์หนึ่งไฟล์ เช่น ขนาดเป็น byte เวลาแก้ไข replication ใช้เทียบขนาดก่อน-หลัง หรือยืนยันว่าไฟล์มีอยู่จริง

พารามิเตอร์: `path`*

#### hdfs_read_text

ต้นฉบับ
> Read by virtual path below /mcp; do not include the /mcp prefix.

ภาษาไทย: อ่านไฟล์ทั้งไฟล์เป็นข้อความ เหมาะกับไฟล์เล็ก เช่น report JSON บรรทัดเดียว มีเพดานขนาดกันไม่ให้ดึง log ใหญ่เข้ามาทั้งก้อน

พารามิเตอร์: `path`*, `max_bytes` (ค่าเริ่มต้น 1,048,576)

#### hdfs_read_lines

ต้นฉบับ
> Read numbered UTF-8 records without loading a large log into model context. Lines are one-based; returns next_line.

ภาษาไทย: อ่าน log ทีละช่วงบรรทัด พร้อมเลขบรรทัด (เริ่มที่ 1) และบอกว่าบรรทัดถัดไปคือเลขอะไร ใช้แทน read_text เมื่อไฟล์ใหญ่ เช่น ดู 3 บรรทัดแรกเพื่อหา parser ใน Lab 1

พารามิเตอร์: `path`*, `start_line` (ค่าเริ่มต้น 1), `limit` (ค่าเริ่มต้น 20)

#### hdfs_sha256

ต้นฉบับ
> Stream the whole real HDFS file (text or binary) and return its SHA-256. Virtual path omits /mcp.

ภาษาไทย: คำนวณ SHA-256 ของไฟล์ทั้งไฟล์ ใช้พิสูจน์ว่าไฟล์ input ที่ทุกคนใช้คือไฟล์เดียวกัน และบันทึก hash ของ report ไว้ใน hashes.json เพื่อให้คนอื่นตรวจซ้ำได้

พารามิเตอร์: `path`*

### กลุ่ม HDFS: เขียน

#### hdfs_mkdir

ต้นฉบับ
> Create by virtual path below /mcp; the result returns its physical path.

ภาษาไทย: สร้าง directory สำหรับ output ของตัวเอง ผลที่คืนมาคือ physical path ซึ่งต้องเก็บไว้ส่งให้ Spark

พารามิเตอร์: `path`*

#### hdfs_write_text

ต้นฉบับ
> Write by virtual path below /mcp; the result returns its physical path.

ภาษาไทย: เขียนข้อความลงไฟล์ใน HDFS เช่น allowlist หรือ hashes.json ค่าเริ่มต้นไม่เขียนทับ ถ้าไฟล์มีอยู่แล้วจะล้ม ต้องตั้ง overwrite เอง

พารามิเตอร์: `path`*, `text`*, `overwrite` (ค่าเริ่มต้น false), `replication` (ค่าเริ่มต้น 2)

#### hdfs_import_file

ต้นฉบับ
> Verify a stable import in HDFS before publishing it with an atomic rename. ``destination`` is an HDFS MCP virtual path such as ``/lab/input.log``; do not include the ``/mcp`` prefix. The returned ``destination`` is the physical HDFS path, such as ``/mcp/lab/input.log``. Pass that returned value unchanged to PySpark or ``spark_submit_job``. Do not pass it back into an HDFS MCP tool. Callers must serialize writes to one destination. An existing destination is replay-safe when ``overwrite`` is false and its exact bytes already match the stable source. Otherwise an existing destination is moved to a temporary backup for rollback because FsShell rename does not provide a cross-replica compare-and-swap operation.

ภาษาไทย: นำไฟล์จากคลังต้นทางที่ server เตรียมไว้ (ระบุด้วย source_name) เข้ามาวางใน HDFS โดยตรวจก่อนแล้วค่อยเปลี่ยนชื่อทีเดียวให้ปลอดภัย ถ้าปลายทางมีไฟล์เดิมที่ byte ตรงกันทุกตัวอยู่แล้วและไม่ได้สั่ง overwrite ถือว่าทำซ้ำได้ไม่เป็นไร ถ้าไม่ตรงจะย้ายของเดิมไปเก็บสำรองไว้ก่อน ข้อจำกัดคือห้ามให้หลายคนเขียนปลายทางเดียวกันพร้อมกัน

พารามิเตอร์: `source_name`*, `destination`*, `overwrite` (ค่าเริ่มต้น false)

#### hdfs_delete

ต้นฉบับ
> Delete by virtual path below /mcp; deleting the root itself is forbidden.

ภาษาไทย: ลบไฟล์หรือ directory ลบ root ไม่ได้ ถ้าจะลบทั้ง directory ต้องตั้ง recursive ใน lab แทบไม่ใช้ เพราะกติกาคือเขียน output ที่ใหม่แทนการลบของเก่า

พารามิเตอร์: `path`*, `recursive` (ค่าเริ่มต้น false)

### กลุ่ม HDFS: สืบค้นโดยไม่ต้องรัน Spark

สามตัวนี้คือเครื่องมือที่ analyst ใช้ตอบคำถามเร็ว ๆ แบบที่เคยพิมพ์ AQL ใน QRadar ทำงานบนไฟล์ทั้งไฟล์แต่คืนเฉพาะตัวเลขสรุปและเลขบรรทัดอ้างอิง

#### hdfs_query_records

ต้นฉบับ
> Scan an entire JSONL or key=value log. Exact filters are AND across fields, OR within each list (values compared as strings). Field names are literal, including dots. Return counts, sums, distinct counts, UTC time/interval statistics and original line references. No attack labels or hidden detection rules. Missing requested fields fail rather than becoming zero. time_field must contain epoch seconds or timezone-aware ISO text; omit for split date/time fields.

ภาษาไทย: กวาด log ทั้งไฟล์แล้วนับ รวม นับค่าไม่ซ้ำ จัดกลุ่ม และคำนวณสถิติเวลา (ช่วงห่างระหว่าง event เป็นวินาที ซึ่งใช้จับ beacon ที่คาบคงที่) filter หลายฟิลด์คือ AND ค่าหลายค่าในฟิลด์เดียวคือ OR เทียบเป็นข้อความตรงตัว ชื่อฟิลด์ที่มีจุดเช่น `alert.severity` ใช้ตามนั้นไม่ใช่การเจาะลงชั้น สิ่งที่ต้องรู้คือ tool นี้ไม่ตีตราว่าอะไรเป็นการโจมตี ไม่มี rule ซ่อน และถ้าขอฟิลด์ที่ไม่มีจะ error ไม่ใช่คืนศูนย์ ซึ่งดีสำหรับการตรวจเพราะไม่มีตัวเลขหลอก

พารามิเตอร์: `path`*, `format`* (jsonl หรือ kv), `filters`, `cidr_filters`, `group_by`, `distinct_fields`, `sum_fields`, `time_field`, `sample_fields`, `samples_per_group` (ค่าเริ่มต้น 2), `max_groups` (ค่าเริ่มต้น 30)

#### hdfs_correlate_records

ต้นฉบับ
> Join two real HDFS log views by equal keys AND timestamp tolerance. Use UID/parentuid or a full directional tuple (source/dest IP, source/dest port, protocol). Literal field names. Time fields: one epoch/ISO field, or two date/time fields; timezone-less input requires explicit naive_timezone='UTC'. Return full-source hashes, line-numbered pairs, deltas, unmatched counts and one-to-many cardinality. Counts are records/pairs, not automatically sessions. Optional left_group_by returns exact matched cohort counts and first/last left timestamps (up to 100 groups). No attack verdict.

ภาษาไทย: จับคู่ record จากสอง log ด้วยคีย์ที่เท่ากัน (เช่น 5-tuple หรือ uid ของ Zeek) และเวลาห่างกันไม่เกินที่กำหนด คืน hash ของทั้งสองไฟล์ต้นทาง คู่ที่จับได้พร้อมเลขบรรทัด ผลต่างเวลา จำนวนที่จับไม่ได้ และบอกว่าเป็นหนึ่งต่อหนึ่งหรือหนึ่งต่อหลาย คำเตือนสำคัญคือตัวเลขที่ได้คือจำนวน record หรือคู่ ไม่ใช่จำนวน session โดยอัตโนมัติ นี่คือที่มาของคำถามใน Lab 3 ว่าทำไม alert 100 แต่ connection 25 และ tool นี้ก็ไม่ตัดสินว่าเป็นการโจมตี

พารามิเตอร์: `left_path`*, `right_path`*, `left_format`*, `right_format`*, `left_keys`*, `right_keys`*, `left_time_fields`*, `right_time_fields`*, `max_delta_seconds` (ค่าเริ่มต้น 1), `left_filters`, `right_filters`, `left_group_by`, `naive_timezone`, `max_examples` (ค่าเริ่มต้น 3)

#### hdfs_pcap_packets

ต้นฉบับ
> Inspect a real HDFS PCAP using TShark/Wireshark display-filter syntax. Scans the capture and returns matching packet count plus bounded numbered packet evidence and TCP payload hex/text. Use numeric addresses; name resolution is disabled. Packet count is not connection count. Requires tshark installed in the MCP image.

ภาษาไทย: เปิด pcap ด้วย filter แบบ Wireshark เช่น `ip.addr == 10.70.0.66 && dns` คืนจำนวน packet ที่ตรงและตัวอย่าง packet พร้อม payload เป็น hex และข้อความ ใช้เมื่อต้องการหลักฐานระดับต่ำสุดยืนยันสิ่งที่ Zeek หรือ Suricata บอก ต้องใช้ IP เป็นตัวเลขเพราะปิด name resolution และจำนวน packet ไม่ใช่จำนวน connection

พารามิเตอร์: `path`*, `display_filter`*, `limit` (ค่าเริ่มต้น 10), `payload_bytes` (ค่าเริ่มต้น 160)

### กลุ่ม Spark

#### spark_cluster_status

ต้นฉบับ
> Return Spark master capacity, applications, and registered workers.

ภาษาไทย: ดูว่า Spark master ยังอยู่ไหม มี worker กี่ตัว core และ memory ว่างเท่าไร มี app รันค้างอยู่หรือเปล่า ไม่มีพารามิเตอร์

#### spark_save_job

ต้นฉบับ
> Save a syntactically valid UTF-8 PySpark application.

ภาษาไทย: บันทึกโค้ด PySpark เป็นไฟล์บน server ถ้า syntax ผิดจะไม่รับ ผลที่คืนมามี sha256 ของโค้ด ซึ่งต้องเท่ากับ code_sha256 ที่ render มา ถ้าไม่เท่าแปลว่าโค้ดถูกแก้ระหว่างทาง ค่าเริ่มต้นไม่เขียนทับไฟล์ชื่อซ้ำ

พารามิเตอร์: `filename`*, `code`*, `overwrite` (ค่าเริ่มต้น false)

#### spark_read_job

ต้นฉบับ
> Read a bounded saved PySpark application before making a targeted repair.

ภาษาไทย: อ่านโค้ดที่บันทึกไว้กลับมาดู ใช้ก่อนจะซ่อมด้วย replace_job_text หรือใช้ตรวจว่าโค้ดที่อยู่บน server ตรงกับที่คิดไหม

พารามิเตอร์: `filename`*

#### spark_replace_job_text

ต้นฉบับ
> Replace exact text in one saved job and reject ambiguous or invalid repairs.

ภาษาไทย: แก้โค้ดโดยระบุข้อความเดิมและข้อความใหม่ตรงตัว ถ้าข้อความเดิมพบมากกว่าที่คาด (ค่าเริ่มต้น 1 ครั้ง) หรือแก้แล้ว syntax พัง จะปฏิเสธ ออกแบบมาให้การแก้ทุกครั้งตรวจย้อนได้ แต่สำหรับโค้ดที่ render จาก template ไม่ควรแก้เลย เพราะจะทำให้ sha ไม่ตรง template

พารามิเตอร์: `filename`*, `old_text`*, `new_text`*, `expected_occurrences` (ค่าเริ่มต้น 1)

#### spark_validate_job

ต้นฉบับ
> Parse a saved Spark job and report whether it imports PySpark.

ภาษาไทย: ตรวจว่าโค้ดที่บันทึกไว้ parse เป็น Python ได้และ import pyspark จริง เป็นการตรวจขั้นต่ำเท่านั้น ไม่ได้บอกว่าโค้ดถูกหรือตรง template การตรวจว่าตรง template เป็นหน้าที่ของ log_skill_validate_spark_job ในอีก server

พารามิเตอร์: `filename`*

#### spark_submit_job

ต้นฉบับ
> Submit one immutable snapshot with single-process persistent replay safety. HDFS arguments must use the physical path returned by an HDFS tool, for example ``/mcp/lab/input.log``, or the equivalent full URI ``hdfs://namenode:9000/mcp/lab/input.log``. Never pass an HDFS MCP virtual path such as ``/lab/input.log`` to Spark. An idempotency key requires the trusted caller's expected code hash. Durable reservations make replays safe across restarts, but the asyncio lock does not coordinate multiple MCP server replicas. Snapshots and terminal state are intentionally retained for audit.

ภาษาไทย: สั่งรัน job โดย server จะถ่าย snapshot ของโค้ดตอนนั้นไว้ไม่ให้เปลี่ยนอีก path ทุกตัวใน arguments ต้องเป็น physical ถ้าใส่ idempotency_key ต้องใส่ expected_sha256 คู่กัน server จะเช็คว่าโค้ดที่กำลังจะรันมี hash ตรงกับที่ผู้เรียกคาดไว้ และถ้าสั่งซ้ำด้วย key เดิมจะคืน job เดิมแทนที่จะรันใหม่ แม้ server จะ restart ไปแล้ว snapshot และสถานะสุดท้ายเก็บไว้ตลอดเพื่อ audit ข้อจำกัดที่ประกาศคือถ้ามี MCP server หลายตัวพร้อมกัน lock จะไม่ครอบคลุม

พารามิเตอร์: `filename`*, `arguments`, `conf`, `idempotency_key`, `expected_sha256`

#### spark_job_status

ต้นฉบับ
> Return durable status for a submitted job.

ภาษาไทย: ถามสถานะของ job ที่ส่งไป ต้องวนถามจนกว่าจะไม่ใช่ RUNNING ค่าที่ต้องการคือ SUCCEEDED พร้อม exit_code 0 สถานะนี้คงอยู่แม้ server restart

พารามิเตอร์: `job_id`*

#### spark_job_logs

ต้นฉบับ
> Return combined stdout/stderr from a submitted job.

ภาษาไทย: อ่าน log ของ job เมื่อล้ม นี่คือที่เดียวที่จะเห็นสาเหตุจริง เช่น path ซ้ำ (errorifexists) หรือ parser ไม่ตรง ค่าเริ่มต้นดึง 200 บรรทัดท้าย

พารามิเตอร์: `job_id`*, `tail_lines` (ค่าเริ่มต้น 200)

#### spark_list_jobs

ต้นฉบับ
> List recent MCP-submitted jobs.

ภาษาไทย: ดูรายการ job ที่ส่งผ่าน MCP ล่าสุด ใช้ตอนหา job_id ที่หายหรือดูว่าใครรันอะไรไว้

พารามิเตอร์: `limit` (ค่าเริ่มต้น 20)

#### spark_cancel_job

ต้นฉบับ
> Cancel a running Spark job submitted by this server process.

ภาษาไทย: ยกเลิก job ที่กำลังรัน ทำได้เฉพาะ job ที่ server ตัวนี้เป็นคนส่ง

พารามิเตอร์: `job_id`*

---

## Server 2: Security skill (14 tool)

### คำสั่งประจำ server

ต้นฉบับ

> Discover approved vendor parsers and trusted security analytics workflows. Render and validate Spark jobs and reports without executing skill code. Published skills are read-only. Drafts can be saved for Git review, but this server never promotes drafts or executes code from a skill.

ภาษาไทย: server นี้เป็นคลัง skill ที่ผ่านการอนุมัติ มีสองชนิดคือ parser skill (นิยามว่า log แบบไหนอ่านอย่างไร map เข้าฟิลด์กลางอย่างไร) และ workflow skill (เจ้าของ template Spark และ contract ของรายงาน) หน้าที่คือ render และ validate เท่านั้น ไม่รันโค้ดใด ๆ skill ที่ publish แล้วแก้ไม่ได้ ร่าง skill ใหม่ได้แต่จะกลายเป็นของจริงต่อเมื่อคน review และ merge ผ่าน Git เท่านั้น นี่คือจุดที่ "คนเป็นผู้ตรวจ" ถูกบังคับด้วยระบบ ไม่ใช่แค่กติกาในห้องเรียน

### กลุ่มค้นหา skill

#### log_skill_list

ต้นฉบับ
> List approved parser and parserless workflow skills.

ภาษาไทย: ดูรายชื่อ skill ทั้งหมด (ตอนนี้ 23 ตัว แบ่ง 12 parser และ 11 workflow) พร้อม parser id, vendor, product, log_type, format และสถานะ ไม่มีพารามิเตอร์

#### log_skill_search

ต้นฉบับ
> Search skill metadata and parser vendor/product/log-type fields.

ภาษาไทย: ค้นด้วยคำ เช่น "suricata" หรือ "dns" ตรงกับชื่อ คำอธิบาย vendor product หรือ log_type เร็วกว่า list เมื่อรู้ว่าหาอะไร

พารามิเตอร์: `query`*

#### log_skill_get

ต้นฉบับ
> Get one published skill and its parser contracts.

ภาษาไทย: อ่าน SKILL.md ของ skill หนึ่งตัวพร้อม contract ของ parser ที่อยู่ในนั้น นี่คือที่อยู่ของ "กติกา 6 ข้อ" ที่ Lab 2 อ้างถึง และเป็นสิ่งที่ Claude ต้องอ่านก่อนลงมือทุกครั้ง

พารามิเตอร์: `skill_name`*, `include_body` (ค่าเริ่มต้น true)

#### log_skill_resolve

ต้นฉบับ
> Rank approved parsers for one sample using metadata and deterministic parsing.

ภาษาไทย: ส่ง log หนึ่งบรรทัดเข้าไป server จะลองทุก parser ที่อนุมัติแล้วเรียงว่าตัวไหนอ่านได้ดีที่สุด ใช้ตอบคำถาม "บรรทัดนี้ใช้ parser ไหน" ใน Lab 1 ถ้าไม่มีตัวไหนอ่านได้จะบอกตรง ๆ ซึ่งคือสถานการณ์ของบรรทัด sshd ระบุ vendor, product, log_type เพิ่มได้เพื่อจำกัดวง

พารามิเตอร์: `sample`*, `vendor`, `product`, `log_type`

### กลุ่มอ่านไฟล์ใน skill

#### log_skill_list_resources

ต้นฉบับ
> List readable published references, scripts, and assets; never execute them.

ภาษาไทย: ดูว่า skill มีไฟล์แนบอะไร เช่น template `.tmpl`, contract JSON, policy, sample log พร้อมขนาดและ sha256 ของแต่ละไฟล์ ประกาศชัดว่าไม่รัน

พารามิเตอร์: `skill_name`*

#### log_skill_read_resource

ต้นฉบับ
> Read one allowlisted UTF-8 published resource as inert text; never execute it.

ภาษาไทย: อ่านไฟล์แนบหนึ่งไฟล์เป็นข้อความธรรมดา นี่คือวิธีดู template Spark ก่อนที่จะ render เพื่อรู้ว่าโค้ดที่จะรันหน้าตาเป็นอย่างไร มีช่องให้เติมตรงไหน อ่านได้เฉพาะไฟล์ที่อยู่ใน allowlist

พารามิเตอร์: `skill_name`*, `resource_path`*

### กลุ่มทดสอบและตรวจ

#### log_skill_test_parser

ต้นฉบับ
> Run a deterministic approved parser against up to 100 sample records.

ภาษาไทย: เอา log จริงไม่เกิน 100 บรรทัดไปทดสอบกับ parser ที่ระบุ คืนผลว่าแต่ละบรรทัด parse ได้ไหม ได้ฟิลด์อะไร ค่าอะไร คำว่า approved สำคัญ tool นี้รับเฉพาะ parser ที่ publish แล้ว draft ทดสอบผ่าน tool นี้ไม่ได้ (ยืนยันแล้วใน Lab 1 ขั้น 3) คำว่า deterministic หมายถึงผลเหมือนเดิมทุกครั้ง ไม่มี AI เดา

พารามิเตอร์: `skill_name`*, `parser_id`*, `samples`*

#### log_skill_validate

ต้นฉบับ
> Validate published skill frontmatter, parser contracts, and bundled samples.

ภาษาไทย: ตรวจความสมบูรณ์ของ skill ที่ publish แล้ว ว่า frontmatter ครบ contract ถูกรูป และ sample ที่แนบมา parse ผ่าน ใช้ตอนสงสัยว่า skill บน server เสียหรือเปล่า

พารามิเตอร์: `skill_name`*

#### log_skill_render_spark_job

ต้นฉบับ
> Render trusted Spark code with one approved parser; never execute skill code.

ภาษาไทย: เอา template ของ workflow มาเติม parser ที่ระบุลงในช่อง `__PARSER_JSON_LITERAL__` แล้วคืนโค้ด PySpark เต็มพร้อม code_sha256 server เป็นคนเลือก workflow จาก log_type ของ parser เอง ดังนั้น skill_name ต้องเป็น parser skill ไม่ใช่ workflow skill ถ้าใส่ผิดจะ error นี่คือสิ่งที่เกิดใน Lab 2 รอบแรก Claude ไม่ได้เขียนโค้ดเอง มันแค่สั่ง render

พารามิเตอร์: `skill_name`*, `parser_id`*

#### log_skill_validate_spark_job

ต้นฉบับ
> Check Spark code against its approved parser and exact trusted template.

ภาษาไทย: เอาโค้ดที่กำลังจะรันมาเทียบกับ template ต้นฉบับทีละตัวอักษร คืน `matches_trusted_template` true หรือ false พร้อมรายการ check ถ้า false แปลว่ามีใครแก้โค้ด นี่คือการตรวจที่ spark_validate_job ทำไม่ได้ และเป็นข้อที่คนต้องดูด้วยตาก่อน submit

พารามิเตอร์: `skill_name`*, `parser_id`*, `code`*

#### log_skill_validate_report

ต้นฉบับ
> Validate one in-memory report against its trusted report contract.

ภาษาไทย: เอา report JSON ที่ Spark เขียนออกมาส่งกลับไปตรวจกับ contract เช่น ids-report-v1 ว่ามีทุกฟิลด์ที่ต้องมี ชนิดถูก ค่าไม่ขัดกัน server อ่าน `report_contract_version` ในตัว report เองว่าจะใช้ contract ไหน การตรวจนี้บอกว่ารายงานถูกรูป ไม่ได้บอกว่าตัวเลขในนั้นหมายถึงอะไร

พารามิเตอร์: `report`* (JSON object)

### กลุ่ม draft

#### log_skill_save_draft

ต้นฉบับ
> Validate and save a parser or parserless draft for later Git review.

ภาษาไทย: บันทึกร่าง skill ใหม่ โดยส่ง SKILL.md และ parser YAML (ถ้าเป็น parser skill) server จะตรวจรูปแบบก่อนรับ แล้วเก็บไว้ในที่แยกจาก skill จริง ร่างนี้ใช้กับ test_parser หรือ render ไม่ได้จนกว่าคนจะ review และ merge ผ่าน Git ค่าเริ่มต้นไม่เขียนทับร่างชื่อซ้ำ

พารามิเตอร์: `skill_name`*, `skill_markdown`*, `parser_yaml`, `overwrite` (ค่าเริ่มต้น false)

#### log_skill_list_drafts

ต้นฉบับ
> List draft skills awaiting human review and Git promotion.

ภาษาไทย: ดูรายการร่างที่รอคนตรวจ คำว่า human review อยู่ในต้นฉบับเอง ไม่มีพารามิเตอร์

#### log_skill_get_draft

ต้นฉบับ
> Get a draft skill and its optional parser YAML for review.

ภาษาไทย: อ่านร่างกลับมาดูเพื่อ review นี่คือสิ่งที่ reviewer ใช้ใน Lab 1 ขั้น 3 เพื่อตัดสินว่า parser ที่ Claude ร่างให้ควรเข้า Git ไหม

พารามิเตอร์: `skill_name`*

---

## tool ที่แต่ละ lab เรียกใช้

นับจากไฟล์ lab ของผู้สอน ไม่รวม tool ที่ Claude อาจเรียกเพิ่มเอง

| lab | Spark/HDFS | Security skill |
| --- | --- | --- |
| 0 | hdfs_mkdir, spark_list_jobs, spark_job_status | log_skill_list, log_skill_list_drafts, log_skill_read_resource, log_skill_validate_spark_job, log_skill_validate_report |
| 1 | hdfs_read_lines | log_skill_resolve, log_skill_test_parser, log_skill_get, log_skill_save_draft, log_skill_list_drafts, log_skill_get_draft |
| 2 | hdfs_mkdir, hdfs_list, hdfs_read_text, spark_save_job, spark_validate_job, spark_submit_job, spark_job_status, spark_job_logs, spark_replace_job_text | log_skill_get, log_skill_render_spark_job, log_skill_validate_spark_job, log_skill_validate_report |
| 2b | hdfs_mkdir, hdfs_query_records, hdfs_read_text, spark_save_job, spark_read_job, spark_validate_job, spark_submit_job, spark_job_status | log_skill_get, log_skill_read_resource, log_skill_validate_spark_job |
| 3 | hdfs_read_lines, hdfs_query_records, hdfs_correlate_records, hdfs_pcap_packets | (ไม่ใช้) |
| 3b | hdfs_read_text, spark_save_job, spark_validate_job, spark_submit_job, spark_job_status | log_skill_get, log_skill_read_resource, log_skill_render_spark_job, log_skill_validate_spark_job, log_skill_validate_report |
| 3c | hdfs_query_records | (ไม่ใช้) |
| 4 | hdfs_mkdir, hdfs_import_file, hdfs_write_text, hdfs_query_records | (ไม่ใช้) |
| 5 | hdfs_list, hdfs_read_text | log_skill_validate_report |

tool ที่ไม่มี lab ไหนเรียกตรง ๆ: hdfs_stat, hdfs_sha256, hdfs_delete, hdfs_cluster_status, spark_cluster_status, spark_cancel_job, log_skill_search, log_skill_validate (Lab 2 ขั้น 11 ใช้ hdfs_sha256 แต่เขียนไว้ในตาราง tool ไม่ใช่ใน prompt)

## สิ่งที่ไม่มีใน server ทั้งสอง

- ไม่มี tool ที่ตัดสินว่าอะไรคือการโจมตี ทั้ง hdfs_query_records และ hdfs_correlate_records เขียนไว้ชัดในต้นฉบับว่า "No attack labels" และ "No attack verdict"
- ไม่มี tool ที่รันโค้ดจาก skill หรือ promote draft ต้องผ่าน Git โดยคน
- ไม่มี tool ที่เขียนทับ output โดยไม่ตั้งใจ ทุกตัวที่เขียนมี overwrite เป็น false โดยปริยาย และ template ใช้ errorifexists
- ไม่มี tool ที่ติดต่อ SIEM, ticket, หรือ threat intel ภายนอก การ enrich ใน Lab 4 จึงต้องนำข้อมูลเข้ามาเองผ่าน hdfs_import_file
