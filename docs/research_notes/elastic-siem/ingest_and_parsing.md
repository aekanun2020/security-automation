# Elastic Stack ingest & normalization of security logs (vs. QRadar DSM/LEEF) — research notes, verified 2026-11-02

Scope: Elastic 9.x. All URLs below were fetched on 2026-11-02 unless marked otherwise. Package versions come from the public Elastic Package Registry (EPR, `https://epr.elastic.co`) queried the same day; "docs page" versions come from `elastic.co/docs/reference/integrations/<name>` and can be newer than what EPR serves to a given Kibana version (see Gaps). Items marked **[inferred]** are my reasoning, not a quoted source.

---

## Key Question 1 — Elastic Agent integrations (the "DSM equivalent"): catalog, license, and the specific integrations requested

### Takeaway
Elastic's DSM equivalent is the **integration package** (an "Elastic Package") served by the Elastic Package Registry and installed through Fleet; each package bundles agent input config, ingest pipelines, ECS field mappings, index templates and dashboards. As of 2026-11-02 EPR serves **422 latest-version packages compatible with Kibana 9.2.0** (373 `integration`, 32 `input`, 17 `content`) and **510 with no Kibana constraint**; the `elastic/integrations` repo `packages/` directory holds 508 entries. Every requested source except **Wazuh** and **LEEF** has a first-party package; there is **no LEEF package, no LEEF Elastic Agent processor and no LEEF Elasticsearch ingest processor** anywhere in Elastic's tooling.

### Cited Findings

**Catalog, repo, license, count**
- "This repository contains sources for Elastic Integrations." Each integration is an Elastic Package that "may define configuration for the Elastic Agent as well as assets"; the README links the Package Specification (`github.com/elastic/package-spec`), the `elastic-package` CLI (`github.com/elastic/elastic-package`), `CONTRIBUTING.md`, and companion AI-agent skills at `elastic/integration-skills` (with a `CLAUDE.md` for Claude Code users) — [github.com/elastic/integrations](https://github.com/elastic/integrations)
- License text of the repo: "Source code in this repository is licensed under multiple licenses. Source code in a given file is licensed under the Elastic License Version 2.0, unless otherwise noted at the beginning of the file or a LICENSE.txt file present in the directory subtree declares another license. Built packages include a copy of the applicable license." — [LICENSE.txt](https://raw.githubusercontent.com/elastic/integrations/main/LICENSE.txt). GitHub reports the repo license as `NOASSERTION` (i.e., not a single SPDX license), 339 stars, last push 2026-11-02 — [GitHub API, repos/elastic/integrations](https://api.github.com/repos/elastic/integrations)
- Every package I inspected on EPR declares `conditions.elastic.subscription: basic` (i.e., usable on the free Basic tier): system, windows, winlog, nginx, apache, zeek, suricata, cef, fortinet_fortigate, panw, cisco_asa, cisco_ftd, cisco_ios, aws, o365, filestream, udp, tcp, log, auditd, ibm_qradar, syslog_router, sysmon_linux — [EPR package manifests, e.g. https://epr.elastic.co/package/cef/2.24.0](https://epr.elastic.co/package/cef/2.24.0)
- Counts (my EPR queries, 2026-11-02): `GET https://epr.elastic.co/search?all=false&kibana.version=9.2.0` → 422 packages (types: integration 373, input 32, content 17); `…&kibana.version=9.0.0` → 371; `GET https://epr.elastic.co/search?all=false` (no Kibana filter) → 510 (integration 402, content 63, input 45). Category tags across the 510: security 312, observability 202, opentelemetry 90, network 76, cloud 76, custom 44 — [epr.elastic.co/search](https://epr.elastic.co/search?all=false&kibana.version=9.2.0)
- `packages/` directory in `elastic/integrations` main branch: 508 entries — [GitHub contents API](https://api.github.com/repos/elastic/integrations/contents/packages)
- Human-readable catalog: "Integration quick reference" at `https://www.elastic.co/docs/reference/integrations/all_integrations`; individual pages follow `https://www.elastic.co/docs/reference/integrations/<slug>` (nested for some, e.g. `/integrations/aws/cloudtrail`). The old `docs.elastic.co/en/integrations` host is still what Elastic's ingest overview links to — [all_integrations](https://www.elastic.co/docs/reference/integrations/all_integrations); [Ingestion overview](https://www.elastic.co/docs/manage-data/ingest)
- Elastic Security Labs (2026-04-04): "Each integration ships with ingest pipelines that normalize and structure data out of the box"; "All nine integrations in this roundup ship with prebuilt dashboards and native ECS mappings." — [Elastic Security Integrations Roundup Q1 2026](https://www.elastic.co/security-labs/elastic-security-integrations-roundup-q1-2026)

**Per-integration facts** (EPR manifest = `data_stream` names, `streams[].input`, asset counts; docs page = behavior). Format: `dataset[type]:inputs`.

| Requested source | Exact package name / title | EPR version (Kibana 9.2.0) | Inputs | Data streams | Dashboards / pipelines in package |
|---|---|---|---|---|---|
| Linux system/auth | `system` / **System** | 2.7.2 (docs page shows 3.3.0, requires Kibana ^9.2.1) | `logfile`, `journald`, `winlog`, `system/metrics` | `system.auth[logs]:journald/logfile`, `system.syslog[logs]:journald/logfile`, `system.security/application/system[logs]:winlog`, + 13 metrics streams | 15 dashboards, 14 pipelines |
| nginx | `nginx` / **Nginx** | 3.2.2 | `logfile`, `nginx/metrics` | `nginx.access[logs]`, `nginx.error[logs]`, `nginx.stubstatus[metrics]` | 3 / 2 |
| apache | `apache` / **Apache HTTP Server** | 3.0.2 | `logfile`, `apache/metrics` | `apache.access[logs]`, `apache.error[logs]`, `apache.status[metrics]` | 2 / 2 |
| Windows / Sysmon | `windows` / **Windows** | 3.12.1 | `winlog`, `windows/metrics` | `windows.sysmon_operational`, `windows.powershell`, `windows.powershell_operational`, `windows.forwarded`, `windows.windows_defender`, 4× `windows.applocker_*` (all `[logs]:winlog`), `windows.perfmon`, `windows.service` | 3 / 16 |
| Windows (any channel) | `winlog` / **Custom Windows Event Logs** | 2.6.1 | `winlog` (input package, no fixed dataset) | user-defined | 0 / 0 |
| Sysmon for Linux | `sysmon_linux` / **Sysmon for Linux** | 1.9.1 | `filestream` | `sysmon_linux.log[logs]` | 1 / 1 |
| Zeek | `zeek` / **Zeek** | 5.0.1 | `logfile` | 43 streams `zeek.<log>` (capture_loss, connection, dce_rpc, dhcp, dnp3, dns, dpd, files, ftp, http, intel, irc, kerberos, known_certs, known_hosts, known_services, modbus, mysql, notice, ntlm, ntp, ocsp, pe, radius, rdp, rfb, signature, sip, smb_cmd, smb_files, smb_mapping, smtp, snmp, socks, software, ssh, ssl, stats, syslog, traceroute, tunnel, weird, x509) | 1 / 43 |
| Suricata | `suricata` / **Suricata** | 2.27.1 | `logfile` | `suricata.eve[logs]` | 2 / 5 |
| CEF (ArcSight) | `cef` / **Common Event Format (CEF)** | 2.24.0 | `logfile`, `tcp`, `udp` | `cef.log[logs]` | 4 / 3 |
| Syslog RFC3164/5424 | `udp` / **Custom UDP Logs**; `tcp` / **Custom TCP Logs**; `syslog_router` / **Syslog Router** | udp 2.4.0 (docs 2.5.1), tcp 2.2.0 (docs 2.3.1), syslog_router 1.0.1 | udp / tcp / (`filestream`,`tcp`,`udp`) | user-defined (`udp.generic` default); `syslog_router.log[logs]` | 0 / 0; syslog_router 0 / 1 |
| Cisco | `cisco_asa` / **Cisco ASA** 2.47.2; `cisco_ftd` / **Cisco FTD** 3.15.0; `cisco_ios` / **Cisco IOS** 1.37.0 | — | `logfile`, `tcp`, `udp` each | `cisco_asa.log`, `cisco_ftd.log`, `cisco_ios.log` | 1/1, 0/1, 0/1 |
| Fortinet | `fortinet_fortigate` / **Fortinet FortiGate Firewall Logs** | 1.36.11 | `logfile`, `tcp`, `udp` | `fortinet_fortigate.log[logs]` | 1 / 5 |
| Palo Alto | `panw` / **Palo Alto Next-Gen Firewall** | 5.5.3 | `logfile`, `tcp`, `udp` | `panw.panos[logs]` | 10 / 16 |
| Wazuh | **none** | — | — | — | — |
| AWS CloudTrail | `aws` / **AWS** (policy template `cloudtrail`) | 5.3.1 (docs/EPR-latest 8.15.0 requires Kibana ^9.6.0) | `aws-s3`, `aws-cloudwatch` | `aws.cloudtrail[logs]` (one of 46 AWS streams) | 53 / 42 (whole AWS package) |
| Microsoft 365 | `o365` / **Microsoft Office 365** | 4.0.2 | `cel` (current), `o365audit` (deprecated) | `o365.audit[logs]` | 2 / 1 |
| LEEF | **none** | — | — | — | — |
| QRadar (as a *source*) | `ibm_qradar` / **IBM QRadar** | 1.2.0 | `cel` | `ibm_qradar.offense[logs]` | 1 / 1 |
| Custom files | `filestream` / **Custom Logs (Filestream)** 2.3.3 (docs 2.5.1, Kibana ^9.4.0); `log` / **Custom Logs (Deprecated)** 2.4.4 | — | filestream / log | user-defined | 0 / 0 |

Sources for the table: EPR manifests ([system](https://epr.elastic.co/package/system/2.7.2), [windows](https://epr.elastic.co/package/windows/3.12.1), [winlog](https://epr.elastic.co/package/winlog/2.6.1), [nginx](https://epr.elastic.co/package/nginx/3.2.2), [apache](https://epr.elastic.co/package/apache/3.0.2), [zeek](https://epr.elastic.co/package/zeek/5.0.1), [suricata](https://epr.elastic.co/package/suricata/2.27.1), [cef](https://epr.elastic.co/package/cef/2.24.0), [udp](https://epr.elastic.co/package/udp/2.4.0), [tcp](https://epr.elastic.co/package/tcp/2.2.0), [syslog_router](https://epr.elastic.co/package/syslog_router/1.0.1), [cisco_asa](https://epr.elastic.co/package/cisco_asa/2.47.2), [cisco_ftd](https://epr.elastic.co/package/cisco_ftd/3.15.0), [cisco_ios](https://epr.elastic.co/package/cisco_ios/1.37.0), [fortinet_fortigate](https://epr.elastic.co/package/fortinet_fortigate/1.36.11), [panw](https://epr.elastic.co/package/panw/5.5.3), [aws](https://epr.elastic.co/package/aws/5.3.1), [o365](https://epr.elastic.co/package/o365/4.0.2), [ibm_qradar](https://epr.elastic.co/package/ibm_qradar/1.2.0), [filestream](https://epr.elastic.co/package/filestream/2.3.3), [log](https://epr.elastic.co/package/log/2.4.4), [sysmon_linux](https://epr.elastic.co/package/sysmon_linux/1.9.1)).

Behavioral details from the docs pages:
- **System**: ingestion methods "API, File, journald"; collects "auth and syslog events on macOS or Linux" and Windows Application/System/Security channels; dashboards include "[Logs System] New users and groups" reading ECS `user.target.name`/`user.target.id`; journald collection inside containers needs the `elastic-agent-complete` image; Windows event queries limited to about 22 conditions — [System integration](https://www.elastic.co/docs/reference/integrations/system)
- **Windows**: "Log collection for the Security, Application, and System event logs is handled by the System integration"; Windows integration covers "forwarded events, PowerShell events, and Sysmon events", Defender and AppLocker; "Because the Windows integration always applies to the local server, the `hosts` config option is not needed." — [Windows integration](https://www.elastic.co/docs/reference/integrations/windows)
- **Zeek**: "relies on JSON-formatted logs"; enable with `@load policy/tuning/json-logs.zeek` in `local.zeek` then `sudo zeekctl deploy`; default base paths `/var/log/bro/current`, `/opt/zeek/logs/current`, `/usr/local/var/spool/zeek`; dashboards "Network Traffic", "Protocol Overview" — [Zeek integration](https://www.elastic.co/docs/reference/integrations/zeek)
- **Suricata**: "The `eve` data stream collects all event types from Suricata's EVE JSON log output", path "typically `/var/log/suricata/eve.json`"; dashboard "[Logs Suricata] Overview"; compatible with Suricata 5.x/6.x/7.x and Elastic Stack ≥ 8.11.0 — [Suricata integration](https://www.elastic.co/docs/reference/integrations/suricata)
- **CEF**: UDP default port 9003, TCP 9004; "automatically parses the CEF header and the extension fields for the `cef.log` data stream"; tested with Forcepoint NGFW SMC 6.6.1 and Check Point Log Exporter; `cef.extensions.*` and `checkpoint.*` non-ECS fields retained; dashboards found by searching "CEF"; **LEEF not mentioned** — [CEF integration](https://www.elastic.co/docs/reference/integrations/cef)
- **Custom UDP Logs**: default `udp.generic` dataset, listen `localhost:8080`, "Syslog Parsing" toggle that will "automatically parse RFC 3164 and RFC 5424 formatted messages", "Syslog Options" YAML (format, timezone), "Preserve Original Event" → `event.original`, optional "ID of a custom ingest pipeline to process logs on the server side", optional agent-level processors; "Use the logs data stream" advanced option requires ES ≥ 9.2.0 — [Custom UDP Logs](https://www.elastic.co/docs/reference/integrations/udp)
- **Custom Logs (Filestream)**: "new, improved alternative to the `log` input"; migrating from deprecated Custom Logs re-ingests files because "the state is not migrated"; files < 1024 bytes are not ingested until they reach that size unless "Fingerprint length" is changed; GZIP decompression GA as of 9.3.0 — [Custom Logs (Filestream)](https://www.elastic.co/docs/reference/integrations/filestream)
- **Fortinet FortiGate**: collects "traffic, UTM, event, and authentication logs"; tested "against FortiOS versions 6.x and 7.x up to 7.4.1"; "The integration does not parse the `csv`, `cef`, or `json` formats" (only the default key-value syslog format); network direction derived from "Internal/External interfaces" and "Internal networks" settings; dashboard "Fortinet FortiGate Overview" — [Fortinet FortiGate](https://www.elastic.co/docs/reference/integrations/fortinet_fortigate)
- **Palo Alto**: "compatible with PAN-OS versions 10.2, 11.1 and 11.2"; log types GlobalProtect, HIP Match, Threat, Traffic, User-ID, Audit, Authentication, Config, Correlated Events, Decryption, GTP, IP-Tag, SCTP, System, Tunnel Inspection; dashboards found by searching "Logs PANW" — [Palo Alto Next-Gen Firewall](https://www.elastic.co/docs/reference/integrations/panw)
- **AWS CloudTrail**: "The `cloudtrail` data stream collects AWS CloudTrail logs"; ingestion methods API, AWS CloudWatch, AWS S3; S3+SQS mode recommended over bucket polling — [AWS CloudTrail](https://www.elastic.co/docs/reference/integrations/aws/cloudtrail)
- **Microsoft Office 365**: data stream `o365.audit`; CEL input replaced the deprecated `o365audit` input in 1.18.0; workloads Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All; needs Entra ID app registration with `ActivityFeed.Read`; dashboards "Office 365 Audit Dashboard", "Office 365 User Dashboard" — [Microsoft Office 365](https://www.elastic.co/docs/reference/integrations/o365)
- **IBM QRadar** (Elastic pulls *from* QRadar): "The QRadar integration collects offense records from QRadar's offense and rules endpoints"; "This integration is the foundation of Elastic's SIEM migration workflow for QRadar" which "uses semantic search and generative AI to map existing rules to Elastic's 1,300+ prebuilt detections" and translates unmapped rules to ES|QL — [Security Labs Q1 2026 roundup](https://www.elastic.co/security-labs/elastic-security-integrations-roundup-q1-2026); docs page lists version 0.1.1 / "Ingestion method(s) | API", QRadar API version 20.0 — [IBM QRadar integration](https://www.elastic.co/docs/reference/integrations/ibm_qradar)

**LEEF — negative results (all verified 2026-11-02)**
- EPR package names/titles containing `leef`, `qradar`, `arcsight`: only `ibm_qradar` — [EPR search](https://epr.elastic.co/search?all=false)
- `gh search code leef --repo elastic/integrations`: only hits are the `beyondtrust_epm` package's sample data containing the literal string `"siem_format": "LEEF"` (a field value, not a parser) — [github.com/elastic/integrations packages/beyondtrust_epm](https://github.com/elastic/integrations/tree/main/packages/beyondtrust_epm)
- `gh search code leef --repo elastic/beats`: no LEEF processor (only a false-positive community_id hash) — [github.com/elastic/beats](https://github.com/elastic/beats)
- The Elastic Agent `decode_cef` processor page: "The `decode_cef` processor decodes Common Event Format (CEF) messages." LEEF not mentioned — [decode_cef processor](https://www.elastic.co/docs/reference/fleet/decode_cef-processor)
- Elasticsearch ingest processor reference lists grok, dissect, kv, csv, json, etc. — no CEF or LEEF processor — [Ingest processor reference](https://www.elastic.co/docs/reference/enrich-processor)
- Elastic community thread on moving QRadar data into Elasticsearch exists but shows no official LEEF tooling — [discuss.elastic.co "QRadar data into Elasticsearch"](https://discuss.elastic.co/t/qradar-data-into-elasticsearch/224800)
- Third-party only: `RyPeck/python-LEEF` (Python module for *creating* LEEF for QRadar), `cyamato/SyslogPro` (Node syslog module supporting LEEF/CEF) — [GitHub repo search "leef"](https://github.com/search?q=leef&type=repositories); Tenzir documents `print_leef` to emit LEEF toward QRadar — [docs.tenzir.com/integrations/qradar](https://docs.tenzir.com/integrations/qradar/)

**Wazuh — negative result**
- No `wazuh` package on EPR — [EPR search](https://epr.elastic.co/search?all=false)
- Wazuh's own guide: Logstash `file` input reads `/var/ossec/logs/alerts/alerts.json` (`codec => "json"`, `mode => "tail"`), outputs to `elasticsearch` with `index => "wazuh-alerts-4.x-%{+YYYY.MM.dd}"`, template `wz-es-4.x-8.x-template.json` (`total_fields.limit` 10000), dashboards `wz-es-4.x-8.x-dashboards.ndjson`, data view `wazuh-alerts-*` — [Wazuh Elastic Stack integration](https://documentation.wazuh.com/current/integrations-guide/elastic/index.html); Wazuh 4.x guide lists "Elastic Agent, Beats, or Logstash" as possible forwarders and says the Wazuh indexer path "uses Logstash as a data forwarder" — [Wazuh integrations guide 4.8](https://documentation.wazuh.com/4.8/integrations-guide/index.html); Wazuh blog: "from version 4.6, we will not develop these integrated applications any longer" (the Kibana/Elastic plugins) — [wazuh.com blog](https://wazuh.com/blog/detection-with-new-integration-methods/)

**Installing: Fleet API and standalone YAML**
- Fleet API routes (Kibana source constants): `API_ROOT = /api/fleet`; `EPM_API_ROOT = /api/fleet/epm`; packages list `GET /api/fleet/epm/packages`; installed list `/api/fleet/epm/packages/installed`; bulk install `POST /api/fleet/epm/packages/_bulk`; package policies `/api/fleet/package_policies`; agent policies `/api/fleet/agent_policies`; "INSTALL_FROM_REGISTRY_PATTERN" reuses the single-package pattern (`EPM_PACKAGES_ONE`) — [kibana routes.ts](https://github.com/elastic/kibana/blob/main/x-pack/platform/plugins/shared/fleet/common/constants/routes.ts)
- Fleet API docs example: create agent policy `POST https://my-kibana-host:9243/api/fleet/agent_policies?sys_monitoring=true` with headers `Authorization: ApiKey yourbase64encodedkey`, `kbn-xsrf: xxx`, `Content-Type: application/json`, body `{"name":"Agent policy 1","namespace":"default","monitoring_enabled":["logs","metrics"]}`; create integration policy `POST /api/fleet/package_policies` with body containing `"name": "nginx-demo-123"`, `"policy_id": "<agent policy id>"`, `"package": {"name": "nginx", "version": "1.5.0"}` and an `inputs` object defining `nginx-logfile` with `nginx.access` / `nginx.error` streams; the UI offers "Preview API request" to generate exact bodies — [Fleet APIs](https://www.elastic.co/docs/reference/fleet/fleet-api-docs)
- Standalone agent: "use Kibana to create and download a standalone configuration file rather than trying to build it by hand"; `outputs.default` needs `api_key` or credentials; install with `sudo ./elastic-agent install` (Linux/macOS); "If you used Kibana to generate the standalone configuration, the assets are set up automatically. Otherwise, you need to install them" (assets = dashboards, ingest pipelines, templates) — [Install standalone Elastic Agent](https://www.elastic.co/docs/reference/fleet/install-standalone-elastic-agent)
- Standalone input structure: `type` is "Required. The type of the input. Must match an input listed in Elastic Agent inputs."; `use_output` "Must match an output defined in the same policy"; "If not set, `data_stream.dataset` defaults to `generic` and `data_stream.namespace` defaults to `default`." — [Elastic Agent input configuration](https://www.elastic.co/docs/reference/fleet/elastic-agent-input-configuration). Composed example (illustrative, assembled from documented keys):
  ```yaml
  inputs:
    - id: lab-filestream
      type: filestream
      use_output: default
      data_stream.namespace: lab
      streams:
        - id: lab-auth
          data_stream:
            dataset: system.auth      # routes to logs-system.auth-lab
          paths:
            - /lab/data/auth.log
  ```
- Elastic Agent input types (page "Elastic Agent inputs"): `filestream` ("Reads lines from active log files. Replaces and improves on the `log` input."), `log` ("DEPRECATED: Use the `filestream` input instead."), `logfile` ("Alias for `log`."), `journald` (Beta), `udp`, `tcp`, `winlog` ("Reads from one or more event logs using Windows APIs", Winlogbeat), `syslog` ("Reads Syslog events as specified by RFC 3164 and RFC 5424, over TCP, UDP, or a Unix stream socket."), `httpjson`, `cel`, `aws-s3`, `aws-cloudwatch`, `o365audit` (Beta), `kafka`, `netflow` — [Elastic Agent inputs list](https://www.elastic.co/docs/reference/fleet/elastic-agent-inputs-list)

### Inferences
- **[inferred]** Most first-party security integrations (nginx, apache, zeek, suricata, cef, firewalls) still use the `logfile` input type (alias of the deprecated `log` input) in their manifests, while the generic custom package has moved to `filestream`. For a lab, pointing a `filestream`/`logfile` stream at static files works identically.
- **[inferred]** For LEEF in Elastic you must write your own parser: the LEEF header is pipe-delimited and attributes are tab-separated `key=value` (see KQ6), so a `dissect` on the header + `kv` processor (field_split `\t`, value_split `=`) in an ingest pipeline is the natural approach. No Elastic source documents this; it is my design suggestion.
- **[inferred]** Wazuh in an Elastic lab = treat Wazuh `alerts.json` as a custom NDJSON source (Custom Logs (Filestream) with the `ndjson` parser, or Logstash as Wazuh documents).
- **[inferred]** The docs-page version being higher than the EPR version served for Kibana 9.2.0 (System 3.3.0 vs 2.7.2; Filestream 2.5.1 vs 2.3.3; AWS 8.15.0 vs 5.3.1) means newest package versions gate on newer Kibana (^9.2.1, ^9.4.0, ^9.6.0). A course should pin the stack version and query EPR with `kibana.version=` to know what students will actually see.

### Gaps
- Elastic publishes no official total count of integrations on the catalog page; the 422/510/508 figures are my own EPR/GitHub queries (reproducible but unofficial).
- Exact ECS field lists per integration were truncated on the docs pages (they run 100k–3M characters); use `https://epr.elastic.co/package/<name>/<version>` → `data_streams[].fields` or the package `fields/*.yml` for exhaustive lists.
- Fleet API docs pages for "install package" (`/api/doc/kibana/operation/operation-install-package`) returned 404 at the URLs I tried; the path pattern `POST /api/fleet/epm/packages/{pkgName}/{pkgVersion}` is widely used but I could only confirm the route constants, not the rendered API reference.
- Default syslog ports for FortiGate/PAN-OS integrations: docs show 9004 only as an example for FortiGate; PAN-OS page excerpt gives none.

---

## Key Question 2 — Parsing mechanisms and tradeoffs: ingest pipelines vs Logstash vs Elastic Agent processors; custom pipelines; `@custom` extension pattern

### Takeaway
Elastic's recommended default is Elastic Agent + integration, with normalization done **server-side in Elasticsearch ingest pipelines** (grok/dissect/date/geoip/set/rename/script/enrich/kv/…, testable with `_simulate`). Agent processors are for light edge sanitization and "execute before ingest pipelines"; Logstash is added only for buffering, routing, multi-destination or sources Agent can't read, and can even run integration pipelines itself via the Enterprise-only `elastic_integration` filter. To extend an integration without breaking upgrades, create the Fleet-provided `*@custom` pipelines, which Fleet appends to every integration pipeline in the fixed order `global@custom` → `<type>@custom` → `<type>-<package>.integration@custom` → `<type>-<dataset>@custom`.

### Cited Findings

**Ingest pipelines (Elasticsearch)**
- Pipelines are stored in cluster state and run on nodes with the `ingest` role; dedicated ingest nodes recommended for heavy loads. `index.default_pipeline` applies when a request has no `pipeline` param; `index.final_pipeline` runs after the request/default pipeline "even when neither is specified." — [Ingest pipelines](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/ingest-pipelines)
- Same page on Fleet: "Elastic Agent integrations ship with default pipelines applied through index templates. Each default pipeline calls a nonexistent, unversioned `*@custom` pipeline. Left unchanged, that call does nothing. You can modify the call to create custom pipelines that persist across upgrades." — [Ingest pipelines](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/ingest-pipelines)
- Simulate API: "You can specify a configured pipeline in the request path" or define a `pipeline` inline; body `docs[]` holds sample `_source`; response returns transformed docs — [Simulate pipeline API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ingest-simulate). Composed example (illustrative):
  ```http
  POST _ingest/pipeline/_simulate
  {
    "pipeline": {
      "processors": [
        { "grok": { "field": "message",
            "patterns": ["%{SYSLOGTIMESTAMP:ts} %{HOSTNAME:host.hostname} sshd\\[%{POSINT:process.pid}\\]: Failed password for %{USERNAME:user.name} from %{IP:source.ip}"] } },
        { "date": { "field": "ts", "formats": ["MMM  d HH:mm:ss","MMM dd HH:mm:ss"], "target_field": "@timestamp" } },
        { "set":  { "field": "event.category", "value": ["authentication"] } },
        { "set":  { "field": "event.type", "value": ["start"] } },
        { "set":  { "field": "event.outcome", "value": "failure" } },
        { "geoip": { "field": "source.ip", "target_field": "source.geo", "ignore_missing": true } },
        { "remove": { "field": "ts" } }
      ]
    },
    "docs": [ { "_source": { "message": "Oct 31 09:12:01 web01 sshd[1234]: Failed password for root from 203.0.113.9 port 51234 ssh2" } } ]
  }
  ```
- Processor catalogue (official): enrichment — `append`, `enrich` ("Adds data from another index to incoming documents"), `geoip` (MaxMind lookup), `community_id`, `fingerprint`, `network_direction`, `registered_domain`; transformation — `grok` ("Extracts structured fields out of a single text field within a document"), `dissect` ("Unlike the grok processor, dissect does not use regular expressions."), `date`, `set`, `rename`, `script` (Painless ingest context), `kv`, `csv`, `json`, `user_agent`, `convert`, `redact`; filtering — `remove`, `drop`; control — `pipeline`, `fail`, `foreach` — [Ingest processor reference](https://www.elastic.co/docs/reference/enrich-processor)
- ECS conversion page: Kibana can generate a pipeline from a CSV mapping: "Stack Management > Ingest Pipelines > Create pipeline > New pipeline from CSV" (CSV ≤ 100 MB) — [Converting an implementation to ECS](https://www.elastic.co/docs/reference/ecs/ecs-converting)

**Elastic Agent processors**
- Fleet guidance table: use an "Elastic Agent processor" to "Sanitize or enrich raw data at the source"; use ingest pipelines to "Convert data to ECS, normalize field data, or enrich incoming data." "Logstash plugins and ingest pipelines both require you to send data to another system for processing." "Processors, on the other hand, allow you to apply processing logic at the source." Processors "execute before ingest pipelines"; they "May break integration ingest pipelines in Elasticsearch if the user-defined processing removes or alters fields expected by ingest pipelines"; "Some integrations do not currently support processors." — [Define processors (Elastic Agent)](https://www.elastic.co/docs/reference/fleet/agent-processors)
- `syslog` processor: "parses RFC 3164 or RFC 5424 formatted syslog messages that are stored in a field"; options `field` (default `message`), `format` `auto|rfc3164|rfc5424`, `timezone` (default `Local`), `ignore_missing`, `ignore_failure`, `overwrite_keys`; populates `log.syslog.priority`, `log.syslog.facility.code/name`, `log.syslog.severity.code/name`, `log.syslog.hostname`, `log.syslog.appname`, `log.syslog.procid`, `log.syslog.msgid`, `log.syslog.version`, `log.syslog.structured_data`, sets `@timestamp` and rewrites `message`. Example: `- syslog:\n    field: message` — [syslog processor](https://www.elastic.co/docs/reference/fleet/syslog-processor)
- `decode_cef` processor: options `field` (default `message`), `target_field` (default `cef`), `ecs` (default `true`, "Whether to generate Elastic Common Schema (ECS) fields from the CEF data"), `timezone` (default `UTC`), `ignore_missing`, `ignore_failure`. Documented example:
  ```yaml
    - rename:
        fields:
          - {from: "message", to: "event.original"}
    - decode_cef:
        field: event.original
  ```
  — [decode_cef processor](https://www.elastic.co/docs/reference/fleet/decode_cef-processor)

**Logstash**
- Reference architectures: "Elastic Agent writing directly to Elasticsearch on Elastic Cloud provides the easiest and fastest time to value"; add Logstash when you need "enrichment between Elastic Agent and Elasticsearch", "persistent queue (PQ) buffering to accommodate network issues and downstream unavailability", "proxying in cases where Elastic Agents have network restrictions", or "data needs to be routed to multiple Elasticsearch clusters and other destinations depending on the content"; Logstash alone when "You need to collect data from a source that Elastic Agent can't read (such as databases, AWS Kinesis)." Architecture pages: agent-to-es, agent-ls, agent-proxy, agent-kafka-es, ls-for-input, airgapped-env — [Ingest architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures)
- Ingestion overview: "Usually, the simplest option for ingesting time series data is using Elastic Agent paired with an Elastic integration." If none exists, Automatic Import "can generate a custom integration from a data sample." — [Ingestion overview](https://www.elastic.co/docs/manage-data/ingest)
- `elastic_integration` filter: "Use this filter to process Elastic integrations powered by Elasticsearch Ingest Node in Logstash." Looks up each event's pipeline in Elasticsearch and executes it locally; sets `[@metadata][target_ingest_pipeline]` to `_none` so the output won't rerun it; failures tagged `_ingest_pipeline_failure`. "Use of this plugin requires an active Elastic Enterprise subscription." Needs Java 21+ with Logstash 9.x; user privileges `monitor`, `read_pipeline`, `manage_index_templates`; `script` processors must be Painless; output must have `data_stream` enabled and `ecs_compatibility` `v1`/`v8`. Example:
  ```
  filter {
    elastic_integration {
      cloud_id   => "YOUR_CLOUD_ID_HERE"
      cloud_auth => "YOUR_CLOUD_AUTH_HERE"
      geoip_database_directory => "/etc/your/geoip-databases"
    }
  }
  ```
  — [elastic_integration filter](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-elastic_integration)
- Grok filter: "Logstash ships with about 120 patterns by default."; syntax `%{SYNTAX:SEMANTIC}`; example `%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}`; "If you need help building patterns to match your logs, try the Grok debugger in Kibana." — [Logstash grok filter](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok). Pattern library repo: [logstash-plugins/logstash-patterns-core](https://github.com/logstash-plugins/logstash-patterns-core/tree/main/patterns) (URL from training knowledge; the docs page's link was blank in the fetched text — **[unverified link]**)

**Custom source with no integration**
- Custom UDP/TCP/Filestream packages accept "the ID of a custom ingest pipeline to process logs on the server side" plus agent-level processors — [Custom UDP Logs](https://www.elastic.co/docs/reference/integrations/udp)
- Fleet warns that modifying Fleet's own integration pipelines can break data streams, but "Fleet doesn't provide an ingest pipeline for the Custom logs integration," so custom logs can be configured more safely — [docs preview of data-streams-pipeline-tutorial](https://docs-v3-preview.elastic.dev/elastic/docs-content/pull/8199/reference/fleet/data-streams-pipeline-tutorial.md)
- Building a real package with `elastic-package`: commands shown are `elastic-package create package`, `elastic-package create data-stream`, `elastic-package lint`, `elastic-package format`, `elastic-package build`, `elastic-package check`, `elastic-package stack up --version=8.12.2 -v`, `elastic-package install`; layout `manifest.yml`, `changelog.yml`, `data_stream/log/manifest.yml`, `data_stream/log/fields/fields.yml`, `data_stream/log/elasticsearch/ingest_pipeline/default.yml`, `data_stream/log/agent/stream/stream.yml.hbs`, `_dev/build/build.yml`. Example `default.yml`:
  ```yaml
  description: Pipeline for processing sample logs
  processors:
  - dissect:
      field: message
      pattern: "%{@timestamp} %{log.level} %{message}"
  on_failure:
  - set:
      field: error.message
      value: '{{ _ingest.on_failure_message }}'
  ```
  — [Quick start: sample integration](https://www.elastic.co/docs/extend/integrations/quick-start); process overview — [Build an integration](https://www.elastic.co/docs/extend/integrations/build-new-integration)
- Pipeline tests: live in `data_stream/<stream>/_dev/test/pipeline/`; inputs `test-*.log` (raw lines "as they would arrive at ingestion after any Agent processors run") or `test-*.json` (`events` array); optional `test-*.log-config.yml` with `fields`, `dynamic_fields` (regex), `numeric_keyword_fields`, `multiline`; expected output `test-*.log-expected.json`; run `elastic-package test pipeline`; `--generate` writes expected files ("It cannot know if this is actually correct"); under the hood it uploads pipelines and runs them through the Simulate API — [Pipeline testing](https://www.elastic.co/docs/extend/integrations/pipeline-testing)
- Automatic Import: LLM generates an ingest pipeline mapping to ECS from samples (JSON/NDJSON, CSV, syslog structured/unstructured); Elastic Stack requires an **Enterprise** subscription; Stack 9.4+/Serverless: up to 1,000 samples, 100,000 chars each, 10 MB per LLM request; Stack 9.0–9.3 send only the first 100 samples; result installs as a custom integration — [Automatic Import](https://www.elastic.co/docs/explore-analyze/ai-features/automatic-import)

**`@custom` pipelines and templates (extension pattern)**
- Fleet source (Kibana `helpers.ts`, `addCustomPipelineAndLocalRoutingRulesProcessor`) appends these `pipeline` processors, in this order, each with `ignore_missing_pipeline: true`: `global@custom` ("[Fleet] Global pipeline for all data streams"), `${type}@custom`, `${type}-${package}.integration@custom` (comment: "This pipeline name gets the `.integration` suffix to avoid conflicts with the pipeline name for the dataset below"), `${type}-${dataset}@custom`; then any `reroute` processors from the package's routing rules — [kibana helpers.ts](https://github.com/elastic/kibana/blob/main/x-pack/platform/plugins/shared/fleet/server/services/epm/elasticsearch/ingest_pipeline/helpers.ts)
- Tutorial: custom pipeline "will run after the default pipeline but before the final pipeline"; naming `<type>-<dataset>@custom` e.g. `metrics-system.cpu@custom`; `logs@custom` example uses a `set` processor adding `my-logs-field: "true"` — [Tutorial: Transform data with custom ingest pipelines](https://www.elastic.co/docs/reference/fleet/data-streams-pipeline-tutorial). Composed example for a lab (illustrative):
  ```http
  PUT _ingest/pipeline/logs-system.auth@custom
  { "processors": [ { "set": { "field": "labels.lab", "value": "week3" } } ] }
  ```
- Component templates Fleet creates on install: `<data_stream_type>@custom` (e.g. `logs@custom`), `<name_of_data_stream>@custom`, since 9.1 `<package>@custom`, since 9.5 optional `<namespace>@custom`; "In the component template chain, later entries take precedence." — [Fleet data streams](https://www.elastic.co/docs/reference/fleet/data-streams)

### Inferences
- **[inferred]** Division of labor for a course: agent processors ≈ QRadar "protocol-level" tweaks; ingest pipeline ≈ the DSM parser; `@custom` ≈ QRadar Log Source Extension / DSM Editor overrides layered on a vendor DSM without editing it.
- **[inferred]** Because `elastic_integration` and Automatic Import are Enterprise-only, a *free* lab should standardize on Elasticsearch ingest pipelines (+ `_simulate`) and the `elastic-package test pipeline` workflow, which is Apache-2.0 tooling with no license gate (license of `elastic-package` not verified here — see Gaps).
- **[inferred]** For a Codex-driven build "from files", the `_dev/test/pipeline/test-*.log` + `*-expected.json` convention is the natural unit-test harness: Codex can generate expected files with `--generate`, then a human reviews.

### Gaps
- Could not fetch an Elastic page that explicitly contrasts "ingest pipeline vs Logstash filter" performance; recommendations above come from architecture pages, not a benchmark.
- The Fleet UI route for attaching a custom pipeline to an integration data stream (Integrations → data stream → "Custom ingest pipeline" link) was not captured verbatim.
- License of `elastic-package` CLI not checked.

---

## Key Question 3 — ECS: version, base/required fields, categorization fields, mapping guide, ecs-logging, OpenTelemetry convergence, 9.x/EDOT impact

### Takeaway
Current ECS is **9.5.0** (released 2026-08-04); the only hard-required field is `@timestamp`, with `ecs.version` strongly recommended; Elastic Security's rules key off the four categorization fields `event.kind`/`event.category`/`event.type`/`event.outcome` with closed vocabularies. ECS–OTel convergence (OTEP 199, announced 2023) is still an *alignment in progress* tracked per-namespace against OTel SemConv 1.38.0; ECS remains the schema that integrations produce. In Elastic Stack 9.5 the EDOT Collector capability is built into Elastic Agent, but security integrations still write ECS to `logs-*-*`.

### Cited Findings
- "This is the documentation of ECS version 9.5.0." — [ECS reference](https://www.elastic.co/docs/reference/ecs)
- GitHub releases: `v9.5.0` 2026-08-04, `v9.4.0` 2026-05-19, `v9.3.0` 2026-02-03 — [github.com/elastic/ecs/releases](https://github.com/elastic/ecs/releases)
- Base field set: `@timestamp` (date, core) "Date/time when the event originated." "Required field for all events."; `labels` (object, core) "Custom key/value pairs."; `message` (match_only_text, core) "For log events the message field contains the log message, optimized for viewing in a log viewer."; `tags` (keyword, core) "List of keywords used to tag each event." Only `@timestamp` is marked required — [ECS Base fields](https://www.elastic.co/docs/reference/ecs/ecs-base)
- Guidelines: "Fields that are most common across all use cases are defined as **core fields**." "Any field that is not a core field is defined as an **extended field**." "The document MUST have the `@timestamp` field." "Use the `ecs.version` field to define which version of ECS is used." "Map as many fields as possible to ECS." Fields sent via API "must be nested objects, not strings containing dots." — [ECS guidelines](https://www.elastic.co/docs/reference/ecs/ecs-guidelines)
- Categorization: the four fields `event.kind`, `event.category`, `event.type`, `event.outcome` hold the "What it is" information independent of source; "If your events don't match any of these categorization values, you should leave the fields empty." — [ECS categorization fields](https://www.elastic.co/docs/reference/ecs/ecs-category-field-values-reference)
- `event.kind` values: `alert` (events from detection rules "run outside the Elastic Stack, such as firewalls or intrusion detection systems"), `asset` (Beta; "used by Elastic Security for asset management solutions"), `enrichment`, `event` ("the most general and most common value"), `metric`, `state`, `pipeline_error` (ingestion error), `signal` ("used by Elastic solutions (e.g., Security, Observability) for alert documents" — reserved; pipelines must not set it) — [event.kind allowed values](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind)
- `event.category` ("This field is an array.") with expected `event.type`: api (access, admin, allowed, change, creation, deletion, denied, end, info, start, user); authentication (start, end, info); configuration (access, change, creation, deletion, info); database (access, change, info, error); driver (change, end, info, start); email (info); file (access, change, creation, deletion, info); host (access, change, end, info, start); iam (admin, change, creation, deletion, group, info, user); intrusion_detection (allowed, denied, info); library (start); malware (info); network (access, allowed, connection, denied, end, info, protocol, start); package (access, change, deletion, info, installation, start); process (access, change, end, info, start); registry (access, change, creation, deletion); session (start, end, info); threat (indicator); vulnerability (info); web (access, error, info) — [event.category allowed values](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category); `event.type` — [allowed values](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-type); `event.outcome` — [allowed values](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-outcome)
- Mapping guide ("Converting an implementation to ECS"): 1) map each original field to an ECS Core field, else Extended, else keep/rename per ECS naming; 2) populate Core fields including static ones, e.g. "add `event.category:authentication`" for auth events, plus host/container/cloud metadata; 3) populate Extended fields; 4) "Set `ecs.version` to the version of the schema you are conforming to." Optional spreadsheet → CSV → Kibana "New pipeline from CSV" — [ecs-converting](https://www.elastic.co/docs/reference/ecs/ecs-converting); full field reference — [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference)
- OTel convergence: 2023 joint announcement targets "convergence of ECS and OTel Semantic Conventions into a single open schema that is maintained by OpenTelemetry"; OTel SemConv are meant to become the successor to ECS; references OTEP 199 "Merge Elastic Common Schema with OpenTelemetry Semantic Conventions"; no timeline given — [OpenTelemetry blog](https://opentelemetry.io/blog/2023/ecs-otel-semconv-convergence/); Elastic announcement — [elastic.co blog](https://elastic.co/blog/ecs-elastic-common-schema-otel-opentelemetry-announcement); OTEP text — [OTEP 199](https://github.com/open-telemetry/oteps/blob/d02a3e2e75dc934fb38c5db88eb41fbe85730af4/text/0199-support-elastic-common-schema-in-opentelemetry.md)
- Alignment status page compares "ECS in version `9.5.0`" with "OpenTelemetry semantic conventions in version `1.38.0`" per namespace, e.g. TLS 29 ECS/28 OTel, 26 match; URL 14/13, 12 match; Process 34/34, 15 match + 2 equivalent; File 24/18, 11 match + 7 equivalent; HTTP 13/12, 1 match, 5 equivalent, 2 related, 1 conflict; Host 19/15, 5 match. No overall total given — [ECS OTel alignment overview](https://www.elastic.co/docs/reference/ecs/ecs-otel-alignment-overview)
- EDOT: "an open-source ecosystem of OpenTelemetry distributions tailored to Elastic"; before 9.5 "the **EDOT Collector** was a standalone product"; "From this version onwards, this OpenTelemetry collector capability is built into **Elastic Agent**" (table lists Elastic Agent 9.5.5 GA) — [Elastic Distributions of OpenTelemetry](https://www.elastic.co/docs/reference/opentelemetry)
- EPR shows 90 packages tagged `opentelemetry` and companion "OpenTelemetry Assets" packages (e.g. "Apache HTTP Server (OpenTelemetry)", "AWS CloudTrail Logs OpenTelemetry Assets") in the catalog — [EPR search](https://epr.elastic.co/search?all=false); [all_integrations](https://www.elastic.co/docs/reference/integrations/all_integrations)
- ecs-logging page fetch returned 404 at `https://www.elastic.co/docs/reference/ecs/logging` (see Gaps). ECS-formatted application logs are covered at [ECS formatted application logs](https://www.elastic.co/docs/solutions/observability/logs/ecs-formatted-application-logs) (URL from Elastic's ingest tools page, not fetched).

### Inferences
- **[inferred]** For detection-rule compatibility, a custom pipeline should at minimum set `@timestamp`, `ecs.version`, `event.kind: event`, `event.category[]`, `event.type[]`, `event.outcome`, and keep raw text in `event.original`; prebuilt Elastic Security rules filter on these plus `event.dataset`/`data_stream.dataset`.
- **[inferred]** Nothing in 9.x changes the ECS contract for security integrations: integration pipelines still emit ECS into `logs-<dataset>-<namespace>`; the OTel path is additive ("OpenTelemetry Assets" content packages) rather than a replacement, and ECS still gets new releases (9.3→9.5 in 2026).

### Gaps
- Did not retrieve the ecs-logging library page (404 at the guessed URL); the list of ecs-logging languages (Java/.NET/Node/Python/Go/PHP/Ruby) is from prior knowledge, **unverified** here.
- No official statement found on whether/when ECS will be frozen in favor of OTel SemConv; alignment page is the only status tracker.

---

## Key Question 4 — Ingesting offline files for a lab: filestream for static files, `_bulk`, Python client, EVTX on macOS

### Takeaway
Static files can be read with Elastic Agent `filestream` (or integration `logfile` inputs) exactly like live files; bulk loading uses `_bulk` NDJSON (data streams accept only `create`) or `elasticsearch.helpers.bulk/streaming_bulk/parallel_bulk` with an optional `pipeline`. Winlogbeat *can* replay archived `.evtx`, but it is a Windows service binary — on macOS use `evtx_dump` (Rust; prebuilt macOS binary) or `pyevtx-rs`/`evtx2es`/`python-evtx` to produce JSON/JSONL, then bulk-index through a pipeline; Hayabusa/Chainsaw also emit JSON/JSONL but their output is already enriched/aggregated.

### Cited Findings
- Filestream input: "Reads lines from active log files. Replaces and improves on the `log` input."; `log` is "DEPRECATED" — [Elastic Agent inputs list](https://www.elastic.co/docs/reference/fleet/elastic-agent-inputs-list). Custom Logs (Filestream) caveat: files under 1024 bytes are not ingested until they reach that size unless "Fingerprint length" is adjusted; "Removing files after ingestion" option added in 2.2.0; GZIP decompression GA 9.3.0 — [Custom Logs (Filestream)](https://www.elastic.co/docs/reference/integrations/filestream)
- `_bulk`: "The actions are specified in the request body using a newline delimited JSON (NDJSON) structure"; "The final line of data must end with a newline character (`\n`)."; "Data streams support only the `create` action."; `pipeline` = "The pipeline identifier to use to preprocess incoming documents."; "use a `Content-Type` header of `application/json` or `application/x-ndjson`"; example `curl -s -H "Content-Type: application/x-ndjson" -XPOST localhost:9200/_bulk --data-binary "@requests"; echo` ("you must use the `--data-binary` flag instead of plain `-d`") — [Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk). Composed data-stream example (illustrative):
  ```
  POST /logs-lab.auth-default/_bulk?pipeline=logs-lab.auth@custom
  { "create": {} }
  { "@timestamp": "2026-10-31T09:12:01Z", "message": "Failed password for root from 203.0.113.9", "data_stream": {"type":"logs","dataset":"lab.auth","namespace":"default"} }
  ```
- Python helpers: bulk helpers accept a client and an iterable of actions; a generator "allows you to index large datasets without the need of loading them into memory"; action dict may contain `'_index'`, `'_id'`, `'_routing'`, `'pipeline': 'my-ingest-pipeline'`, `'_source': {...}`; `_op_type` "defaults to `index`" and accepts `index`, `create`, `delete`, `update`; async variants use the `async_` prefix — [Python client helpers](https://www.elastic.co/docs/reference/elasticsearch/clients/python/client-helpers). Signatures from source: `streaming_bulk(client, actions, chunk_size=500, max_chunk_bytes=100*1024*1024, flush_after_seconds=None, raise_on_error=True, expand_action_callback=expand_action, raise_on_exception=True, max_retries=0, initial_backoff=2, …)`; `bulk(client, actions, stats_only=False, ignore_status=(), *args, **kwargs)` "consumes an iterator of actions and sends them to elasticsearch in chunks. It returns a tuple with summary information"; `parallel_bulk(client, actions, thread_count=4, chunk_size=500, max_chunk_bytes=…, queue_size=4, …)` — [elasticsearch-py helpers/actions.py](https://github.com/elastic/elasticsearch-py/blob/main/elasticsearch/helpers/actions.py). Composed snippet (illustrative, matches documented action format):
  ```python
  from elasticsearch import Elasticsearch, helpers
  es = Elasticsearch("https://localhost:9200", api_key="…", verify_certs=False)
  def gen(path):
      for line in open(path, encoding="utf-8"):
          yield {"_op_type": "create", "_index": "logs-lab.auth-default",
                 "pipeline": "logs-lab.auth@custom",
                 "_source": {"message": line.rstrip("\n"),
                             "data_stream": {"type":"logs","dataset":"lab.auth","namespace":"default"}}}
  ok, errors = helpers.bulk(es, gen("auth.log"), raise_on_error=False, stats_only=False)
  ```
- Winlogbeat and EVTX: "Yes, Winlogbeat can ingest archived .evtx files."; config `winlogbeat.event_logs: - name: ${EVTX_FILE}  no_more_events: stop`, `winlogbeat.shutdown_timeout: 30s`, `winlogbeat.registry_file: evtx-registry.yml`; run `.\winlogbeat.exe -e -c .\winlogbeat-evtx.yml -E EVTX_FILE=c:\backup\Security-2019.01.evtx` — [Winlogbeat: reading from .evtx](https://www.elastic.co/docs/reference/beats/winlogbeat/reading-from-evtx). Winlogbeat README: "Winlogbeat is an open-source log collector that ships Windows Event Logs to Elasticsearch or Logstash. It installs and runs as a Windows service." — [beats/winlogbeat/README.md](https://github.com/elastic/beats/blob/main/winlogbeat/README.md); install guide is PowerShell-only ("Download the Winlogbeat zip file", "Open a PowerShell prompt as an Administrator") — [Winlogbeat quick start](https://www.elastic.co/docs/reference/beats/winlogbeat/winlogbeat-installation-configuration)
- Rust `evtx` / `evtx_dump`: "A cross-platform parser for the Windows XML EventLog format"; prebuilt 64-bit executables for Windows, macOS, Linux (`cargo install evtx` also works); `evtx_dump -o json <evtx_file>`; `cat <evtx_file> | evtx_dump -o jsonl -`; `evtx_dump -f <output_file> -o json <input_file>`; batch: `fd -e evtx -x evtx_dump -o jsonl`; Python bindings `pyevtx-rs` (PyPI package `evtx`); dual Apache-2.0/MIT — [github.com/omerbenamram/evtx](https://github.com/omerbenamram/evtx); [pyevtx-rs](https://github.com/omerbenamram/pyevtx-rs); [PyPI evtx](https://pypi.org/project/evtx/)
- `evtx2es` (PyPI): bulk-imports `.evtx` into Elasticsearch using `pyevtx-rs`; options for host, port, index, bulk size, credentials/HTTPS; includes `evtx2json` for offline JSON; "does not verify the certificate in the current version" — [pypi.org/project/evtx2es](https://pypi.org/project/evtx2es/1.3.1)
- `python-evtx`: "a pure Python parser for recent Windows Event Log files"; `pip install python-evtx`; scripts `evtx_info.py`, `evtx_templates.py`, `evtx_dump.py` (binary XML → XML), `evtx_dump_json.py` (→ JSON); Apache-2.0 — [github.com/williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)
- Elastic forum thread on ingesting .evtx files exists ("Windows Events with evtx") — [discuss.elastic.co](https://discuss.elastic.co/t/windows-events-with-evtx/264565); community approaches: Dragos "EvtxToElk" offline module — [dragos.com](https://dragos.com/?p=1503); RSM "Manually upload EVTX log files to ELK with Winlogbeat and PowerShell" (Windows host) — [warroom.rsmus.com](https://warroom.rsmus.com/manually-upload-evtx-log-files-to-elk-with-winlogbeat-and-powershell/)
- Chainsaw: "Can be run on MacOS, Linux and Windows."; `hunt` supports `--json`, e.g. `./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --from "2019-03-17T19:09:39" --to "2019-03-17T19:09:50" --json`; `dump` is documented for "MFT, registry hives, ESE databases" with `--json`/`--jsonl` (EVTX not explicitly listed for dump); GPL-3.0 — [github.com/WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw)
- Hayabusa: "Windows event log fast forensics timeline generator and threat hunting tool"; outputs "CSV / JSON / JSONL timeline" "ready for analysis in LibreOffice, Timeline Explorer, Elastic Stack, Timesketch and more"; AGPLv3 (rules under DRL 1.1) — [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa). Elastic import doc command: `./hayabusa dfir-timeline -t jsonl -d ../hayabusa-sample-evtx -w -p super-verbose -G /opt/homebrew/var/GeoIP -o results.jsonl` (macOS Homebrew GeoIP path), then import via SOF-ELK's `/logstash/hayabusa` directory with config `6650-hayabusa-jsonl.conf`; index pattern `evtxlogs-*`; macOS note about Local Network privacy blocking Kibana access — [Hayabusa ElasticStackImport-English.md](https://github.com/Yamato-Security/hayabusa/blob/main/doc/ElasticStackImport/ElasticStackImport-English.md). Older community sources use `json-timeline -L` / `--JSONL-output` (flag names differ by version) — [GitHub issue #1324](https://github.com/yamato-security/hayabusa/issues/1324)

### Inferences
- **[inferred]** Winlogbeat cannot be used on macOS to read `.evtx`: the docs never list a non-Windows build and the README describes it as a Windows service; the request's premise "winlogbeat cannot read .evtx offline" is **half right** — it *can* read archived .evtx, but only on a Windows host.
- **[inferred]** Recommended macOS lab path: `evtx_dump -o jsonl Security.evtx > security.jsonl` → Python `helpers.streaming_bulk` into `logs-windows.security-lab` (or a custom dataset) via an ingest pipeline that reshapes `Event.System.*`/`Event.EventData.*` into `winlog.*` + ECS. The field layout from `evtx_dump` differs from Winlogbeat's `winlog.event_data.*`, so the Windows integration's pipelines will **not** apply directly without a reshaping step — this is my assessment, not documented by Elastic.
- **[inferred]** Hayabusa/Chainsaw JSON is best treated as *findings* (Sigma hits), not raw telemetry; for teaching raw-event normalization use `evtx_dump`/`pyevtx-rs` output.

### Gaps
- No Elastic-supported, documented procedure exists for `.evtx` → Elasticsearch on macOS/Linux; all routes are third-party.
- Did not verify `evtx2es` compatibility with Elasticsearch 9.x clients.
- Hayabusa CLI flag set for the current version not verified against its command reference (README defers to external docs).

---

## Key Question 5 — Data streams, index templates, ILM, `logs-*-*` naming, namespaces, and verifying pipeline output

### Takeaway
Integrations write to data streams named `<type>-<dataset>-<namespace>` (e.g. `logs-nginx.access-prod`), matched by built-in `logs-*-*`/`metrics-*-*` index templates and dataset-specific templates (`logs-nginx.access-*`); `-` is forbidden inside components, namespace ≤ 100 bytes, defaults `generic`/`default`. ILM is attached via the `@custom` component templates (`logs@custom`, `<data_stream>@custom`, 9.1 `<package>@custom`, 9.5 `<namespace>@custom`). Verify parsing with `_simulate` (pre-index) and `_search` with `"fields"` + `"_source": false` (post-index).

### Cited Findings
- Naming scheme: `"<type>-<dataset>-<namespace>"`; type = `logs`, `metrics`, `traces`, `synthetics`; dataset "defined by the integration"; namespace "a user-configurable grouping"; examples `logs-nginx.access-prod`, `traces-apm-dev`; "A `namespace` can be up to 100 bytes in length (multibyte characters will count toward this limit faster)."; namespace defaults to the agent policy's, can be overridden per integration — [Fleet data streams](https://www.elastic.co/docs/reference/fleet/data-streams)
- Original design blog (2020-12-23): "In all three parts, the “-” character is not allowed."; defaults dataset=`generic`, namespace=`default`; unconfigured Elastic Agent file ingest lands in `logs-generic-default`; `logs-*-*` and `metrics-*-*` templates ship with Elasticsearch 7.9+; documents must carry `data_stream.type`, `data_stream.dataset`, `data_stream.namespace`, mapped as `constant_keyword`, which "makes querying on them efficient by reducing the number of shards that have to be queried" — [Elastic blog: data stream naming scheme](https://www.elastic.co/blog/an-introduction-to-the-elastic-data-stream-naming-scheme)
- Templates: "Elasticsearch provides built-in, ECS-based templates: `logs-*-*`, `metrics-*-*`, and `synthetics-*-*`"; integrations add dataset-specific templates like `logs-nginx.access-*`; Fleet creates `@custom` component templates `<data_stream_type>@custom`, `<name_of_data_stream>@custom`, since 9.1 `<package>@custom`, since 9.5 `<namespace>@custom`; "In the component template chain, later entries take precedence." — [Fleet data streams](https://www.elastic.co/docs/reference/fleet/data-streams)
- ILM: data streams "use an ILM policy that matches their data type" (example: `metrics-system.logs-*` uses the metrics ILM policy); ILM unavailable on Serverless; namespace-level templates (9.5) let you "apply one ILM policy to every data stream an integration produces in a single namespace" — [Fleet data streams](https://www.elastic.co/docs/reference/fleet/data-streams). Tutorial: edit `logs@custom` or `metrics@custom` for all data of a type, a data stream's own `@custom` template for one dataset, or clone the index template to scope to one namespace — [Customize data retention policies](https://www.elastic.co/docs/reference/fleet/data-streams-ilm-tutorial); Scenario 1 edits `logs@custom` index settings to `{"index":{"lifecycle":{"name":"my-ilm-policy"}}}`; "New ILM policies only take effect when new indices are created, so you either must wait for a rollover to occur." — [Scenario 1](https://www.elastic.co/docs/reference/fleet/data-streams-scenario1)
- Namespaces for access control: "Using a namespace makes it easier to search data from a given source by using a matching pattern." "You can also use matching patterns to give users access to data when creating user roles." — [Fleet data streams](https://www.elastic.co/docs/reference/fleet/data-streams)
- Verifying fields after indexing: "To retrieve specific fields in the search response, use the `fields` parameter."; it "returns values in the way that matches how Elasticsearch indexes them"; "The `fields` response always returns an array of values for each field"; "only leaf fields are returned"; supports wildcards, multi-fields, aliases; preferred over `_source` filtering — [Retrieve selected fields](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/retrieve-selected-fields). Composed check (illustrative):
  ```http
  GET logs-lab.auth-default/_search
  { "size": 3, "_source": false,
    "fields": ["@timestamp", "event.*", "source.ip", "user.name", "ecs.version"],
    "query": { "term": { "event.outcome": "failure" } } }
  ```
- Pre-index verification: `_simulate` (KQ2) and `elastic-package test pipeline`, which "processes the test inputs through the Simulate API" — [Pipeline testing](https://www.elastic.co/docs/extend/integrations/pipeline-testing)
- Custom UDP/TCP/Filestream packages expose "Use the logs data stream" (routes to the `logs`/`logs.ecs` index template instead of per-dataset) — requires ES ≥ 9.2.0 — [Custom UDP Logs](https://www.elastic.co/docs/reference/integrations/udp); [Custom Logs (Filestream)](https://www.elastic.co/docs/reference/integrations/filestream)

### Inferences
- **[inferred]** For an offline lab, choose a dedicated namespace (e.g. `lab`) so students can wipe `logs-*-lab` without touching other data and so a `<namespace>@custom` template (9.5+) can give the lab a short-retention ILM policy.
- **[inferred]** When bulk-indexing directly (bypassing Agent), you must set `data_stream.*` fields yourself and target a data stream name that matches an installed template, otherwise documents fall back to the generic `logs-*-*` template and integration mappings won't apply.

### Gaps
- The exact default ILM policy names (`logs`, `metrics`, or `logs@lifecycle`) were not stated on the pages fetched.
- Dataset character/length constraints beyond "no `-`" not found on current docs pages.

---

## Key Question 6 — Comparison material: Elastic vs QRadar DSM/LEEF (and Splunk TAs); IBM's definition of a DSM

### Takeaway
No Elastic or reputable third-party write-up directly compares Elastic integrations/ingest pipelines with QRadar DSMs or LEEF; the only Elastic↔QRadar artifacts are the `ibm_qradar` offense-collection integration and the AI-assisted rule-migration workflow. IBM's own docs define a DSM as a parsing/normalization code module with auto-detection, QID mapping and weekly auto-updates, extended via the DSM Editor and fed by LEEF — enough to build an apples-to-apples table from primary sources on each side.

### Cited Findings

**IBM (QRadar) side**
- DSM definition: "a code module that parses received events from multiple log sources and converts them to a standard taxonomy format"; normalization maps information to common field names "such as event name, IP addresses, protocol, and ports"; QRadar auto-detects some devices and creates a log source with default settings — "If QRadar does not automatically detect the log source, manually add a log source."; DSMs are installed as RPMs or via auto update: "The weekly automatic update includes new DSM releases, corrections to parsing issues, and protocol updates." — [IBM DSM guide overview](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/c_dsm_guide_install_manage_overview.html); adding a DSM — [t_dsm_guide_adding_single_dsm](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/t_dsm_guide_adding_single_dsm.html); DSM FAQ — [g_dsm_inst](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/g_dsm_inst.html); Log source extensions — [c_LogSourceGuide_ExtDocs_about](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/c_LogSourceGuide_ExtDocs_about.html)
- Supported DSM list: columns Manufacturer, Device name and version, Protocol, Recorded events and formats, Auto discovered?, Includes identity?, Includes custom properties?; the HTML contains 396 `<tr>` rows (my count; includes header rows, so roughly 390 product rows). Rows: "Open Source Linux OS 2.4 and later" (Syslog; auto-discovered yes); "Microsoft Windows Security Event Log" (Syslog, Forwarded, TLS Syslog, WinCollect…; "All events, including Sysmon and winlogbeats.json"); "HTTP Server V1.3+" Apache (Syslog, Syslog-ng); "NGINX HTTP Server 1.15.5" (Syslog); "ASA V7.x and later" (Syslog); "Fortinet FortiGate Security Gateway FortiOS 7.6.3 and earlier" (Syslog, Syslog Redirect); "Palo Alto PA Series" (Syslog, TLS Syslog); "Amazon AWS CloudTrail" (Amazon AWS S3 REST API; "Event versions 1.0 through 1.08"); "Microsoft Office 365" (Office 365 REST API; not auto-discovered). **Zeek/Bro and Suricata are not in the list** (only SNORT v2.x under Open Source) — [QRadar supported DSMs](https://www.ibm.com/docs/SS42VS_DSM/com.ibm.dsm.doc/r_supported_dsm_list.html)
- DSM Editor: "use the DSM Editor to solve parsing problems and to add custom parsing"; it is used to "extract fields, define custom properties, categorize events, and define new QID definition"; Property Autodetection generates properties automatically; Log Source Autodetection avoids manually creating "a log source for each instance"; Event Mapping "shows all the event ID and category combinations that are in the system" — [DSM Editor overview](https://www.ibm.com/docs/SSKMKU/com.ibm.qradar.doc/c_qradar_admin_data_ingestion.html) (page title as served; sub-pages: [properties](https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/c_qradar_adm_dsm_ed_properties.html), [event mapping](https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/c_qradar_adm_dsm_ed_eventmapping.html), [custom log source types](https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/c_qradar_adm_custom_log_source.html), [creating a custom log source type](https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/t_qradar_adm_dsm_ed_create_cust_logsource.html)); IBM "Develop a DSM" support page — [ibm.com/support/pages/develop-dsm](https://www.ibm.com/support/pages/develop-dsm)
- Unsupported sources: "if your log source is not a part of this DSM guide, then the event data ingested is either categorized as Stored or Unknown" — [Packt, Building a Next-Gen SOC with IBM QRadar, ch.5](https://www.packtpub.com/en-ph/product/building-a-next-gen-soc-with-ibm-qradar-7-9781801076029/chapter/chapter-5-leaving-no-data-behind/getting-to-know-dsm-editor) (secondary source)
- Coalescing: when four events arrive with the same key properties they are coalesced into a single record for 10 seconds; only the first (base) event keeps its full payload — [IBM Events FAQ](https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/c_troubleshooting_events_faq.html)
- LEEF: "The Log Event Extended Format (LEEF) is a customized event format for IBM® Security QRadar®."; "LEEF events must use UTF-8 character encoding."; transports: Syslog, or "File import with the Log File Protocol"; "Before QRadar can use LEEF events, you must complete Universal LEEF configuration tasks." — [LEEF overview](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/c_LEEF_Format_Guide_intro.html). Components: optional syslog header (`<13>Jan 18 11:07:53 192.168.1.1` RFC 3164 or `<13>1 2019-01-18T11:07:53.520Z 192.168.1.1` RFC 5424) followed by a space; "The LEEF header is a required field for LEEF events." pipe-delimited `LEEF:Version|Vendor|Product|Version|EventID|` e.g. `LEEF:2.0|Lancope|StealthWatch|1.0|41|^|`; "Every event attribute is a key and value pair with a tab that separates individual payload events." e.g. `src=192.0.2.0 dst=172.50.123.1 sev=5 cat=anomaly srcPort=81 dstPort=21 usrName=joe.black`; LEEF 2.0 lets you "specify an alternate delimiter" (`^`, `x5E`, `x7c`) — [LEEF event components](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/c_LEEF_Format_Guide_LEEFeventcomps.html); predefined attributes — [c_LEEF_Format_Guide_predefinedAttrrs](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/c_LEEF_Format_Guide_predefinedAttrrs.html); custom keys — [c_LEEF_Format_Guide_customkeys](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/c_LEEF_Format_Guide_customkeys.html); Universal LEEF — [c_DSM_guide_UniversalLEEF_intro](https://www.ibm.com/support/knowledgecenter/SS42VS_DSM/com.ibm.dsm.doc/c_DSM_guide_UniversalLEEF_intro.html); PDF guide — [b_Leef_format_guide.pdf](https://www.ibm.com/docs/en/SS42VS_DSM/com.ibm.dsm.doc/b_Leef_format_guide.pdf)

**Elastic ↔ QRadar / Splunk comparisons**
- Elastic's only QRadar-specific material: the `ibm_qradar` integration (offenses via `cel`) and the SIEM migration workflow (rule mapping to "1,300+ prebuilt detections", ES|QL translation) — [Security Labs Q1 2026](https://www.elastic.co/security-labs/elastic-security-integrations-roundup-q1-2026); [IBM QRadar integration](https://www.elastic.co/docs/reference/integrations/ibm_qradar)
- No Elastic blog/doc comparing integrations with DSMs or Splunk TAs was found in searches; third-party only: a Splunk→Elastic migration checklist says ECS replaces CIM as the normalization standard, "every Splunk TA providing CIM field mapping needs an Elastic equivalent, either an integration or a custom ingest pipeline", and that field-name mapping is the most common source of broken detections — [decryptiondigest.com checklist](https://www.decryptiondigest.com/blog/splunk-to-elastic-siem-migration-checklist) (secondary, unverified vendor-neutral blog)
- Generic product-comparison aggregators (not technical): [rfp.wiki Elastic vs Splunk](https://www.rfp.wiki/it-security/security-information-and-event-management/elastic/splunk); [getapp QRadar vs Elasticsearch](https://www.getapp.de/compare/113981/122079/ibm-qradar-siem/vs/elasticsearch) — low value.

**Apples-to-apples mapping (assembled from the primary sources above; the pairing itself is my synthesis — [inferred])**

| QRadar concept (IBM docs) | Elastic equivalent (Elastic docs) |
|---|---|
| DSM = "code module that parses received events … converts them to a standard taxonomy" | Integration package = agent input config + Elasticsearch ingest pipeline(s) + ECS field mappings + dashboards |
| Supported DSM list (~390 rows; weekly RPM auto-update) | EPR catalog (422 packages for Kibana 9.2.0; 510 total); versioned per package, upgraded via Fleet |
| Normalized taxonomy fields (event name, IPs, protocol, ports) + QID / high-/low-level category | ECS fields (`source.ip`, `destination.port`, `network.protocol`, …) + `event.kind/category/type/outcome` (+ `event.code`, `event.action`) |
| Log source auto-detection ("traffic analysis") | None: data stream is chosen by the agent policy/input (`data_stream.dataset`); `syslog_router` package can "Route syslog events to integrations" |
| DSM Editor / Log Source Extension (regex & JSON keypath; custom properties; event mapping) | `*@custom` ingest pipelines appended after the integration pipeline; `@custom` component templates for mappings; Kibana Ingest Pipelines UI / `_simulate` |
| Universal DSM / Universal LEEF for unknown sources; events otherwise "Stored"/"Unknown" | Custom Logs (Filestream) / Custom UDP/TCP Logs + custom pipeline; Automatic Import (Enterprise); unparsed docs land in `logs-generic-default` with raw `message` |
| LEEF (pipe header + tab `key=value`), CEF | CEF: `cef` package / `decode_cef` agent processor; LEEF: **no native support** (write `dissect` + `kv`) |
| Protocols: Syslog, TLS Syslog, Log File Protocol, WinCollect, S3 REST API, Office 365 REST API | Inputs: `udp`/`tcp`/`syslog`, `filestream`/`logfile`, `winlog`, `aws-s3`/`aws-cloudwatch`, `cel`/`httpjson`/`o365audit` |
| Coalescing of repeated events (10 s window) | No equivalent in ingest; aggregation is done at query/rule time (ES|QL, threshold rules) — **[inferred]** |

### Inferences
- **[inferred]** The biggest conceptual gap for QRadar-trained students is auto-detection: QRadar classifies incoming syslog by payload; Elastic requires you to declare the source per input (or use Syslog Router), so "which integration parses this?" is a configuration decision, not a runtime one.
- **[inferred]** Elastic's coverage of open-source sensors (Zeek 43 streams, Suricata) exceeds QRadar's DSM list, which lacks Zeek/Suricata entirely; conversely QRadar ships native LEEF/Universal DSM while Elastic has no LEEF parser.

### Gaps
- No direct, technical Elastic-vs-QRadar-DSM comparison exists from Elastic, IBM, or a reputable third party; the table above is assembled from primary docs on each side.
- IBM's authoritative event-pipeline page (Event Collector → parsing → QID mapping → coalescing → Event Processor) was not retrieved; the URL I tried served the DSM Editor overview. Pipeline-stage ordering appears only in vendor sales decks (not cited as fact).
- Exact count of supported DSMs is not published by IBM as a number; 396 table rows is my HTML count.
- QRadar QID/category taxonomy reference page not fetched.
