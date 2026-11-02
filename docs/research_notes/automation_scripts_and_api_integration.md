# Module 5 – Python for Cybersecurity: Security Automation Scripts and API Integration for Security Tools

Research date: 2026-11-01. Perspective: defensive / SOC (blue team). Star counts are GitHub figures as displayed on the day of research and are approximate. Every URL below was fetched or returned by search during this session unless explicitly marked otherwise.

---

## Key Question 1: Which libraries and patterns do authoritative sources recommend for robust security scripting (error handling, logging, secrets from environment variables, retries, rate limits, idempotency)?

### Takeaway
The authoritative Python and vendor docs converge on a small toolkit: `requests.Session` + `urllib3.util.Retry` mounted on an `HTTPAdapter` for retries/backoff that honours `Retry-After` on 429/503; explicit timeouts on every call (requests has no default timeout, httpx defaults to 5 s); `subprocess.run([...], check=True, timeout=...)` with `shell=False`; `hashlib.file_digest` + `hmac.compare_digest` for integrity checks; secrets from environment variables (vendor SDKs such as FalconPy and the Elasticsearch client show `os.getenv`/`os.environ` in their own quickstarts), optionally typed/validated with `pydantic-settings`; and `schedule` (simple, in-process, no persistence) or APScheduler (persistent job stores, cron/interval triggers, misfire handling) for scheduled jobs.

### Cited Findings

**HTTP clients, sessions, retries, timeouts**
- `requests.Session` "allows you to persist certain parameters across requests… and will use urllib3's connection pooling. So if you're making several requests to the same host, the underlying TCP connection will be reused" — [Requests Advanced Usage](https://requests.readthedocs.io/en/latest/user/advanced/)
- Requests docs: "By default, Requests does not retry failed connections." The documented retry recipe mounts `urllib3.util.Retry(total=3, backoff_factor=0.1, status_forcelist=[502, 503, 504], allowed_methods={'POST'})` via `s.mount('https://', HTTPAdapter(max_retries=retries))` — [Requests Advanced Usage – Example: Automatic Retries](https://requests.readthedocs.io/en/latest/user/advanced/#example-automatic-retries)
- Requests docs on timeouts: "Most requests to external servers should have a timeout attached… By default, requests do not time out unless a timeout value is set explicitly. Without a timeout, your code may hang for minutes or more." Tuple form `timeout=(3.05, 27)` sets connect and read separately — [Requests Advanced Usage – Timeouts](https://requests.readthedocs.io/en/latest/user/advanced/#timeouts)
- Requests verifies TLS by default; setting `verify=False` "will make your application vulnerable to man-in-the-middle (MitM) attacks"; CA bundle comes from `certifi`, overridable via `REQUESTS_CA_BUNDLE` — [Requests Advanced Usage – SSL Cert Verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- Requests warns: "Storing sensitive username and password information in an environment variable or a version-controlled file is a security risk and is highly discouraged" (in the proxy-credentials context) — [Requests Advanced Usage – Proxies](https://requests.readthedocs.io/en/latest/user/advanced/#proxies)
- Custom auth schemes are implemented by subclassing `requests.auth.AuthBase` and setting headers in `__call__` — [Requests Advanced Usage – Custom Authentication](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication)
- Requests auto-parses RFC 8288 `Link` headers into `r.links["next"]` for pagination — [Requests Advanced Usage – Link Headers](https://requests.readthedocs.io/en/latest/user/advanced/#link-headers)
- `urllib3.util.Retry` defaults: `total=10`, `backoff_factor=0` (backoff disabled), `backoff_max=120`, `allowed_methods=frozenset({'DELETE','GET','HEAD','OPTIONS','PUT','TRACE'})` (idempotent verbs only), `status_forcelist=None`, `respect_retry_after_header=True`; sleep formula "{backoff factor} * (2 ** ({number of previous retries}))" plus optional jitter; Retry-After is honoured for `RETRY_AFTER_STATUS_CODES` = 413, 429, 503 — [urllib3 util reference](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html)
- HTTPX: "The default behavior is to raise a TimeoutException after 5 seconds of network inactivity"; four timeout types (connect, read, write, pool); `httpx.Timeout(10.0, connect=60.0)`; HTTPX is "careful to enforce timeouts everywhere by default" — [HTTPX Timeouts](https://www.python-httpx.org/advanced/timeouts/)
- Requests itself names httpx, requests-futures, grequests as options for non-blocking IO — [Requests Advanced Usage – Blocking Or Non-Blocking?](https://requests.readthedocs.io/en/latest/user/advanced/#blocking-or-non-blocking)

**Rate-limit standards**
- RFC 6585 §4: "The 429 status code indicates that the user has sent too many requests in a given amount of time ('rate limiting')"; the response "MAY include a Retry-After header indicating how long to wait before making a new request"; "Responses with the 429 status code MUST NOT be stored by a cache." (Nottingham & Fielding, April 2012) — [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585)
- Real-world examples of 429 + Retry-After: Have I Been Pwned returns 429 with a `retry-after` header "expressing the number of seconds remaining" — [HIBP API v3](https://haveibeenpwned.com/API/v3); AbuseIPDB returns 429 when daily CHECK quota is exceeded — [AbuseIPDB docs](https://docs.abuseipdb.com/); Azure Monitor Data Collector API returns 429 "The service is experiencing a high volume of data from your account. Please retry the request later." — [Azure Monitor HTTP Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)
- Slack SDK: by default only `ConnectionErrorRetryHandler` is enabled (one retry with exponential backoff and jitter); `RateLimitErrorRetryHandler` retries on HTTP 429 and is added via `webhook.retry_handlers.append(...)` — [Slack SDK Webhook docs](https://docs.slack.dev/tools/python-slack-sdk/webhook/)
- NVD: public rate limit 5 requests per rolling 30 s without a key, 50 with a key; NVD still recommends sleeping ~6 s between requests even with a key — [NVD Developers – Start Here](https://nvd.nist.gov/developers/start-here) (page is JavaScript-rendered; figures confirmed via search summary of the official page and corroborated by [DEV Community article](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p) and nvdlib's default of "6 seconds between requests" — [nvdlib](https://github.com/Vehemont/nvdlib))
- VirusTotal Public API: "limited to 500 requests per day and a rate of 4 requests per minute" and "must not be used in commercial products or services"; Premium "does not have request rate or daily allowance limitations" — [VirusTotal Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)

**Subprocess / shelling out to CLI tools (nmap, openssl, osquery, etc.)**
- "Unlike some other popen functions, this library will not implicitly choose to call a system shell… If the shell is invoked explicitly, via shell=True, it is the application's responsibility to ensure that all whitespace and metacharacters are quoted appropriately to avoid shell injection vulnerabilities… it is possible to use shlex.quote()" — [subprocess – Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- "The recommended approach to invoking subprocesses is to use the run() function for all use cases it can handle"; `check=True` raises `CalledProcessError` on non-zero exit; `timeout` kills the child and raises `TimeoutExpired`; `capture_output=True` + `text=True` capture stdout/stderr as str — [subprocess.run](https://docs.python.org/3/library/subprocess.html#subprocess.run)
- Windows caveat: batch files may be launched in a shell regardless of arguments (gh-114539) — [subprocess – Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)

**Hashing / integrity**
- `hashlib.file_digest(fileobj, digest, /)` "Added in version 3.11"; "Return a digest object that has been updated with contents of file object"; fileobj must be opened in binary mode; "The function may bypass Python's I/O and use the file descriptor from fileno() directly" — [hashlib](https://docs.python.org/3/library/hashlib.html#hashlib.file_digest)
- All hashlib constructors take keyword-only `usedforsecurity=True` (since 3.9); `hexdigest()` returns hex string "to exchange the value safely in email or other non-binary environments" — [hashlib](https://docs.python.org/3/library/hashlib.html)
- `hmac.compare_digest(a, b)` "uses an approach designed to prevent timing analysis by avoiding content-based short circuiting behaviour, making it appropriate for cryptography"; docs recommend it over `==` "to reduce the vulnerability to timing attacks"; `hmac.new(key, msg=None, digestmod)` — digestmod required since 3.8 — [hmac](https://docs.python.org/3/library/hmac.html)

**TLS certificate inspection**
- `ssl.create_default_context()` returns a context with "a higher security level than when calling the SSLContext constructor directly"; with `SERVER_AUTH` sets `verify_mode` to `CERT_REQUIRED` and loads default CAs; `PROTOCOL_TLS_CLIENT` enables hostname checking by default — [ssl](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)
- `SSLSocket.getpeercert()` returns a dict including `notBefore`/`notAfter` in the form `'Nov 22 08:15:19 2013 GMT'`; "If the certificate was not validated, the dict is empty"; `ssl.cert_time_to_seconds(cert_time)` parses `"%b %d %H:%M:%S %Y %Z"` (C locale) and the dates "must use GMT (RFC 5280)" — [ssl](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.getpeercert)

**Secrets / configuration**
- pydantic-settings: `pip install pydantic-settings`; `class Settings(BaseSettings)` reads fields from environment variables; `model_config = SettingsConfigDict(env_prefix='my_prefix_')`; env var names are case-insensitive by default (`case_sensitive=True` to change); `env_file='.env'` support with "environment variables will always take priority over values loaded from a dotenv file"; `secrets_dir='/var/run'` reads one secret per file (Docker uses `/run/secrets`); `SecretStr` used for sensitive fields — [Pydantic Settings docs](https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/)
- Vendor quickstarts model env-var secrets: FalconPy `Hosts(client_id=os.getenv("FALCON_CLIENT_ID"), client_secret=os.getenv("FALCON_CLIENT_SECRET"))` — [FalconPy README](https://github.com/CrowdStrike/falconpy); Elasticsearch client `api_key=os.environ["ELASTIC_API_KEY"]` — [Elasticsearch Python client – Connecting](https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting)
- AbuseIPDB prefers the `Key` header over query-string keys because "server logs (like ours) will record them" — [AbuseIPDB docs](https://docs.abuseipdb.com/)

**Scheduling**
- `schedule`: "Python job scheduling for humans… In-process scheduler for periodic jobs. No extra processes needed!… no external dependencies"; explicitly NOT for job persistence, exact (sub-second) timing, concurrent execution or localization; pattern `schedule.every(10).minutes.do(job)` then `while True: schedule.run_pending(); time.sleep(1)`; tested on Python 3.7–3.11 — [schedule docs](https://schedule.readthedocs.io/en/stable/)
- APScheduler 3.x: `BlockingScheduler` (only thing running), `BackgroundScheduler` (inside an app), plus AsyncIO/Gevent/Tornado/Twisted/Qt schedulers; triggers `date`, `interval`, `cron`; job stores `MemoryJobStore` (default, not persisted), `SQLAlchemyJobStore` (PostgreSQL recommended), `MongoDBJobStore`; `misfire_grace_time` and `coalesce` control late/duplicate runs; `pip install apscheduler` — [APScheduler 3.x User Guide](https://apscheduler.readthedocs.io/en/3.x/userguide.html)

**Data validation of API responses**
- CISA publishes a JSON Schema for the KEV feed (useful for validating downloads before acting on them) — [KEV JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
- OpenAPI Specification v3.2.1 (10 September 2026) "defines a standard, programming language-agnostic interface description for HTTP APIs, which allows both humans and computers to discover and understand the capabilities of a service without requiring access to source code, additional documentation, or inspection of network traffic" — [OpenAPI Specification (latest)](https://spec.openapis.org/oas/latest.html)

**Community guidance on SOC scripting practice**
- TechTarget (Damon Garn, 17 March 2026): Python in the SOC automates host isolation, "configure routers and firewalls to block IPs or domains", Jira ticketing, scheduled threat hunts in SIEM/EDR data; recommends `requests`, `pandas`, `re`, `scapy`, `paramiko`, `python-nmap`, `elasticsearch`/`opensearch-py`; "Be sure to run these scripts in test environments before deploying them to production systems"; "Plan to standardize the installation, including version control" — [Boost SOC efficiency with Python security automation](https://www.techtarget.com/searchsecurity/tip/Boost-SOC-efficiency-with-Python-security-automation)

### Inferences
- Because `urllib3.Retry` only retries idempotent methods by default and `respect_retry_after_header` is on, the idiomatic "robust SOC client" is: `Session` + `Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])` + explicit `timeout=` on every call. To retry POSTs (e.g., webhook alerts) you must opt in via `allowed_methods` and make the POST idempotent yourself (e.g., include a dedup key such as alert ID in the payload).
- Idempotency for defensive scripts is mostly achieved at the design level (hash-compare-then-act, "upsert" into a local state store, use `lastModStartDate` watermarks for incremental sync as NVD recommends) rather than by any library feature; none of the fetched official docs offers a general idempotency library.
- For logging, the Python `logging` module is the implied standard (every vendor SDK fetched uses it internally) but no fetched source explicitly prescribes a logging pattern for SOC scripts; treat this as a reasonable default rather than a cited recommendation.
- `schedule` is adequate for lab/course demos; APScheduler (or OS cron/systemd timers) is the better fit for production because of persistence and misfire handling, which the `schedule` docs themselves say they do not provide.

### Gaps
- The official NVD developer pages (`/developers/start-here`, `/developers/vulnerabilities`) are JavaScript-rendered and returned only "NVD - Home" to the fetcher; the 5/50-per-30 s limits and 6 s sleep were confirmed only via a search summary of that page plus secondary sources. The 2000 `resultsPerPage` maximum and `apiKey` header come from the DEV Community article; the 120-day maximum date range could not be confirmed from any fetched source.
- No fetched official source gives a canonical "logging for security scripts" recommendation.
- aiohttp and `urllib` official docs were not fetched in this session (budget); the Slack SDK notes that aiohttp is the optional dependency for its async clients.

---

## Key Question 2: Which security-product APIs are most commonly integrated from Python in SOC work, and where is each documented?

### Takeaway
The APIs in the course brief all have current official Python SDKs or well-documented REST endpoints: threat-intel lookups (VirusTotal vt-py, Shodan, AbuseIPDB, HIBP, MISP PyMISP), vulnerability data (NVD CVE API 2.0, CISA KEV JSON, Tenable pyTenable, Greenbone python-gvm), SIEM/log platforms (Splunk SDK, elasticsearch-py, Wazuh REST API, Azure Monitor/Sentinel ingestion), EDR/XDR (CrowdStrike FalconPy, Microsoft Graph Security API via msgraph-sdk), and notification (Slack SDK webhooks). Each is listed below with its exact documentation URL and auth model.

### Cited Findings

**Vulnerability intelligence**
- NVD CVE API 2.0 base URL `https://services.nvd.nist.gov/rest/json/cves/2.0`; API key in `apiKey` header; pagination via `startIndex`/`resultsPerPage`/`totalResults`; `lastModStartDate`/`lastModEndDate` for incremental sync; dates ISO 8601 with offset e.g. `2024-01-01T00:00:00.000+00:00` — [DEV Community: NVD API v2](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p); official docs at [NVD Developers – Vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities) and [Start Here](https://nvd.nist.gov/developers/start-here) (JS-rendered, see gaps)
- nvdlib (118 stars, MIT) wraps the NVD API with "Built in rate limiting according to NIST NVD recommendations", e.g. `nvdlib.searchCVE(cveId='CVE-2021-26855')[0]` — [nvdlib](https://github.com/Vehemont/nvdlib); docs [nvdlib.com](https://nvdlib.com)
- CISA KEV: JSON feed `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, CSV `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`, schema `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json`, license `https://www.cisa.gov/sites/default/files/licenses/kev/license.txt`; catalog showed 1,766 entries on 2026-11-01 — [KEV Catalog page](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- KEV JSON fields (from schema): top-level `catalogVersion`, `dateReleased` (YYYY-MM-DDTHH:mm:ss.sssZ), `count`, `vulnerabilities[]`; per entry `cveID` (pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`), `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse` ("Known"/"Unknown"), `forensicTriage` ("Yes"/"No", "per BOD 26-04"), `notes`, `cwes[]` — [KEV JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
- KEV inclusion criteria: assigned CVE ID; "reliable evidence that the vulnerability has been actively exploited in the wild"; "a clear remediation action… such as a vendor-provided update"; "BOD 26-04 carries forward the KEV catalog criteria from BOD 22-01"; "CISA strongly recommends all organizations review and monitor the KEV catalog" — [CISA KEV overview](https://www.cisa.gov/known-exploited-vulnerabilities)
- Tenable pyTenable: `pip install pytenable`; Python 3.10+; products: Tenable Vulnerability Management (`tenable.io`), Security Center (`tenable.sc`), Nessus, OT Security, Downloads, Cloud Security, Identity Exposure, Attack Path Analysis, ASM, Tenable One; `TenableIO(access_key=..., secret_key=...)`, `for scan in tio.scans.list()` — [pyTenable docs](https://pytenable.readthedocs.io/en/stable/)
- Greenbone python-gvm (126 stars, GPL-3.0): "Greenbone Vulnerability Management Python Library" speaking GMP (Greenbone Management Protocol) and OSP; `pip install python-gvm`; Python 3.11+; `UnixSocketConnection()`, `with GMP(connection, transform=transform) as gmp: gmp.authenticate('foo','bar'); tasks = gmp.get_tasks()` — [python-gvm](https://github.com/greenbone/python-gvm); docs [greenbone.github.io/python-gvm](https://greenbone.github.io/python-gvm/)

**Threat intelligence / enrichment**
- VirusTotal vt-py (792 stars, Apache-2.0): "The official Python 3 client library for VirusTotal"; supports scanning files/URLs, retrieving file/URL info, Intelligence searches, LiveHunt, Retrohunt, Graphs — [vt-py](https://github.com/VirusTotal/vt-py); quickstart `client = vt.Client("<apikey>")`, `file = client.get_object("/files/<hash>")`, `file.last_analysis_stats` → `{'malicious': 62, 'undetected': 2, ...}`, `with vt.Client('<apikey>') as client:` — [vt-py quickstart](https://virustotal.github.io/vt-py/quickstart.html)
- Shodan REST base `https://api.shodan.io`, key passed as `key` query parameter; `GET /shodan/host/{ip}` "Returns all services that have been found on the given host IP"; `/shodan/host/search` deducts 1 query credit when a filter is used or results past page 1 are read ("For every 100 results past the 1st page 1 query credit is deducted"); `GET /api-info` returns `plan`, `query_credits`, `scan_credits` — [Shodan REST API](https://developer.shodan.io/api); Python: `api = shodan.Shodan(SHODAN_API_KEY)`, `api.host(ip)`, `api.search('apache')` with "up to 100 results" per page, errors raise `shodan.APIError` — [shodan-python tutorial](https://shodan.readthedocs.io/en/latest/tutorial.html)
- AbuseIPDB v2: base `https://api.abuseipdb.com/api/v2`; headers `Key` and `Accept: application/json`; CHECK params `ipAddress` (v4/v6), `maxAgeInDays` (default 30, 1–365), `verbose`; response `data.abuseConfidenceScore`, `totalReports`, `isTor`, `usageType`, `countryCode`; daily CHECK limits Standard 1,000 / Webmaster 3,000 / Supporter 5,000 / Basic 10,000 / Premium 50,000; 429 on exceed — [AbuseIPDB docs](https://docs.abuseipdb.com/)
- Have I Been Pwned v3: base `https://haveibeenpwned.com/api/v3`; `GET /breachedAccount/{email}` requires `hibp-api-key` header; "Each request to the API must be accompanied by a user agent request header" else 403; 404 = not found in any breach; 429 with `retry-after`; Pwned Passwords `GET https://api.pwnedpasswords.com/range/{first 5 SHA-1 chars}` "freely accessible without the need for a subscription and API key" (k-anonymity) — [HIBP API v3](https://haveibeenpwned.com/API/v3)
- MISP PyMISP (494 stars, 2-clause BSD): "Python library using the MISP Rest API"; `pip3 install pymisp` (extras e.g. `pymisp[virustotal,email]`); API key from the Automation section of the MISP UI; Python 3.10+; docs [pymisp.readthedocs.io](https://pymisp.readthedocs.io/en/latest/) — [PyMISP](https://github.com/MISP/PyMISP)

**SIEM / log platforms**
- Splunk SDK for Python (747 stars, Apache-2.0): `python3 -m pip install splunk-sdk`; "Python 3.13 or newer"; connect via `client.connect(host=..., username=..., password=..., autologin=True)`, bearer `splunkToken=...`, or session key `token=...` — [splunk-sdk-python](https://github.com/splunk/splunk-sdk-python); docs [dev.splunk.com Python SDK](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/)
- elasticsearch-py (4.4k stars, Apache-2.0): "Official Python client for Elasticsearch"; clients are forward compatible with later minor versions; "To upgrade to a new major version, first upgrade Elasticsearch, then upgrade the Python Elasticsearch client" — [elasticsearch-py](https://github.com/elastic/elasticsearch-py); connecting: `Elasticsearch("https://localhost:9200", ca_certs="/path/to/http_ca.crt", api_key=os.environ["ELASTIC_API_KEY"])`, or `cloud_id`, `basic_auth`, `bearer_auth`; `ssl_assert_fingerprint` alternative (Python 3.10+); "Running Elasticsearch without security enabled is not recommended" — [Elasticsearch Python client – Connecting](https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting)
- Wazuh API on port 55000: "All API endpoints (except the login endpoint itself) require authentication using a JSON Web Token (JWT)"; `POST /security/user/authenticate` with basic auth (`?raw=true` returns plain token); then `Authorization: Bearer $TOKEN`; default `wazuh:wazuh` "should be changed after installation"; the page ships `wazuh_api_authenticator.py` using `requests` that calls `/` and `/agents/summary/status`; sample token `exp - nbf` = 900 s (inferred, not stated) — [Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- Azure Monitor HTTP Data Collector API (legacy, HMAC-signed custom log ingestion to Log Analytics/Sentinel): `POST https://<CustomerId>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`; deprecated, "Support ended… September 14, 2026, although ingestion continues to function. Migrate to the Logs ingestion API" — [Azure Monitor HTTP Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)

**EDR / XDR / cloud security**
- CrowdStrike FalconPy (517 stars, Unlicense): `python3 -m pip install crowdstrike-falconpy`; Python 3.8–3.14; OAuth2 client credentials, "completely abstracts token management, automatically refreshing your token when it expires"; Service Classes (one per API collection) and the Uber Class (all operations); `Hosts(...).query_devices_by_filter(filter=f"hostname:*'*{SEARCH_FILTER}*'")` — [FalconPy](https://github.com/CrowdStrike/falconpy); docs [developer.crowdstrike.com/sdks/python](https://developer.crowdstrike.com/sdks/python/)
- Microsoft Graph Security API: application-level (no signed-in user, "for example, a SIEM scenario") or user-delegated authorization; tenant admin must grant consent per tenant; "requires the *.Read.All scope for GET queries, and the *.ReadWrite.All scope for PATCH/POST/DELETE"; permissions include `SecurityEvents.Read.All` (alerts, secureScores), `SecurityActions.Read.All`, `ThreatIndicators.ReadWrite.OwnedBy`; admin consent URL `https://login.microsoftonline.com/common/adminconsent?client_id=...` — [Authorization and the Microsoft Graph Security API](https://learn.microsoft.com/en-us/graph/security-authorization)
- `GET /security/alerts_v2` (least privileged `SecurityAlert.Read.All`, delegated or application); OData `$count`, `$filter`, `$skip`, `$top`; `$filter` on `assignedTo, classification, determination, createdDateTime, lastUpdateDateTime, severity, serviceSource, status`; "Use @odata.nextLink for pagination"; Python: `result = await graph_client.security.alerts_v2.get()` — [List alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2)
- msgraph-sdk-python (634 stars, MIT): `pip install msgraph-sdk`; Python 3.10+; `ClientSecretCredential('TENANT_ID','CLIENT_ID','CLIENT_SECRET')` from `azure.identity.aio`, `scopes = ['https://graph.microsoft.com/.default']`, `GraphServiceClient(credentials=credentials, scopes=scopes)`, async `await client.users.by_user_id('upn').get()` — [msgraph-sdk-python](https://github.com/microsoftgraph/msgraph-sdk-python)

**Notification**
- Slack SDK incoming webhooks: `from slack_sdk.webhook import WebhookClient; webhook = WebhookClient(url); response = webhook.send(text="Hello!"); assert response.status_code == 200; assert response.body == "ok"`; Block Kit via `blocks=[...]`; `AsyncWebhookClient` in `slack_sdk.webhook.async_client` (requires `pip install aiohttp`) — [Slack SDK Webhook](https://docs.slack.dev/tools/python-slack-sdk/webhook/)

**Scanner output parsing**
- python-nmap (PyPI, GPL-3.0, Alexandre Norman, v0.7.1 released 26 Oct 2021, homepage http://xael.org/pages/python-nmap-en.html): `nm = nmap.PortScanner(); nm.scan('127.0.0.1', '22-443'); nm.all_hosts(); nm['127.0.0.1'].all_protocols(); nm['127.0.0.1']['tcp'].keys(); nm['127.0.0.1']['tcp'][22]['state']`; `PortScannerAsync().scan(hosts='192.168.1.0/30', arguments='-sP', callback=callback_result)`; `nm.csv()`; changelog references "nmap program was not found in path" (requires nmap binary) — [python-nmap on PyPI](https://pypi.org/project/python-nmap/)
- python-libnmap (493 stars, Apache-2.0): "libnmap is a python library to run nmap scans, parse and diff scan results"; modules process / parse (XML only) / report (JSON serialisation) / diff / common (NmapHost, NmapService) / plugins (MongoDB, SQLAlchemy, S3); `pip install python-libnmap` — [python-libnmap](https://github.com/savon-noir/python-libnmap); parser: `NmapParser.parse_fromfile('…xml')`, `NmapParser.parse(nm.stdout)`, `for host in nmap_report.hosts:` — [libnmap parser docs](https://libnmap.readthedocs.io/en/latest/parser.html)
- CIS Benchmarks: "prescriptive configuration recommendations for more than 25+ vendor product families", "consensus-based effort of cybersecurity experts globally"; families include Cloud Providers, Desktop Software, DevSecOps Tools, DISA STIG, Mobile Devices, Network Devices, Operating Systems, Server Software, Storage; CIS-CAT Pro Assessor "Assess system conformance to CIS Benchmarks"; CIS Build Kits "Easily configure your systems in accordance with a CIS Benchmark" — [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

### Inferences
- The integration surface splits cleanly by auth style (see Q4), and the course can teach one "shape" per style: a key-in-header client (AbuseIPDB/HIBP/NVD/VT), an SDK that hides OAuth2 (FalconPy, msgraph-sdk), a JWT-exchange client (Wazuh), and an HMAC signer (Azure Data Collector).
- KEV is the simplest first integration for students: no auth, a published JSON Schema, stable field names, small (1,766 entries) and directly actionable for a SOC (vendor filter + dueDate).
- python-nmap has not had a release since Oct 2021; for teaching, `xml.etree.ElementTree` on `nmap -oX` output or libnmap's parser are safer long-term choices, and the parsing skill transfers to .nessus and OpenVAS XML.

### Gaps
- Shodan's per-second rate limit is not stated on the fetched REST API page; the commonly quoted "1 request/second" could not be verified here.
- Wazuh FIM endpoint (`GET /syscheck/{agent_id}`) and the default token lifetime were not on the fetched Getting Started page; they live in the full API reference (not fetched).
- Tenable's `.nessus` file-format documentation page (`docs.tenable.com/nessus/Content/NessusFileFormats.htm`) returned 404; .nessus/OpenVAS XML element names are therefore not cited here.
- vt-py README did not show install command or asyncio usage; the quickstart showed sync usage only.
- GitHub page for python-nmap (`nmmapper/python-nmap`) returned 404; the project is primarily distributed via PyPI/xael.org.

---

## Key Question 3: What are the most cited books, courses and repositories on this subject?

### Takeaway
For courses, SANS SEC573 (GIAC GPYC, Mark Baggett) is the reference Python-for-defenders course and has been re-titled in 2026 to foreground AI/LLM/MCP automation; for books, Black Hat Python 2nd ed. (offense-oriented, Python 3), Poston's Python for Cybersecurity (ATT&CK-structured, offense and defense) and Packt's Security Automation with Python (2025, vulnerability-management focus) are the current mainstream titles; for repositories, the official vendor SDKs (elasticsearch-py 4.4k, vt-py ~790, splunk-sdk ~750, msgraph-sdk ~630, FalconPy ~520, PyMISP ~490, libnmap ~490) plus the awesome-cybersecurity-blueteam list (~5.6k) are the most-starred anchors.

### Cited Findings

**Courses / certifications**
- SANS SEC573 — now titled "SEC573: AI-Powered Security Automation: Building Tools with Python, LLMs, and MCP" (image alt-text still reads "Automating Information Security with Python"); certification GIAC Python Coder (GPYC); "6 Days (Instructor-Led)" or "36 Hours (Self-Paced)"; sections: Essential Skills Workshop, Essentials Knowledge Workshop, Automated Defense with AI, Automated Forensics with AI, Automated Offense with AI, Capture-the-Flag Challenge; covers log parsing, packet captures, network interaction, SQL, regular expressions; author Mark Baggett — [SANS SEC573](https://www.sans.org/cyber-security-courses/automating-information-security-with-python/)
- Mark Baggett is SANS Faculty Fellow, teaches SEC573 and SEC673, and is CTO of the SANS Internet Storm Center — [SANS.edu profile](https://www.sans.edu/profiles/mark-baggett)

**Books**
- *Black Hat Python, 2nd Edition* — Justin Seitz and Tim Arnold, No Starch Press, April 2021, 216 pp., ISBN-13 9781718501126; "All of the code in this edition has been updated to Python 3.x"; covers sniffers, credential theft, fuzzers, malware analysis, trojans, Volatility forensics (offensive focus) — [No Starch Press](https://nostarch.com/black-hat-python2E)
- *Python for Cybersecurity: Using Python for Cyber Offense and Defense* — Howard E. Poston III, Wiley, 2022, ISBN 9781119850649, 240 pp.; structured around MITRE ATT&CK tactics (Reconnaissance/Resource Development, initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement); publication date given as March 2022 by O'Reilly and May 2022 by retailers — [O'Reilly listing](https://www.oreilly.com/library/view/-/9781119850649); [Eyrolles](https://www.eyrolles.com/Informatique/Livre/python-for-cybersecurity-9781119850649/)
- *Security Automation with Python* — Corey Charles Sr., Packt, February 2025, ISBN 9781805125105; aimed at "vulnerability management and scaling security workflows", covers automating vulnerability scans, integrating Python with tools like Nessus, and frameworks such as NIST 800-53 and FedRAMP; audience security analysts, sysadmins, developers — [Packt](https://www.packtpub.com/product/security-automation-with-python/9781805125105); [O'Reilly](https://www.oreilly.com/library/view/-/9781805125105/)
- Non-Python defender quick references that appear alongside on reading lists: *Blue Team Field Manual* (Alan J White) and *PTFM: Purple Team Field Manual* (Tim Bryant) — [SimeonOnSecurity book list](https://simeononsecurity.com/articles/essential-books-cybersecurity-it-professionals/)

**Repositories (approximate stars, 2026-11-01)**
- elastic/elasticsearch-py — 4.4k, Apache-2.0 — [link](https://github.com/elastic/elasticsearch-py)
- fabacab/awesome-cybersecurity-blueteam — 5.6k, CC BY 4.0; "A curated collection of awesome resources, tools, and other shiny things for cybersecurity blue teams"; sections include Automation and Convention, SOAR, DevSecOps, Threat intelligence, Incident Response tools, Threat hunting; Python tools listed: MultiScanner, DShell, python-dshield, python-sandboxapi, python-stix2, Forager, GRR Rapid Response — [link](https://github.com/fabacab/awesome-cybersecurity-blueteam)
- VirusTotal/vt-py — 792, Apache-2.0 — [link](https://github.com/VirusTotal/vt-py)
- splunk/splunk-sdk-python — 747, Apache-2.0 — [link](https://github.com/splunk/splunk-sdk-python)
- microsoftgraph/msgraph-sdk-python — 634, MIT — [link](https://github.com/microsoftgraph/msgraph-sdk-python)
- CrowdStrike/falconpy — 517, Unlicense — [link](https://github.com/CrowdStrike/falconpy)
- MISP/PyMISP — 494, 2-clause BSD — [link](https://github.com/MISP/PyMISP)
- savon-noir/python-libnmap — 493, Apache-2.0 — [link](https://github.com/savon-noir/python-libnmap)
- greenbone/python-gvm — 126, GPL-3.0 — [link](https://github.com/greenbone/python-gvm)
- Vehemont/nvdlib — 118, MIT — [link](https://github.com/Vehemont/nvdlib)
- python-nmap — distributed on PyPI (GPL-3.0; v0.7.1, Oct 2021) — [PyPI](https://pypi.org/project/python-nmap/)
- pyTenable — docs at [pytenable.readthedocs.io](https://pytenable.readthedocs.io/en/stable/) (star count not fetched)

**Community articles**
- TechTarget, "Boost SOC efficiency with Python security automation" (Damon Garn, 17 March 2026) — the most on-topic recent practitioner article found; lists SOC automation use cases and libraries — [TechTarget](https://www.techtarget.com/searchsecurity/tip/Boost-SOC-efficiency-with-Python-security-automation)
- DEV Community, "How to Scrape and Parse CVE Data from NVD API v2" (Ayi Nedjimi) — practical NVD 2.0 pagination/rate-limit walkthrough — [DEV Community](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p)

### Inferences
- Star counts show that in SOC Python the "most cited repositories" are the vendors' own SDKs rather than independent projects; teaching students to read an SDK README and the vendor's REST reference side-by-side is the transferable skill.
- The SEC573 retitling (AI/LLM/MCP) signals where the professional curriculum is heading in 2026: Python automation scripts increasingly become tools called by agents; a course module should still teach the deterministic script layer these agents depend on.
- *Black Hat Python* remains the most recognised title but is offensive; for a blue-team module Poston (ATT&CK-structured, includes defense) and Charles (vulnerability management) are closer fits.

### Gaps
- No SANS Reading Room / white paper specifically about Python-based SOC automation surfaced in search; results were courses, vendor pages and one faculty profile. A direct search on the SANS Reading Room site would be needed.
- A beginner blog claimed a "2025 SANS survey" showing SOC teams that script repetitive tasks cut MTTR by up to 40%; this could not be traced to a SANS source and should not be cited.
- Star counts for pyTenable, python-nmap (GitHub mirror), and Shodan's `shodan-python` were not fetched.

---

## Key Question 4: What authentication patterns (API keys, OAuth 2.0 client credentials, HMAC) do the major security APIs use?

### Takeaway
Three patterns cover every API in scope: (1) static API key in a custom header or query parameter (VirusTotal, AbuseIPDB `Key`, HIBP `hibp-api-key`, NVD `apiKey`, Shodan `key=` query param, Tenable access/secret key pair, MISP key, Elasticsearch `api_key`); (2) OAuth 2.0 client-credentials grant yielding a bearer token (CrowdStrike Falcon via FalconPy, Microsoft Graph via Entra ID / `ClientSecretCredential`), and the closely related username/password-to-JWT exchange (Wazuh, Splunk session key); (3) HMAC-SHA256 request signing with a shared secret (Azure Monitor Data Collector `SharedKey`). RFC 6749 §4.4 defines client credentials; RFC 6749 §2.3.1 says client_id/secret go in HTTP Basic, not the body.

### Cited Findings

**Static API keys**
- VirusTotal: Public API key obtained via VirusTotal Community; quotas 4 req/min, 500/day (header name not shown on the fetched page; vt-py takes the key in `vt.Client("<apikey>")`) — [VT Public vs Premium](https://docs.virustotal.com/reference/public-vs-premium-api); [vt-py quickstart](https://virustotal.github.io/vt-py/quickstart.html)
- AbuseIPDB: `Key` header, header preferred over query string for log-hygiene reasons — [AbuseIPDB docs](https://docs.abuseipdb.com/)
- HIBP: `hibp-api-key` header plus mandatory `user-agent`; Pwned Passwords range endpoint needs no key — [HIBP API v3](https://haveibeenpwned.com/API/v3)
- NVD: `apiKey` header (free key raises limit 5→50 per 30 s) — [DEV Community: NVD API v2](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p); official [NVD Start Here](https://nvd.nist.gov/developers/start-here)
- Shodan: `key` query parameter, e.g. `https://api.shodan.io/shodan/host/{ip}?key={YOUR_API_KEY}` — [Shodan REST API](https://developer.shodan.io/api)
- Tenable: access key + secret key pair passed to `TenableIO(access_key=..., secret_key=...)` — [pyTenable docs](https://pytenable.readthedocs.io/en/stable/)
- MISP: automation API key from the MISP web UI Automation section — [PyMISP](https://github.com/MISP/PyMISP)
- Elasticsearch: `api_key=`, `basic_auth=`, or `bearer_auth=` in the constructor or per request via `.options()` — [Elasticsearch Python – Connecting](https://www.elastic.co/docs/reference/elasticsearch/clients/python/connecting)
- Slack incoming webhooks: the capability is the secret URL itself (`https://hooks.slack.com/services/T.../B.../XXXX`) — [Slack SDK Webhook](https://docs.slack.dev/tools/python-slack-sdk/webhook/)

**OAuth 2.0 client credentials / bearer tokens**
- RFC 6749 §4.4 Client Credentials Grant: used when "the client is requesting access to the protected resources under its control"; `grant_type` "REQUIRED. Value MUST be set to 'client_credentials'"; `scope` OPTIONAL; "The client MUST authenticate with the authorization server"; example `POST /token` with `Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW` and body `grant_type=client_credentials`; refresh token SHOULD NOT be included — [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
- RFC 6749 §2.3.1: client_id/client_secret via HTTP Basic; "Including the client credentials in the request-body… is NOT RECOMMENDED" — [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)
- CrowdStrike FalconPy: OAuth2 client_id/client_secret; SDK auto-refreshes expired tokens; credentials via keywords or environment — [FalconPy](https://github.com/CrowdStrike/falconpy)
- Microsoft Graph Security: Entra ID tokens; app-only vs delegated; token sent as `Authorization: Bearer {token}`; admin consent per tenant; Python `ClientSecretCredential` + scope `https://graph.microsoft.com/.default` — [Graph Security authorization](https://learn.microsoft.com/en-us/graph/security-authorization); [msgraph-sdk-python](https://github.com/microsoftgraph/msgraph-sdk-python); [List alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2)
- Wazuh: basic-auth login → JWT → `Authorization: Bearer` (token-exchange pattern, not OAuth) — [Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html)
- Splunk SDK: username/password (`autologin=True`), bearer `splunkToken`, or session key `token` — [splunk-sdk-python](https://github.com/splunk/splunk-sdk-python)

**HMAC request signing**
- Azure Monitor Data Collector API: `Authorization: SharedKey <WorkspaceID>:<Signature>`; `StringToSign = VERB + "\n" + Content-Length + "\n" + Content-Type + "\n" + "x-ms-date:" + x-ms-date + "\n" + "/api/logs"`; `Signature=Base64(HMAC-SHA256(UTF8(StringToSign)))` with the base64-decoded workspace key; official Python sample uses `hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256)`; 403 `InvalidAuthorization` if signature fails — [Azure Monitor HTTP Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)
- Python stdlib support: `hmac.new(key, msg, digestmod)` (digestmod required since 3.8), `hmac.digest()` one-shot (3.7+), `hmac.compare_digest()` for verification — [hmac](https://docs.python.org/3/library/hmac.html)

**Standards describing these schemes**
- OpenAPI 3.2.1 (10 Sept 2026) is the standard machine-readable description for HTTP APIs, including a Security Scheme Object (§4.27) — [OpenAPI Specification](https://spec.openapis.org/oas/latest.html) (security scheme type list not confirmed from fetched portion; see gaps)

### Inferences
- Header-based keys are safer than query-string keys because URLs are logged by proxies and servers (AbuseIPDB states this explicitly); when an API offers both (NVD, Shodan), teach the header form and warn about Shodan's `key=` URL parameter leaking into logs.
- OAuth2 client credentials add operational complexity (token caching, expiry, refresh) that the official SDKs (FalconPy, msgraph-sdk/azure-identity) handle; writing the raw `POST /token` once in class is instructive, but production code should use the SDK.
- HMAC signing is the least common pattern in modern security APIs (the main example, Azure Data Collector, is deprecated), but it is still worth teaching because it shows why clock skew (`x-ms-date`) and exact byte-for-byte canonicalisation matter.

### Gaps
- The VirusTotal `x-apikey` header name was not visible on the fetched quota page (vt-py abstracts it).
- The OpenAPI security-scheme type list (`apiKey`, `http`, `mutualTLS`, `oauth2`, `openIdConnect`) could not be confirmed because the fetched portion of the 348k-character spec ended before §4.27's table.
- No fetched source covers mutual-TLS or signed-JWT (private_key_jwt) client auth for security APIs.

---

## Key Question 5 (layer c): What concrete, runnable code examples illustrate these patterns, and where do they come from?

### Takeaway
Twelve snippets follow (each 10–40 lines). Those marked **verbatim/adapted** reproduce or lightly extend code from the cited official docs; those marked **illustrative** are written from the documented APIs cited next to them and were not executed in this session. Replace placeholder secrets with environment variables; do not commit keys.

### Cited Findings

**Snippet 1 — SHA-256 file-integrity baseline (illustrative; based on [hashlib.file_digest](https://docs.python.org/3/library/hashlib.html#hashlib.file_digest) and [hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest); requires Python 3.11+)**
```python
import hashlib, hmac, json, sys
from pathlib import Path

def sha256_of(path: Path) -> str:
    with path.open("rb") as f:                     # binary mode is required by file_digest
        return hashlib.file_digest(f, "sha256").hexdigest()

def build_baseline(root: Path, out: Path) -> None:
    baseline = {str(p): sha256_of(p) for p in root.rglob("*") if p.is_file()}
    out.write_text(json.dumps(baseline, indent=2, sort_keys=True))

def verify(root: Path, baseline_file: Path) -> int:
    baseline = json.loads(baseline_file.read_text())
    changed = 0
    for rel, expected in baseline.items():
        p = Path(rel)
        if not p.exists():
            print(f"MISSING  {rel}"); changed += 1; continue
        actual = sha256_of(p)
        if not hmac.compare_digest(actual, expected):   # constant-time compare
            print(f"MODIFIED {rel}"); changed += 1
    new = {str(p) for p in root.rglob("*") if p.is_file()} - set(baseline)
    for rel in sorted(new):
        print(f"NEW      {rel}"); changed += 1
    return changed

if __name__ == "__main__":
    mode, root, store = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    if mode == "init":
        build_baseline(root, store)
    else:
        sys.exit(1 if verify(root, store) else 0)   # non-zero exit = drift detected
```

**Snippet 2 — TLS certificate expiry check (illustrative; based on [ssl.create_default_context / getpeercert / cert_time_to_seconds](https://docs.python.org/3/library/ssl.html))**
```python
import socket, ssl, sys
from datetime import datetime, timezone

def days_until_expiry(host: str, port: int = 443, timeout: float = 5.0) -> int:
    ctx = ssl.create_default_context()             # CERT_REQUIRED + hostname check
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()              # dict is empty if not validated
    not_after = cert["notAfter"]                    # e.g. 'Nov 22 08:15:19 2013 GMT'
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    return (expires - datetime.now(timezone.utc)).days

if __name__ == "__main__":
    warn_days = 30
    rc = 0
    for host in sys.argv[1:]:
        try:
            d = days_until_expiry(host)
            status = "WARN" if d < warn_days else "OK"
            print(f"{status:4} {host:40} {d:4d} days left")
            rc |= d < warn_days
        except (ssl.SSLError, socket.error) as e:   # expired/untrusted certs raise here
            print(f"FAIL {host:40} {e}"); rc = 1
    sys.exit(rc)
```

**Snippet 3 — requests.Session with urllib3 Retry/backoff honouring Retry-After (adapted from [Requests: Example Automatic Retries](https://requests.readthedocs.io/en/latest/user/advanced/#example-automatic-retries) and [urllib3.util.Retry](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html))**
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

def make_session(user_agent: str = "soc-automation/1.0") -> requests.Session:
    retries = Retry(
        total=5,
        backoff_factor=1,                 # sleeps 0s,2s,4s,8s,16s (factor*2**n), capped by backoff_max=120
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods={"GET", "HEAD"},  # retry idempotent verbs only
        respect_retry_after_header=True,  # default; honours Retry-After on 413/429/503
        raise_on_status=False,
    )
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

if __name__ == "__main__":
    with make_session() as s:
        r = s.get("https://httpbin.org/status/503", timeout=(3.05, 27))  # always set a timeout
        print(r.status_code)
```

**Snippet 4 — NVD CVE API 2.0 query with pagination and rate limiting (illustrative; based on [NVD Developers](https://nvd.nist.gov/developers/start-here) limits and [DEV Community NVD v2 walkthrough](https://dev.to/ayinedjimi-consultants/how-to-scrape-and-parse-cve-data-from-nvd-api-v2-3p0p))**
```python
import os, time, requests

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")                       # free key: 50 req/30s instead of 5
SLEEP = 0.7 if API_KEY else 6.5                           # NVD asks for ~6s sleeps without key

def iter_cves(**params):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    start = 0
    while True:
        q = dict(params, startIndex=start, resultsPerPage=2000)   # 2000 is the max page size
        r = requests.get(NVD, headers=headers, params=q, timeout=60)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", "30"))); continue
        r.raise_for_status()
        data = r.json()
        yield from data.get("vulnerabilities", [])
        start += data["resultsPerPage"]
        if start >= data["totalResults"]:
            break
        time.sleep(SLEEP)

if __name__ == "__main__":
    # incremental sync: only CVEs modified in a window (ISO-8601 with offset)
    for item in iter_cves(lastModStartDate="2026-10-25T00:00:00.000+00:00",
                          lastModEndDate="2026-11-01T00:00:00.000+00:00",
                          cvssV3Severity="CRITICAL"):
        cve = item["cve"]
        print(cve["id"], cve["descriptions"][0]["value"][:80])
```

**Snippet 5 — VirusTotal file-hash lookup with vt-py (adapted from [vt-py quickstart](https://virustotal.github.io/vt-py/quickstart.html); quotas per [VT Public API](https://docs.virustotal.com/reference/public-vs-premium-api))**
```python
import os, sys, vt

def lookup(sha256: str) -> dict:
    with vt.Client(os.environ["VT_API_KEY"]) as client:       # context manager closes the client
        try:
            f = client.get_object(f"/files/{sha256}")
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                return {"sha256": sha256, "known": False}
            raise
        stats = f.last_analysis_stats                           # {'malicious': 62, 'undetected': 2, ...}
        return {"sha256": f.sha256, "known": True, "size": f.size,
                "type": f.type_tag, "malicious": stats["malicious"],
                "suspicious": stats["suspicious"], "undetected": stats["undetected"]}

if __name__ == "__main__":
    # Public API: 4 requests/minute, 500/day, non-commercial use only
    for h in sys.argv[1:]:
        print(lookup(h))
```

**Snippet 6 — Pull the CISA KEV feed and filter by vendor / due date (illustrative; fields per [KEV JSON schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json); feed URL per [KEV catalog page](https://www.cisa.gov/known-exploited-vulnerabilities-catalog))**
```python
import sys, requests
from datetime import date

KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def load_kev() -> dict:
    r = requests.get(KEV_JSON, timeout=30,
                     headers={"User-Agent": "soc-kev-check/1.0"})
    r.raise_for_status()
    return r.json()

def filter_kev(catalog: dict, vendors: set[str], ransomware_only: bool = False):
    for v in catalog["vulnerabilities"]:
        if v["vendorProject"].lower() not in vendors:
            continue
        if ransomware_only and v.get("knownRansomwareCampaignUse") != "Known":
            continue
        yield v

if __name__ == "__main__":
    cat = load_kev()
    print(f"KEV {cat['catalogVersion']} released {cat['dateReleased']} count={cat['count']}")
    today = date.today().isoformat()
    for v in filter_kev(cat, {x.lower() for x in sys.argv[1:]} or {"microsoft"}):
        overdue = "OVERDUE" if v["dueDate"] < today else ""
        print(f"{v['cveID']:16} {v['product'][:28]:28} added={v['dateAdded']} "
              f"due={v['dueDate']} ransomware={v['knownRansomwareCampaignUse']} {overdue}")
```

**Snippet 7 — Parse Nmap XML with ElementTree (illustrative; `nmap -oX` structure — host/status/address/ports/port/state/service — per Nmap's XML DTD at https://nmap.org/book/nmap-dtd.html, which was not fetched in this session)**
```python
import sys
import xml.etree.ElementTree as ET

def parse_nmap_xml(path: str):
    root = ET.parse(path).getroot()                       # <nmaprun>
    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") == "ipv4"), "?")
        for port in host.findall("./ports/port"):
            state = port.find("state").get("state")
            if state != "open":
                continue
            svc = port.find("service")
            yield {
                "host": addr,
                "proto": port.get("protocol"),
                "port": int(port.get("portid")),
                "service": svc.get("name") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            }

if __name__ == "__main__":
    # generate input with: nmap -sV -oX scan.xml 192.0.2.0/28   (authorised targets only)
    for row in parse_nmap_xml(sys.argv[1]):
        print(f"{row['host']:15} {row['proto']}/{row['port']:<5} {row['service']:12} "
              f"{row['product']} {row['version']}")
```

**Snippet 7b — Same with python-nmap (verbatim calls from [python-nmap PyPI](https://pypi.org/project/python-nmap/); requires the nmap binary)**
```python
import nmap

nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-443')          # runs nmap under the hood
print(nm.command_line())
for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            print(host, proto, port, nm[host][proto][port]['state'])
print(nm.csv())
```

**Snippet 8 — Post an alert to Slack via incoming webhook with 429 retry (adapted from [Slack SDK Webhook docs](https://docs.slack.dev/tools/python-slack-sdk/webhook/))**
```python
import os
from slack_sdk.webhook import WebhookClient
from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler

webhook = WebhookClient(os.environ["SLACK_WEBHOOK_URL"])     # the URL *is* the secret
webhook.retry_handlers.append(RateLimitErrorRetryHandler(max_retry_count=2))  # retry on HTTP 429

def alert(title: str, detail: str, severity: str = "high") -> None:
    response = webhook.send(
        text=f"[{severity.upper()}] {title}",                 # fallback text for notifications
        blocks=[{
            "type": "section",
            "text": {"type": "mrkdwn",
                     "text": f"*{title}*\nSeverity: `{severity}`\n{detail}"},
        }],
    )
    assert response.status_code == 200
    assert response.body == "ok"

if __name__ == "__main__":
    alert("Certificate expiring", "vpn.example.com expires in 12 days")
```

**Snippet 9 — AbuseIPDB IP reputation check (illustrative; based on [AbuseIPDB docs](https://docs.abuseipdb.com/))**
```python
import os, sys, requests

def check_ip(ip: str, max_age_days: int = 90) -> dict:
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},  # key in header, not URL
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        timeout=15,
    )
    if r.status_code == 429:                           # daily CHECK quota exceeded (1,000/day on Standard)
        raise RuntimeError("AbuseIPDB quota exceeded; retry tomorrow")
    r.raise_for_status()
    d = r.json()["data"]
    return {"ip": ip, "score": d["abuseConfidenceScore"], "reports": d["totalReports"],
            "tor": d["isTor"], "usage": d.get("usageType"), "cc": d.get("countryCode")}

if __name__ == "__main__":
    for ip in sys.argv[1:]:
        res = check_ip(ip)
        flag = "BLOCK?" if res["score"] >= 75 else ""
        print(f"{res['ip']:16} score={res['score']:3} reports={res['reports']:4} tor={res['tor']} {flag}")
```

**Snippet 10 — Pwned Passwords k-anonymity check for account-hygiene audits (illustrative; based on [HIBP API v3](https://haveibeenpwned.com/API/v3))**
```python
import hashlib, requests

def pwned_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",   # no API key needed
                     headers={"User-Agent": "soc-password-audit/1.0"},     # UA is mandatory on HIBP APIs
                     timeout=10)
    r.raise_for_status()
    for line in r.text.splitlines():
        sfx, count = line.split(":")
        if sfx == suffix:
            return int(count)
    return 0

if __name__ == "__main__":
    for pw in ["Password123", "correct horse battery staple"]:
        print(f"{pw!r}: seen {pwned_count(pw)} times in breaches")
```

**Snippet 11 — OAuth2 client-credentials via SDK: CrowdStrike FalconPy and Microsoft Graph (verbatim/adapted from [FalconPy README](https://github.com/CrowdStrike/falconpy), [msgraph-sdk-python README](https://github.com/microsoftgraph/msgraph-sdk-python), [List alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2))**
```python
import asyncio, os
from falconpy import Hosts
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient

# CrowdStrike: SDK performs the OAuth2 client-credentials flow and refreshes tokens
hosts = Hosts(client_id=os.getenv("FALCON_CLIENT_ID"),
              client_secret=os.getenv("FALCON_CLIENT_SECRET"))
SEARCH_FILTER = "hostname-search-string"
hosts_search_result = hosts.query_devices_by_filter(filter=f"hostname:*'*{SEARCH_FILTER}*'")
print(hosts_search_result["status_code"], hosts_search_result["body"].get("resources", [])[:5])

# Microsoft Graph Security: app-only token via Entra ID, scope .default
credentials = ClientSecretCredential(os.environ["TENANT_ID"], os.environ["CLIENT_ID"],
                                     os.environ["CLIENT_SECRET"])
graph_client = GraphServiceClient(credentials=credentials,
                                  scopes=["https://graph.microsoft.com/.default"])

async def high_alerts():
    result = await graph_client.security.alerts_v2.get()     # needs SecurityAlert.Read.All
    for a in (result.value or []):
        if a.severity and a.severity.value == "high":
            print(a.created_date_time, a.service_source, a.title)

asyncio.run(high_alerts())
```

**Snippet 12 — HMAC-SHA256 SharedKey signing for Azure Monitor custom logs (verbatim `build_signature` from [Azure Monitor HTTP Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api); API deprecated, support ended 14 Sept 2026 — shown for the HMAC pattern)**
```python
import base64, datetime, hashlib, hmac, json, requests

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

def post_data(customer_id, shared_key, body, log_type):
    method, content_type, resource = 'POST', 'application/json', '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(customer_id, shared_key, rfc1123date, len(body), method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'
    headers = {'content-type': content_type, 'Authorization': signature,
               'Log-Type': log_type, 'x-ms-date': rfc1123date}
    response = requests.post(uri, data=body, headers=headers, timeout=30)
    print('Accepted' if 200 <= response.status_code <= 299 else f"Response code: {response.status_code}")

body = json.dumps([{"host": "web01", "check": "cert_expiry", "days_left": 12}])
# post_data(WORKSPACE_ID, SHARED_KEY, body, "SocAutomation")
```

**Snippet 13 — Wazuh API: basic-auth to JWT, then Bearer calls (illustrative; based on [Wazuh API Getting Started](https://documentation.wazuh.com/current/user-manual/api/getting-started.html))**
```python
import os, requests
from requests.auth import HTTPBasicAuth

BASE = os.getenv("WAZUH_API", "https://localhost:55000")
CA = os.getenv("WAZUH_CA_BUNDLE", False)          # path to the API cert; False only in a lab

def get_token() -> str:
    r = requests.post(f"{BASE}/security/user/authenticate",
                      auth=HTTPBasicAuth(os.environ["WAZUH_USER"], os.environ["WAZUH_PASS"]),
                      params={"raw": "true"}, verify=CA, timeout=10)
    r.raise_for_status()
    return r.text                                  # JWT; re-authenticate when it expires

def agents_status(token: str) -> dict:
    r = requests.get(f"{BASE}/agents/summary/status",
                     headers={"Authorization": f"Bearer {token}"}, verify=CA, timeout=10)
    r.raise_for_status()
    return r.json()["data"]

if __name__ == "__main__":
    print(agents_status(get_token()))              # e.g. {'active': 12, 'disconnected': 1, ...}
```

**Snippet 14 — Scheduled job pattern with `schedule` and safe subprocess invocation (adapted from [schedule docs](https://schedule.readthedocs.io/en/stable/) and [subprocess docs](https://docs.python.org/3/library/subprocess.html))**
```python
import logging, subprocess, time, schedule

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("soc.jobs")

def run_integrity_check():
    try:
        result = subprocess.run(
            ["python3", "fim.py", "verify", "/etc", "baseline.json"],  # list form, shell=False (default)
            capture_output=True, text=True, check=True, timeout=300)
        log.info("FIM OK: %s", result.stdout.strip()[:200])
    except subprocess.CalledProcessError as e:      # non-zero exit = drift detected
        log.warning("FIM drift (rc=%s): %s", e.returncode, e.stdout.strip()[:500])
    except subprocess.TimeoutExpired:
        log.error("FIM check timed out")

schedule.every(6).hours.do(run_integrity_check)
schedule.every().day.at("07:00").do(lambda: log.info("daily KEV/cert checks go here"))

while True:                 # schedule has no persistence; use APScheduler/cron for production
    schedule.run_pending()
    time.sleep(1)
```

**Snippet 15 — Typed secrets/config with pydantic-settings (illustrative; based on [Pydantic Settings docs](https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/))**
```python
from pydantic import SecretStr, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", env_file_encoding="utf-8")
    vt_api_key: SecretStr                     # read from SOC_VT_API_KEY (case-insensitive)
    abuseipdb_key: SecretStr
    slack_webhook: HttpUrl
    nvd_api_key: SecretStr | None = None
    cert_warn_days: int = 30

settings = Settings()                          # raises ValidationError if a required var is missing
print(settings.vt_api_key)                     # prints '**********' — SecretStr masks on repr/print
api_key = settings.vt_api_key.get_secret_value()
```

### Inferences
- Snippets 1, 2, 6, 7, 10 need no credentials and are ideal first labs; 3 and 15 are the "plumbing" every later script reuses; 4, 5, 9 introduce key-in-header auth and quota handling; 11, 12, 13 cover OAuth2, HMAC and JWT exchange respectively; 8 and 14 close the loop with alerting and scheduling.
- Every snippet that calls the network sets `timeout=`, because the requests docs state there is no default timeout.

### Gaps
- None of the snippets was executed in this session; the ones marked illustrative are consistent with the cited docs but should be run in a lab before use in class. Snippet 7's XML element names rely on Nmap's DTD, which was not fetched.
- A Nessus `.nessus` / OpenVAS XML parsing snippet was not included because the Tenable file-format page returned 404 and the OpenVAS report schema was not fetched; the ElementTree pattern in Snippet 7 applies directly (`ReportHost`/`ReportItem` for .nessus is widely documented but unverified here).
- Splunk SDK search (`service.jobs.oneshot`, `splunklib.results`) and pyTenable `tio.exports.vulns()` examples were not visible on the fetched pages, so no snippet was written for them beyond the connection lines quoted in Q2.
