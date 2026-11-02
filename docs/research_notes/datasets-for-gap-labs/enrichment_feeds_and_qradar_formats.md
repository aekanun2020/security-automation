# Free enrichment feeds (G3/G2) and QRadar-shaped lab formats (LEEF / AQL / REST) — verified 2026-11-02

Legend used throughout:
- **LIVE** = endpoint was called with `curl` from this machine on 2026-11-02 and the response shown is real.
- **DOC** = statement comes from the vendor's own documentation page fetched on 2026-11-02.
- **SECONDARY** = third-party source (press, competitor blog, aggregator) — treat with care.
- **NOT FETCHED** = page could not be retrieved (403/404/JS-rendered); claim is unverified.

---

## Part A — Key question A1: Which enrichment sources work with NO key at all (pure offline / anonymous HTTP), and what does a record look like?

### Takeaway
Nine sources were confirmed to work anonymously on 2026-11-02: CISA KEV (JSON+CSV), NVD CVE API 2.0 (keyless but throttled), FIRST EPSS (API + daily CSV), HIBP Pwned Passwords range API, MITRE ATT&CK (TAXII 2.1 + STIX GitHub), abuse.ch Feodo Tracker blocklists (still keyless, CC0), Spamhaus DROP, Tor bulk exit list, Shodan InternetDB, GreyNoise Community (anonymous but tiny quota), ip-api.com (HTTP only, non-commercial), ipinfo.io legacy `/{ip}/json` (undocumented, limited), AlienVault OTX indicator lookups (worked without key in a live test), plus benign baselines Tranco / Majestic Million / Cisco Umbrella top-1M and the MISP default-feed OSINT (CIRCL, Botvrij). These are the "no sign-up" lab backbone.

### Cited Findings

**CISA Known Exploited Vulnerabilities (KEV)**
- LIVE: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` returned HTTP 200, 1,826,755 bytes, `application/json`; top-level keys `title`, `catalogVersion` = "2026.10.30", `dateReleased` = "2026-10-30T17:02:45.3665Z", `count` = 1766, plus `vulnerabilities[]` — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- LIVE example record (fields: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, forensicTriage, notes, cwes[]):
  `{"cveID":"CVE-2020-29583","vendorProject":"Zyxel","product":"Multiple Products","vulnerabilityName":"Zyxel Multiple Products Use of Hard-Coded Credentials Vulnerability","dateAdded":"2021-11-03","shortDescription":"...","requiredAction":"Apply updates per vendor instructions.","dueDate":"2022-05-03","knownRansomwareCampaignUse":"Unknown","forensicTriage":"No","notes":"https://nvd.nist.gov/vuln/detail/CVE-2020-29583","cwes":["CWE-522"]}` — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- LIVE: CSV variant `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv` header row: `cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,forensicTriage,notes,cwes`; newest row on 2026-11-02 was CVE-2026-118527 (Ivanti Connect Secure, added 2026-10-30, due 2026-11-13) and its requiredAction text references "BOD 26-04" and "Forensics Triage Requirements" — [CISA KEV CSV](https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv)
- LIVE: JSON Schema (draft-07) exists at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json` (title "CISA Catalog of Known Exploited Vulnerabilities") — [KEV schema](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json)
- DOC: Catalog page lists CSV, JSON, JSON Schema (updated 09-02-2026) and Print view downloads; shows "1766 results"; links a license file at `/sites/default/files/licenses/kev/license.txt`; displayed fields include "Known To Be Used in Ransomware Campaigns?" and "Forensic triage required per BOD 26-04" — [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- DOC: BOD 26-04 (issued June 10, 2026) "carries forward the KEV catalog criteria from BOD 22-01" — [CISA KEV page](https://www.cisa.gov/known-exploited-vulnerabilities)
- Key needed: **no**. Format: JSON / CSV. Update frequency: not stated on page (catalogVersion changes per release; observed release 2026-10-30). Commercial use: license file returned "Access Denied" to curl (NOT FETCHED — see Gaps).
- **G3 fit: excellent** (CVE -> "is it actively exploited?" boolean + due date + ransomware flag). **G2 fit: yes** (binary KEV membership is a standard scoring input alongside EPSS/CVSS).

**NVD CVE API 2.0**
- LIVE: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29583` without any key returned HTTP/2 200 with envelope `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-02T07:19:16.364"}` and `vulnerabilities[0].cve` keys: `id, sourceIdentifier, published, lastModified, vulnStatus, cveTags, descriptions, affected, metrics, cisaExploitAdd, cisaActionDue, cisaRequiredAction, cisaVulnerabilityName, weaknesses, configurations, references` — [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29583)
- LIVE: `metrics.cvssMetricV31[]` entries carry `source`, `type` (Primary/Secondary), `cvssData.{version,vectorString,baseScore,baseSeverity,attackVector,...}`, `exploitabilityScore`, `impactScore`; CVE-2020-29583 shows baseScore 9.8 CRITICAL, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29583)
- LIVE: response header `access-control-allow-headers: accept, apiKey, content-type, origin, x-requested-with` confirms the optional key header name is `apiKey` — [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
- NVD now embeds KEV fields (`cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName`) in the CVE record, so one NVD call yields CVSS + KEV status — [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29583)
- Key needed: **optional** (free). Rate-limit numbers: NOT FETCHED (developer pages are JS-rendered; see Gaps). Format: JSON. Commercial use: NVD terms page NOT FETCHED.
- **G3 fit: excellent** (CVSS vector/severity, description, CWE, references). **G2 fit: yes** (CVSS base score is the canonical severity input).

**FIRST EPSS**
- LIVE: `GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2020-29583` (no key) returned `{"status":"OK","status-code":200,"version":"1.0","access":"public","total":2,"offset":0,"limit":100,"data":[{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-11-01"},{"cve":"CVE-2020-29583","epss":"0.901550000","percentile":"0.997960000","date":"2026-11-01"}]}` — [EPSS API](https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2020-29583)
- LIVE: bulk daily CSV `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` HTTP 200, 2,797,262 bytes gz; first lines: `#model_version:v2026.06.15,score_date:2026-11-01T12:00:16Z` then `cve,epss,percentile` then `CVE-1999-0001,0.04753,0.91883` — [EPSS daily CSV](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz)
- DOC: "A single stable URL always points to the current day's complete file: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz ... gzip-compressed CSV containing three fields ... cve, epss, percentile"; "the 'v1' in the URL is a reference to the API version, not the EPSS version"; full parameter reference at api.first.org/epss — [FIRST EPSS Get the Data](https://www.first.org/epss/data)
- DOC: "Is EPSS free to use? Yes. EPSS scores are published freely via CSV download and API with no registration required. Attribution is requested when EPSS data is used in publications or products."; "How often are scores generated? Daily ... typically within a minute or two after 13:30 UTC daily."; scores generated by Empirical Security — [FIRST EPSS FAQ](https://www.first.org/epss/faq)
- DOC: API params documented: `cve` (comma-separated multiple), `date` (YYYY-MM-DD, since April 14, 2021), `days`, `scope=public|time-series` (time-series returns last 30 days); example uses `pretty=true`; response includes `offset`/`limit` (default limit 100) — [api.first.org/epss](https://api.first.org/epss/)
- DOC: FIRST API-wide rule: "Public endpoints without authentication are limited to 1000 requests per minute ... 429 Too many requests" — [FIRST API v1 docs](https://api.first.org/)
- Key needed: **no**. Format: JSON API / gz CSV. Update: daily ~13:30 UTC. Commercial use: free, attribution requested.
- **G3 fit: excellent. G2 fit: the primary probabilistic scoring input** (epss probability + percentile).

**Have I Been Pwned — Pwned Passwords range API**
- LIVE: `GET https://api.pwnedpasswords.com/range/21BD1` (no key, no UA tricks) HTTP/2 200 `text/plain`, body lines like `0002EEFFB2CCA91812B5CC9956854E22BEB:4`, `000F6468C6E4D09C0C239A4C2769501B3DD:5959`; headers `access-control-allow-origin: *`, `cache-control: public, max-age=2678400`, `vary: Add-Padding` — [Pwned Passwords range](https://api.pwnedpasswords.com/range/21BD1)
- DOC: "GET https://api.pwnedpasswords.com/range/{first 5 SHA-1 chars} ... the API will respond with an HTTP 200 and include the suffix of every hash beginning with the specified prefix, followed by a count"; "There is no rate limit on the Pwned Passwords API."; `?mode=ntlm` returns NTLM suffixes; `Add-Padding: true` pads responses to 800–1,000 records (padded entries have count 0) — [HIBP API v3](https://haveibeenpwned.com/API/v3)
- DOC: "Authorisation is required for all APIs that enable searching HIBP by email address or domain" (breachedaccount, pastes, domain search) — passed in `hibp-api-key` header; breach & paste APIs are "licensed under a Creative Commons Attribution 4.0 International License" with attribution required; all hashes also downloadable via the Pwned Passwords Downloader on GitHub — [HIBP API v3](https://haveibeenpwned.com/API/v3)
- Key needed: **no** for range API; paid key for email/domain endpoints (price NOT FETCHED). Format: text `SUFFIX:COUNT`. Commercial: breach API CC BY 4.0 w/ attribution.
- **G3 fit: good for credential-hygiene enrichment** (hash a captured/suspected password, k-anonymity lookup). **G2 fit: weak/indirect** (count can be a "commonness" weight).

**MITRE ATT&CK (TAXII 2.1 + STIX 2.1 GitHub)**
- LIVE: `GET https://attack-taxii.mitre.org/api/v21/collections/` with `Accept: application/taxii+json;version=2.1` and no key returned collections: `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019` "Enterprise ATT&CK", `x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09` "ICS ATT&CK", plus Mobile; `can_read:true, can_write:false` — [ATT&CK TAXII 2.1](https://attack-taxii.mitre.org/api/v21/collections/)
- LIVE: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` HTTP 200, 55,271,014 bytes — [attack-stix-data raw](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json)
- DOC: repo "contains the MITRE ATT&CK dataset represented in STIX 2.1 JSON collections"; `enterprise-attack/enterprise-attack.json` is latest, versioned files like `enterprise-attack-9.0.json`; machine-readable `index.json`; "Copyright 2020-2025 The MITRE Corporation. Approved for public release. Case number 19-3504"; ATT&CK Terms of Use at attack.mitre.org/resources/terms-of-use/; recommends cti-python-stix2 — [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- Key needed: **no**. Format: STIX 2.1 / TAXII 2.1 JSON. Update: per ATT&CK release (cadence not fetched). Commercial: ATT&CK Terms of Use (NOT FETCHED).
- **G3 fit: excellent** (map technique IDs in alerts to names/tactics/mitigations). **G2 fit: indirect** (tactic position can weight severity).

**abuse.ch Feodo Tracker (still keyless, CC0)**
- LIVE: `https://feodotracker.abuse.ch/downloads/ipblocklist.json` HTTP/2 200 `application/json` without any Auth-Key; record: `{"ip_address":"162.243.103.246","port":8080,"status":"offline","hostname":null,"as_number":14061,"as_name":"DIGITALOCEAN-ASN","country":"US","first_seen":"2022-06-04 21:24:53","last_online":"2026-03-07","malware":"Emotet"}` — [Feodo ipblocklist.json](https://feodotracker.abuse.ch/downloads/ipblocklist.json)
- LIVE: `ipblocklist.csv` header `"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"`, file banner "Last updated: 2026-03-04 14:28:39 UTC", "Terms Of Use: https://feodotracker.abuse.ch/blocklist/" — [Feodo ipblocklist.csv](https://feodotracker.abuse.ch/downloads/ipblocklist.csv)
- LIVE: `ipblocklist_aggressive.json` returned 404 (only .csv/.txt aggressive variants are documented) — [Feodo blocklist page](https://feodotracker.abuse.ch/blocklist/)
- DOC: downloads: `ipblocklist_recommended.txt|.json` (active C2s, "generated every 5 minutes"), `ipblocklist.csv|.json|.txt` (C2s within past 30 days, "intended for SIEM enrichment"), `ipblocklist_aggressive.csv|.txt` (all C2s ever — "will cause false positives"), Suricata rules `feodotracker.rules`; page does not mention Auth-Key — [Feodo blocklist page](https://feodotracker.abuse.ch/blocklist/)
- DOC (terms): "Feodo Tracker, SSL Blacklist and YARAify are all currently free to use without limitations according to Creative Commons principles (CC0) for both commercial and non-commercial purposes." — [abuse.ch Terms of Use §3.4](https://abuse.ch/terms-of-use/)
- LIVE: SSLBL `sslipblacklist.csv` banner says "ATTENTION: This list has been deprecated on 2025-01-03" (Last updated 2025-01-03) — do not use SSLBL IP list in labs — [SSLBL CSV](https://sslbl.abuse.ch/blacklist/sslipblacklist.csv)
- **G3 fit: excellent, keyless IP->botnet C2 enrichment** (small list, clear schema). **G2 fit: yes** (c2_status online/offline, last_online recency as weight).

**Spamhaus DROP**
- LIVE: `https://www.spamhaus.org/drop/drop_v4.json` HTTP 200 (`text/json`), NDJSON lines `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}` ... final line `{"type":"metadata","timestamp":1793535242,"size":107020,"records":1754,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}` — [DROP v4 JSON](https://www.spamhaus.org/drop/drop_v4.json)
- LIVE: `drop.txt` header "; Spamhaus DROP List 2026/11/01 ... Last-Modified: Sun, 01 Nov 2026 11:45:38 GMT ... Expires: ..."; lines `1.10.16.0/20 ; SBL256894` — [DROP txt](https://www.spamhaus.org/drop/drop.txt)
- DOC: JSON URLs `drop_v4.json`, `drop_v6.json`, `asndrop.json`; text files "still being populated" and will eventually be deprecated; "Please DO NOT auto-fetch the DROP list more than once per hour!"; FAQ also says not more than once per day; data "at no cost, regardless of size or business type", "free for any use", credit to The Spamhaus Project required and © text must stay; eDROP merged into DROP on 10 April 2024 — [Spamhaus DROP](https://www.spamhaus.org/drop/)
- **G3 fit: excellent offline CIDR hit-test** (1,754 nets). **G2 fit: yes** (hijacked/criminal netblock = strong weight).

**Tor exit nodes**
- LIVE: `https://check.torproject.org/torbulkexitlist` HTTP 200, one IPv4 per line (1,237 lines on 2026-11-02), e.g. `171.25.193.25` — [Tor bulk exit list](https://check.torproject.org/torbulkexitlist)
- LIVE: Onionoo `https://onionoo.torproject.org/summary?limit=1&flag=Exit` returns JSON `{"version":"8.0","relays_published":"2026-11-02 06:00:00","relays":[{"n":"Quintex152","f":"0008D96...","a":["204.8.96.141","[2620:7:6003::141]"],"r":true}],"relays_truncated":2922,...}` — [Onionoo](https://onionoo.torproject.org/summary?limit=1&flag=Exit)
- DOC: CollecTor exit lists at `/collector/recent/exit-lists/` and archive, `@type tordnsel 1.0` format with `ExitNode`, `Published`, `LastStatus`, `ExitAddress <ip> <timestamp>`; Tor Metrics data is "freely available under a CC0 no copyright declaration" — [Tor CollecTor](https://metrics.torproject.org/collector.html)
- MISP default feeds also list `https://www.dan.me.uk/torlist/?exit` as a CSV Tor exit feed — [MISP defaults.json 2.5](https://raw.githubusercontent.com/MISP/MISP/2.5/app/files/feed-metadata/defaults.json)
- **G3 fit: excellent** (is_tor_exit flag). **G2 fit: yes** (anonymizer weight).

**Shodan InternetDB (keyless)**
- LIVE: `https://internetdb.shodan.io/8.8.8.8` -> `{"cpes":[],"hostnames":["dns.google","indus.capgemini.com"],"ip":"8.8.8.8","ports":[53,443],"tags":["pqc"],"vulns":[]}` — [InternetDB](https://internetdb.shodan.io/8.8.8.8)
- DOC: no Shodan account or API key needed; "It's free for non-commercial use!" — commercial use needs enterprise license; fields ip, ports, cpes, hostnames, tags, vulns; no banners; data updated once a week — [InternetDB docs](https://internetdb.shodan.io/)
- **G3 fit: very good keyless exposure enrichment** (open ports + CVEs for an IP). **G2 fit: yes** (vulns count / risky ports). Training-only use respects non-commercial clause.

**GreyNoise Community API**
- LIVE: `GET https://api.greynoise.io/v3/community/8.8.8.8` without key -> HTTP 404 (meaning "not observed") with body `{"ip":"8.8.8.8","noise":false,"riot":false,"message":"IP not observed scanning the internet."}` and headers `x-ratelimit-limit: 25`, `x-ratelimit-remaining: 24` — [GreyNoise Community](https://api.greynoise.io/v3/community/8.8.8.8)
- DOC: endpoint `https://api.greynoise.io/v3/community/{ip}`; "Available to unauthenticated users with a limited number of lookups per day" (doc says 10/day unauthenticated; Free Tier with business email 50 lookups/week shared with Visualizer; free-mail accounts such as Gmail do not get key access); fields `ip, noise, riot, classification, name, link, last_seen, message`; example `{"ip":"51.91.185.74","noise":true,"riot":false,"classification":"malicious","name":"unknown","link":"https://viz.greynoise.io/ip/51.91.185.74","last_seen":"2021-03-18","message":"Success"}` — [GreyNoise Community API docs](https://docs.greynoise.io/docs/using-the-greynoise-community-api); live header showed limit 25, which conflicts with the documented 10/day
- **G3 fit: marginal** (too few lookups for a class). Use for a demo of "benign scanner vs malicious scanner" only. **G2: classification is a useful label but quota kills it.**

**ip-api.com (free geo-IP)**
- LIVE: `http://ip-api.com/json/8.8.8.8?fields=status,country,countryCode,regionName,city,isp,org,as,query,proxy,hosting` -> `{"status":"success","country":"United States","countryCode":"US","regionName":"Virginia","city":"Ashburn","isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC","proxy":true,"hosting":true,"query":"8.8.8.8"}` with headers `X-Rl: 44`, `X-Ttl: 60` — [ip-api JSON](http://ip-api.com/json/8.8.8.8)
- DOC: 45 requests per minute per IP; `X-Rl` remaining / `X-Ttl` seconds to reset; HTTP 429 when exceeded, repeated abuse -> 1-hour ban; "256-bit SSL encryption is not available for this free API"; "We do not allow commercial use of this endpoint"; fields include continent, country, region, city, zip, lat, lon, timezone, isp, org, as, asname, reverse, mobile, proxy, hosting — [ip-api docs](https://ip-api.com/docs/api:json)
- **G3 fit: good for classroom (45/min, no key), HTTP-only and non-commercial.** **G2: proxy/hosting booleans and country are weights.**

**ipinfo.io**
- LIVE: legacy `https://ipinfo.io/8.8.8.8/json` with no token still returned `{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View","region":"California","country":"US","loc":"38.0088,-122.1175","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles","readme":"https://ipinfo.io/missingauth","anycast":true}` — [ipinfo legacy](https://ipinfo.io/8.8.8.8/json)
- LIVE: `https://api.ipinfo.io/lite/8.8.8.8` without token -> HTTP 403 `{"status":403,"error":{"title":"Unknown token",...}}` — [ipinfo Lite](https://api.ipinfo.io/lite/8.8.8.8)
- DOC: Lite is the free tier — "IPinfo Lite offers unlimited access to our API" but requires a token (query `token=`, Basic auth or Bearer); Lite fields `ip, asn, as_name, as_domain, country_code, country, continent_code, continent`; endpoints `api.ipinfo.io/lite/{ip}` and `api.ipinfo.io/lookup/{ip}` (paid Core/Plus); data downloadable as CSV/MMDB/JSON/Parquet (free status of Lite MMDB not confirmed on page) — [ipinfo developers](https://ipinfo.io/developers)
- **G3 fit: good if learners create a free token (Lite: country + ASN only, unlimited).** Keyless legacy endpoint is undocumented and may vanish.

**AlienVault / LevelBlue OTX**
- LIVE: `GET https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general` with **no** `X-OTX-API-KEY` returned HTTP 200: `{"whois":"http://whois.domaintools.com/8.8.8.8","reputation":0,"indicator":"8.8.8.8","type":"IPv4","base_indicator":{...,"access_type":"public"},"pulse_info":{"count":0,"pulses":[],...}}` — [OTX indicator general](https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general)
- DOC: `/api/v1/indicators/IPv4/{ip}/{section}` with section one of `general, reputation, geo, malware, url_list, passive_dns`; `/api/v1/pulses/subscribed?modified_since=...&limit=...&page=...`; `/api/v1/users/me` validates an API key; "DirectConnect SDK (available in Java and Python)" — [OTX API reference](https://otx.alienvault.com/assets/static/external_api.html)
- DOC: Python SDK `OTXv2` (`pip install OTXv2`), `OTXv2("API_KEY")`, `get_indicator_details_full(IndicatorTypes.DOMAIN, "google.com")`, `get_pulse_indicators(pulse_id)` — [OTX-Python-SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK)
- SECONDARY: LevelBlue blog says a key "allows 10,000 requests per hour rather than just 1,000 requests per hour" (undated) — [LevelBlue blog](https://www.levelblue.com/blogs/levelblue-blog/the-upgraded-alienvault-otx-api-ways-to-score-swag)
- Key: free (optional for indicator lookups in live test; required for subscribed pulses). Format JSON. Commercial terms NOT FETCHED (the interactive /api page is JS-only).
- **G3 fit: excellent** (pulse_info.count, malware, passive_dns, url_list per IOC). **G2 fit: yes** (pulse count / reputation as weight).

**Benign-domain baselines (for false-positive suppression)**
- LIVE: Tranco `https://tranco-list.eu/top-1m.csv.zip` -> 307 to `/download/daily/top-1m.csv.zip` -> 200 `application/zip` 9,720,088 bytes; CSV rows `1,google.com` / `2,cloudflare.com` / `3,amazonaws.com` — [Tranco](https://tranco-list.eu/top-1m.csv.zip)
- DOC: Tranco updated daily by 0:00 UTC; permanent ID at `/top-1m-id`; subdomain variant `/top-1m-incl-subdomains.csv.zip`; sources Cisco Umbrella, Majestic, Farsight, CrUX, Cloudflare Radar; upstream licences: Umbrella free, Majestic CC BY 3.0, CrUX CC BY-SA 4.0, Cloudflare Radar CC BY-NC 4.0; citation via NDSS 2019 paper — [Tranco](https://tranco-list.eu/)
- LIVE: Majestic Million `https://downloads.majestic.com/majestic_million.csv` HTTP 200 `text/csv` 80,368,083 bytes; header `GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs`; row `1,1,google.com,com,505221,2189176,...` — [Majestic Million CSV](https://downloads.majestic.com/majestic_million.csv)
- DOC: Majestic Million "Licensed under a Creative Commons Attribution 3.0 Unported License"; ~80MB; "the million domains we find with the most referring subnets" — [Majestic Million](https://majestic.com/reports/majestic-million)
- LIVE: Cisco Umbrella `http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip` HTTP 200, 12,810,969 bytes — [Umbrella top-1m](http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip)
- DOC: Umbrella lists "generated on a daily basis", based on unique client IPs querying a domain; historical `top-1m-<YYYY-MM-DD>.csv.zip`; no licence text on page beyond "© Cisco Umbrella, 2016" — [Umbrella index](http://s3-us-west-1.amazonaws.com/umbrella-static/index.html)
- **G3 fit: excellent as "known-good" whitelist** (rank lookup). **G2 fit: yes** (rank <= 10k => negative weight).

**MISP default feeds / OSINT MISP-format feeds (no MISP server needed)**
- LIVE: `https://raw.githubusercontent.com/MISP/MISP/2.5/app/files/feed-metadata/defaults.json` HTTP 200 (86,315 bytes), 108 feed entries; each entry has `Feed.name`, `Feed.url`, `Feed.source_format` (misp|csv|freetext), `Feed.enabled` — [MISP defaults.json](https://raw.githubusercontent.com/MISP/MISP/2.5/app/files/feed-metadata/defaults.json)
- LIVE sample of keyless feeds listed there: CIRCL OSINT Feed `https://www.circl.lu/doc/misp/feed-osint` (misp), Botvrij `https://www.botvrij.eu/data/feed-osint` (misp), ET compromised IPs `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`, Phishtank `https://data.phishtank.com/data/online-valid.csv`, firehol_level1, blocklist.de, dataplane.org sshpwauth/vncrfb, CINS ci-badguys, OpenPhish `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`, IPsum levels 1–8 `https://raw.githubusercontent.com/stamparm/ipsum/master/levels/N.txt`, Feodo `ipblocklist.csv`, URLhaus `csv_recent` (now dead — see A2), Metasploit-CVE `https://feeds.ecrimelabs.net/data/metasploit-cve` — [MISP defaults.json](https://raw.githubusercontent.com/MISP/MISP/2.5/app/files/feed-metadata/defaults.json)
- LIVE: CIRCL OSINT `manifest.json` is a dict keyed by event UUID with `Orgc`, `Tag[]` (e.g. `tlp:white`, `type:OSINT`), `info`, `date`, `analysis`, `threat_level_id`, `timestamp`; Botvrij manifest has same shape — [CIRCL manifest](https://www.circl.lu/doc/misp/feed-osint/manifest.json), [Botvrij manifest](https://www.botvrij.eu/data/feed-osint/manifest.json)
- DOC: 108 default feeds from 52 providers: 18 MISP-format, 47 CSV, 43 free-text; feeds "fetch events without prior agreement" — [MISP feeds](https://www.misp-project.org/feeds/)
- DOC: Named MISP communities (CIRCL MISPPRIV >1,100 members, FIRST, NATO, X-ISAC, misp-lea, etc.) are sector/vetting-gated; only SecureGRID Alliance ("free to join") and ICS-CSIRT.io (free but contribution expected) describe open joining — [MISP communities](https://www.misp-project.org/communities/)
- **G3 fit: excellent** (per-event JSON = `<feed>/<uuid>.json` with Attribute[] of ip-dst/domain/sha256). **G2: threat_level_id + tags.** No public open-registration MISP *instance* with API was found (Gap).

### Inferences
- A fully keyless G3 lab is feasible with: KEV + NVD + EPSS (CVE axis), Feodo + Spamhaus DROP + Tor + IPsum/firehol/CINS (IP axis), InternetDB (exposure), ip-api (geo), Tranco/Majestic (benign baseline), ATT&CK STIX (technique names), OTX general lookups (context).
- For G2 scoring, the cleanest numeric inputs without keys are EPSS probability/percentile, CVSS baseScore (NVD), KEV membership, Feodo c2_status/last_online recency, DROP/Tor membership, InternetDB vulns count, Tranco rank.
- Because the live GreyNoise header showed `x-ratelimit-limit: 25` while docs say 10/day, treat Community quota as "a handful per day per IP" — unusable for a 30-student class behind one NAT.

### Gaps
- NVD rate-limit text (5 req / 30 s anonymous, 50 req / 30 s with key, 6 s sleep recommended) is widely documented but **could not be fetched** this session: `https://nvd.nist.gov/developers/start-here`, `/developers/vulnerabilities`, `/developers/api-workflows`, `/developers/request-an-api-key`, `/developers/terms-of-use` all returned a JS shell titled "NVD - Home". The course author must open these in a browser to confirm the numbers and the attribution terms.
- CISA KEV license file `https://www.cisa.gov/sites/default/files/licenses/kev/license.txt` returned Akamai "Access Denied" to curl; licence wording unverified.
- MITRE ATT&CK Terms of Use text not fetched (`https://attack.mitre.org/resources/terms-of-use/`); ATT&CK v18 release date not confirmed.
- OTX: official rate-limit and commercial-use text not found (API docs page is JS; secondary 1,000/10,000 per hour figure is undated).
- No open-registration public MISP instance with API access was identified; MISP communities page describes vetted communities only.
- HIBP paid-key price for breach/domain search not fetched (page section not extracted).

---

## Part A — Key question A2: Which sources require a free key (sign-up) and what are the quotas / terms as of Nov 2026?

### Takeaway
VirusTotal (500/day, 4/min, non-commercial), AbuseIPDB (1,000 checks/day on the free "Standard" plan), all abuse.ch *query APIs* and *bulk exports* for URLhaus / ThreatFox / MalwareBazaar (mandatory `Auth-Key` since 30 June 2025 — old keyless download URLs now return HTTP 410 Gone), Shodan main API (free account, 1 req/s, credit-based), ipinfo Lite (token, unlimited), GreyNoise Free Tier (business e-mail only) and HIBP breach search (paid) need registration; Feodo Tracker is the one abuse.ch dataset that still works without a key.

### Cited Findings

**VirusTotal Public API v3 (vt-py)**
- LIVE: `GET https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8` without key -> `{"error":{"code":"AuthenticationRequiredError","message":"X-Apikey header is missing"}}` (confirms header name `x-apikey`) — [VT API v3](https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8)
- DOC: "The Public API is limited to 500 requests per day and a rate of 4 requests per minute."; "The Public API must not be used in commercial products or services."; also may not be used in business workflows that do not contribute new files; "The only thing you need in order to use the Public API is to sign up to VirusTotal Community and obtain your API key." — [VT Public vs Premium](https://docs.virustotal.com/reference/public-vs-premium-api)
- DOC: vt-py is "The official Python 3 client library for VirusTotal", Apache-2.0, docs at virustotal.github.io/vt-py — [vt-py](https://github.com/VirusTotal/vt-py)
- Key: **yes, free**. Quota 500/day, 4/min. Commercial: **no**. Format JSON (`data.attributes.last_analysis_stats`, etc.).
- **G3 fit: good but quota-bound** (one shared key = 500 lookups/day for whole class; prefer per-student keys or cache). **G2: last_analysis_stats.malicious count is a classic score input.**

**AbuseIPDB APIv2**
- LIVE: `GET https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8` without key -> 401 `"Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key."` — [AbuseIPDB check](https://api.abuseipdb.com/api/v2/check)
- DOC: header `Key: YOUR_OWN_API_KEY` plus `Accept: application/json`; daily limits on the Standard (free) column: check 1,000; reports 100; blacklist 5; report 1,000; check-block 100; bulk-report 5; clear-address 5; exceeding -> HTTP 429 "Daily rate limit of 1000 requests exceeded for this endpoint"; Standard blacklist capped at 10,000 IPs, check-block up to /24 and maxAgeInDays <= 30; example `/check` response fields: `ipAddress, isPublic, ipVersion, isWhitelisted, abuseConfidenceScore (0-100), countryCode, countryName, usageType, isp, domain, isTor, totalReports, numDistinctUsers, lastReportedAt, reports[]` — [AbuseIPDB docs](https://docs.abuseipdb.com/)
- Key: **yes, free**. Commercial-use terms not on docs page (Gap).
- **G3 fit: excellent** (abuseConfidenceScore, isTor, usageType). **G2 fit: excellent** (0–100 score already normalised).

**abuse.ch URLhaus / ThreatFox / MalwareBazaar (Auth-Key mandatory)**
- DOC: "Starting June 30, 2025, authentication will be mandatory."; API-related data downloads require authentication on all abuse.ch platforms; Auth-Key obtained at auth.abuse.ch using an X, LinkedIn, Google or GitHub login, connect a second provider as backup, then create the key; send as HTTP header `Auth-Key: YOUR-AUTH-KEY` (post dated 18 Nov 2024) — [abuse.ch Community First](https://abuse.ch/blog/community-first/)
- LIVE: keyless API calls now fail: `POST https://urlhaus-api.abuse.ch/v1/host/` -> `{"error": "Unauthorized"}`; `POST https://threatfox-api.abuse.ch/api/v1/` -> `{"error": "Unauthorized"}`; `POST https://mb-api.abuse.ch/api/v1/` -> `{"error": "Unauthorized"}` — [URLhaus API](https://urlhaus-api.abuse.ch/), [ThreatFox API](https://threatfox-api.abuse.ch/api/v1/), [MalwareBazaar API](https://mb-api.abuse.ch/api/v1/)
- LIVE: legacy bulk URLs return **HTTP 410 Gone** ("Please remove all references to this resource"): `https://urlhaus.abuse.ch/downloads/csv_recent/`, `/downloads/text/`, `/downloads/hostfile/`, `/downloads/csv_online/`, `https://threatfox.abuse.ch/export/json/recent/`, `/export/csv/recent/`, `https://bazaar.abuse.ch/export/txt/sha256/recent/` — these URLs are still listed in MISP `defaults.json` 2.5 and will silently fail there — [URLhaus csv_recent (410)](https://urlhaus.abuse.ch/downloads/csv_recent/)
- DOC: URLhaus API base `https://urlhaus-api.abuse.ch/v1/` with `urls/recent/` and `payloads/recent/` (GET, `limit` max 1000), `url/`, `urlid/`, `host/`, `payload/` (md5/sha256), `tag/`, `signature/`, `download/<sha256>`; Auth-Key "required on every request"; `query_status` ok|no_results|invalid_host; bulk ZIPs (password "infected") at `https://datalake.abuse.ch/urlhaus/hourly/` and `/daily/`; example host record: `{"host":"vektorex.com","firstseen":"2019-01-15 07:09:01 UTC","url_count":"120","blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"},"urls":[{"id":"121319","url_status":"online","date_added":"2019-02-11 07:45:05 UTC","threat":"malware_download","reporter":"abuse_ch","larted":"false","tags":["AZORult","exe"]}]}` — [URLhaus API docs](https://urlhaus-api.abuse.ch/)
- DOC: ThreatFox `POST https://threatfox-api.abuse.ch/api/v1/` JSON body `{"query":"get_iocs","days":1..7}` (default 3), also `ioc`, `search_ioc` (`search_term`, `exact_match`), `search_hash`, `taginfo` (limit default 100 max 1000), `malwareinfo`; record fields `id, ioc, ioc_type, threat_type, malware, malware_printable, malware_alias, malware_malpedia, confidence_level, first_seen, last_seen, reference, reporter, tags`; "free under fair use ... commercial use may require a paid subscription" — [ThreatFox API](https://threatfox.abuse.ch/api/)
- DOC: MalwareBazaar `POST https://mb-api.abuse.ch/api/v1/` queries `get_info` (sha256/sha1/md5), `get_recent` (`selector=time` or `100`), `get_taginfo`, `get_siginfo`, `get_file` (zip, password "infected", AES128 -> use pyzipper); record fields `sha256_hash, sha1_hash, md5_hash, first_seen, last_seen, file_name, file_size, file_type_mime, file_type, reporter, signature, imphash, tlsh, ssdeep, magika, tags, intelligence{clamav,downloads,uploads,mail}`; bulk at `https://datalake.abuse.ch/malware-bazaar/hourly/` and `/daily/` — [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- DOC (terms): platforms "PROVIDED FREE OF CHARGE, SUBJECT TO THE FAIR USE PRINCIPLES"; "Authenticated Users may access the Platforms for not-for-profit purposes, subject to usage limitations"; Query Volume Limits are "volumes reasonably expected for non-commercial or non-profit purposes"; exceeding may require a paid subscription; **exception**: Feodo Tracker, SSL Blacklist, YARAify are CC0 for commercial and non-commercial use — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- Key: **yes (free, social login)**. Quota: unspecified "fair use". Commercial: not-for-profit only unless paid (except Feodo/SSLBL/YARAify CC0). Format JSON.
- **G3 fit: very good once each learner has an Auth-Key** (URL/host/hash context). **G2: ThreatFox confidence_level (0–100) and URLhaus url_status/threat are direct inputs.**

**Shodan main API**
- DOC: "To use the API you need to have an API key, which you can get for free by creating a Shodan account." — [Shodan API requirements](https://developer.shodan.io/api/requirements)
- DOC (billing page): "All Shodan accounts come with a free API plan"; rate limit 1 request/second on all API plans; Membership $49 one-time (100 query credits/mo, 100 scan credits, 16 monitored IPs); Freelancer $69/mo (10,000 query credits); Small Business $359/mo; Corporate $1,099/mo — [Shodan billing](https://account.shodan.io/billing)
- Free-plan access to `/shodan/host/{ip}` and credit counts for the free plan were not legible on the page (Gap). For labs, prefer keyless InternetDB (A1).

**GreyNoise Free Tier** — see A1: key only for business-email accounts; 50 lookups/week — [GreyNoise Community API docs](https://docs.greynoise.io/docs/using-the-greynoise-community-api)

**ipinfo Lite** — token required, unlimited, country+ASN only — [ipinfo developers](https://ipinfo.io/developers)

**HIBP breach/paste/domain search** — paid `hibp-api-key`; CC BY 4.0 with attribution — [HIBP API v3](https://haveibeenpwned.com/API/v3)

### Inferences
- Any lab that still points at `urlhaus.abuse.ch/downloads/csv_recent/` or `threatfox.abuse.ch/export/...` (including unmodified MISP default feeds) is broken as of 2026; swap to Feodo (keyless) or to the Auth-Key APIs with per-student keys.
- Per-student free keys (VT, AbuseIPDB, abuse.ch) are the realistic model; a single shared VT key gives a 30-person class ~16 lookups each per day.
- Commercial-use restrictions (VT Public, ip-api free, InternetDB, abuse.ch fair-use) are compatible with a training course but should be stated in lab READMEs so learners do not copy the pattern into production QRadar automations.

### Gaps
- abuse.ch does not publish numeric query limits ("fair use" only); MalwareBazaar daily download cap number not on API page.
- Shodan free-plan credit numbers and whether free keys can call `/shodan/host/{ip}` not extracted from the billing page.
- AbuseIPDB commercial-use terms are not on the docs page (would be in site ToS, not fetched).
- VirusTotal "Getting started" page (key header, vt-py quickstart) not fetched; header name confirmed only via live error message.

---

## Part B — Key question B1: LEEF 1.0 / 2.0 event format and how QRadar ingests LEEF via syslog

### Takeaway
Official IBM DSM docs (fetched) define LEEF as `[syslog header] LEEF:<ver>|Vendor|Product|Version|EventID|[delimiter|]key=value<TAB>key=value...`; LEEF 2.0 adds a header field declaring a custom attribute delimiter (single char or `x5E`-style hex); predefined keys (`src, dst, srcPort, dstPort, proto, sev 1-10, cat, usrName, devTime, devTimeFormat, ...`) drive QRadar normalisation; LEEF arrives by syslog or Log File Protocol and QRadar auto-discovers a log source after ~25 events.

### Cited Findings
- DOC: "LEEF events must use UTF-8 character encoding"; LEEF can be sent "by Syslog or by file import using the Log File Protocol"; QRadar "typically needs at least 25 LEEF events to identify the source and create a log source"; until then events are "SIM Generic Log DSM" / "Unknown Log Event"; after 1,000 unidentified events QRadar raises a notification and stops auto-detecting (manual log source needed) — [IBM LEEF overview](https://www.ibm.com/docs/en/dsm?topic=leef-overview)
- DOC: structure = optional syslog header (RFC 3164, e.g. `<13>Jan 18 11:07:53 192.168.1.1`, or RFC 5424 `<pri>1 yyyy-MM-ddTHH:mm:ss.SSSZ host`), then LEEF header, then attributes; header is pipe-delimited in order: LEEF version (`LEEF:1.0` / `LEEF:2.0`), Vendor, Product, Product version, EventID (<=255 chars), and for 2.0 only a Delimiter field; delimiter may be a single character (e.g. `^`) or hex with `0x`/`x` prefix (page examples `x5E` = caret, `x7c`); default attribute separator is tab; attribute order not enforced; avoid IPv6 in syslog header — [IBM LEEF event components](https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components)
- DOC exact examples: LEEF 1.0 header `LEEF:1.0|Microsoft|MSExchange|4.0 SP1|15345|`; LEEF 2.0 header `LEEF:2.0|Lancope|StealthWatch|1.0|41|^|`; attributes `src=192.0.2.0 dst=172.50.123.1 sev=5 cat=anomaly srcPort=81 dstPort=21 usrName=joe.black` (tab-separated in practice) — [IBM LEEF event components](https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components)
- DOC: predefined attributes (type): `cat` (string, extends EventID for QID mapping), `devTime` (date), `devTimeFormat` (required unless devTime is 10/13-digit epoch), `proto`, `sev` (integer 1–10), `src`/`dst` (IPv4/IPv6), `srcPort`/`dstPort` (0–65535), `srcPreNAT/dstPreNAT/srcPostNAT/dstPostNAT`, `usrName` (<=255), `srcMAC/dstMAC`, `*PreNATPort/*PostNATPort`, `identSrc/identHostName/identNetBios/identGrpName`, `vSrc/vSrcName`, `accountName`, `srcBytes/dstBytes/srcPackets/dstPackets/totalPackets`, `role, realm, policy, resource, url, groupID, domain`; `isLoginEvent/isLogoutEvent/identSecondlp/calLanguage/calCountryOrRegion` are reserved/not implemented — [IBM predefined LEEF attributes](https://www.ibm.com/docs/en/dsm?topic=overview-predefined-leef-event-attributes)
- SECONDARY (search snippet): IBM "Universal LEEF" DSM "parses events forwarded from syslog or from files in LEEF format polled through the Log File protocol" — [IBM Universal LEEF (legacy KC URL)](https://www.ibm.com/support/knowledgecenter/SS42VS_DSM/com.ibm.dsm.doc/c_DSM_guide_UniversalLEEF_intro.html) — the current-docs Universal LEEF page was NOT FETCHED (index truncated).
- SECONDARY: NXLog documentation gives complete single-line LEEF examples usable as test fixtures — [NXLog LEEF](https://docs.nxlog.co/integrations/format/leef.html)

### Inferences
- A lab "LEEF emitter" in Python should produce: `<13>` + RFC3164 timestamp + hostname + space + `LEEF:2.0|<Course>|<Tool>|1.0|<EventID>|x09|` + tab-joined `devTime=<epoch ms>` (so no devTimeFormat needed), `src=`, `dst=`, `srcPort=`, `dstPort=`, `proto=`, `sev=1..10`, `cat=`, `usrName=`, plus custom keys for enrichment (e.g. `epss=`, `kev=true`, `abuseScore=`). Using a 13-digit epoch for devTime avoids the devTimeFormat requirement stated by IBM.
- Since auto-discovery needs ~25 events, lab scripts should emit batches >= 25 lines with a stable Vendor|Product pair.

### Gaps
- IBM page on syslog ports (514/6514) and the Universal LEEF log source parameter table was not retrieved (IBM docs index page is huge/truncated; direct `?topic=` guesses returned 403 to curl).
- IBM LEEF Format Guide PDF `https://www.ibm.com/docs/en/SS42VS_DSM/pdf/b_Leef_format_guide.pdf` returned HTTP 403 (bot block) — open in browser.
- IBM pages do not describe escaping of `=`/tab inside values; author should test or cite DSM Editor behaviour.

---

## Part B — Key question B2: QRadar REST API basics (versions, auth, Ariel searches, offenses, pagination)

### Takeaway
IBM's getting-started page confirms: HTTPS calls to the Console, auth via `SEC` header with an authorized-service token (recommended; basic auth only for the doc page), `Version` header with semantic versions, filter/sort query params and `Range` header paging; version map 7.5.0 → API 17.0, 7.5.0 UP15 → 28.0, 7.6.0 → 29.0; the public GitHub-Pages reference (up to 23.0) documents `POST /ariel/searches` (async AQL, returns `search_id`, `status` WAIT|EXECUTE|SORTING|COMPLETED|CANCELED|ERROR) and `GET /siem/offenses` (offense object with magnitude/severity/credibility/relevance, times in epoch ms).

### Cited Findings
- DOC: API is used "by sending HTTPS requests to endpoint URLs on the QRadar SIEM Console" with GET/POST/PUT/DELETE; two auth options: "Authorized service token" in the **SEC** header (recommended for all integrations; valid until expiry) or username/password HTTP basic ("supported only for viewing the documentation page"); `Version` header requests an API version (semantic versioning; `3` → latest 3.x, `3.0` exact; omitted → latest, which may break after upgrade); deprecated endpoints return a `Deprecated` header and remain >= one release; removed → HTTP 410; unsupported version → HTTP 422; query params `filter`, `sort`, paging via **Range header**; sample code on GitHub — [IBM QRadar REST API getting started](https://www.ibm.com/docs/en/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_getting_started.html)
- DOC version map (Table 1 excerpt): QRadar 7.6.0 → REST API 29.0 (also supports 28.0, 27.0, 26.x); 7.5.0 UP15 → 28.0; 7.5.0 → 17.0; 7.4.0 → 13.0 — [IBM QRadar REST API getting started](https://www.ibm.com/docs/en/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_getting_started.html)
- LIVE: public static reference sites exist for API 20.0, 21.0, 22.0, 23.0 at `https://ibmsecuritydocs.github.io/qradar_api_<ver>/` (all HTTP 200); 23.0 index lists `GET/POST /ariel/searches`, `GET /ariel/searches/{search_id}`, `GET /ariel/searches/{search_id}/results`, `GET /ariel/searches/{search_id}/metadata`, `GET /siem/offenses`, `GET/POST /siem/offenses/{offense_id}`, `/siem/offenses/{offense_id}/notes`, `/siem/source_addresses`, `/config/access/authorized_services` — all tagged DEPRECATED on that 23.0 snapshot — [qradar_api_23.0](https://ibmsecuritydocs.github.io/qradar_api_23.0/)
- DOC: `POST /ariel/searches` creates an asynchronous Ariel search; "accepts only SELECT queries"; params `query_expression` (AQL) xor `saved_search_id`; default time window is last 60 seconds unless the AQL sets one; 201 on create; 422 code 2000 = invalid AQL; 503 = Ariel offline; response fields `search_id, cursor_id, status (WAIT|EXECUTE|SORTING|COMPLETED|CANCELED|ERROR), progress, record_count, processed_record_count, data_file_count, data_total_size, query_execution_time, query_string, save_results, desired_retention_time_msec, error_messages[], snapshot, subsearch_ids`; sample query selects `sourceip, starttime, qid, sourceport` from events with a subquery on destinationip — [POST /ariel/searches (23.0)](https://ibmsecuritydocs.github.io/qradar_api_23.0/23.0--ariel-searches-POST.html)
- DOC: `GET /siem/offenses` params `sort`, `filter`, `fields` (e.g. `fields=id,description,magnitude`), header **Range** "zero-indexed, for example `items=50-99` returns the second 50 offenses"; Offense fields: `id, description, status (OPEN|HIDDEN|CLOSED), assigned_to, protected, follow_up, inactive, magnitude, severity, credibility, relevance, offense_type, offense_source, source_network, domain_id, start_time, last_updated_time, first_persisted_time, last_persisted_time, close_time (epoch ms), closing_user, closing_reason_id, event_count, flow_count, device_count, category_count, ..., categories[], destination_networks[], source_address_ids[], local_destination_address_ids[], rules[{id,type: ADE_RULE|BUILDING_BLOCK_RULE|CRE_RULE}], log_sources[{id,name,type_id,type_name}]` — [GET /siem/offenses (23.0)](https://ibmsecuritydocs.github.io/qradar_api_23.0/23.0--siem-offenses-GET.html)
- LIVE (GitHub API search): IBM-owned QRadar repos include `IBM/api-samples` ("Samples code that uses QRadar API's", archived, last push 2020-05-20), `IBM/qpylib` (Python utilities for QRadar apps, active 2026-09-28), `IBM/qradar-mcp` (push 2026-11-01) and `IBM/qradar-mcp-server` (2026-09-18), `IBM/pySigma-backend-QRadar-AQL` (Sigma → AQL, push 2026-10-29), `IBM/qradar-misp-ioc-importer` (MISP → reference sets, 2026-01-25), `IBM/IBM-QRadar-Universal-Cloud-REST-API` (workflows, 2026-08-18) — [GitHub search](https://api.github.com/search/repositories?q=qradar+org:ibm-security+org:IBM)

### Inferences
- For a classroom without QRadar, a mock REST server should implement exactly: `POST /api/ariel/searches?query_expression=...` → `{search_id, status:"WAIT"}`; `GET /api/ariel/searches/{id}` → status progression to COMPLETED; `GET /api/ariel/searches/{id}/results` → `{"events":[...]}`; `GET /api/siem/offenses` honouring `Range: items=0-49`, `filter`, `fields`; all requiring `SEC` and `Version` headers (e.g., `Version: 28.0` for 7.5.0 UP15). That mirrors what the IBM docs and the 23.0 reference specify.
- The `ibmsecuritydocs.github.io` snapshots stop at 23.0 while current QRadar ships 28.0/29.0; use them for shapes, but tell learners the live `/api_doc` on their Console is authoritative.

### Gaps
- IBM doc pages for the exact `Range: items=x-y` paging topic and `/api_doc` interactive docs were not retrieved (IBM docs TOC pages are 150k–600k chars; `?topic=` URLs returned 403 to curl).
- GitHub Pages for API 24.0+ were not probed; existence unknown.
- `GET /ariel/searches/{id}/results` response-shape page was not fetched (only index entry seen).

---

## Part B — Key question B3: AQL syntax basics

### Takeaway
IBM's AQL index page confirms the SELECT/FROM events|flows/WHERE/GROUP BY/ORDER BY/LIMIT structure with `LAST n MINUTES|HOURS|DAYS` or `START ... STOP ...` time clauses and lookup functions `QIDNAME(qid)`, `LOGSOURCENAME(logsourceid)`, `CATEGORYNAME(category)`, `DATEFORMAT`, `UTF8(payload)`, `TEXT SEARCH`, `REFERENCESETCONTAINS`; the detailed example page could not be retrieved, so the concrete query examples below are inferred.

### Cited Findings
- DOC: AQL queries and manipulates event and flow data in the Ariel database; core `SELECT ... FROM events|flows` with optional `WHERE`, `GROUP BY`, `ORDER BY`, `LIMIT`; time via `LAST n MINUTES|HOURS|DAYS` or `START`/`STOP`; common fields `sourceip, destinationip, destinationport, username, qid, starttime, magnitude`; functions `QIDNAME(qid)`, `LOGSOURCENAME(logsourceid)`, `CATEGORYNAME(category)`, `DATEFORMAT`, `UTF8(payload)`, `TEXT SEARCH`, `REFERENCESETCONTAINS`; also logical/comparison/bitwise operators, CIDR addresses, subqueries, sessions, IF/CASE — [IBM AQL (QRadar 7.5)](https://www.ibm.com/docs/en/qsip/7.5?topic=aql-ariel-query-language)
- DOC: the IBM 7.5 docs index lists pages "Sample event, log source, and storage usage AQL statements", "Tips for creating AQL queries for dashboard charts", "AQL Generation and AQL Explanation" (bodies not retrieved) — [IBM QRadar 7.5 docs index](https://www.ibm.com/docs/en/qsip/7.5?topic=language-aql-query-examples)
- DOC: `POST /ariel/searches` sample AQL selects `sourceip, starttime, qid, sourceport` from events filtered by a subquery on destinationip — [POST /ariel/searches (23.0)](https://ibmsecuritydocs.github.io/qradar_api_23.0/23.0--ariel-searches-POST.html)
- LIVE: `IBM/pySigma-backend-QRadar-AQL` ("QRadar AQL backend for converting Sigma rules to QRadar AQL queries", active Oct 2026) is a source of machine-generated, syntactically valid AQL examples — [pySigma-backend-QRadar-AQL](https://github.com/IBM/pySigma-backend-QRadar-AQL)

### Inferences
- Illustrative (author-composed, consistent with the IBM-listed grammar — verify on a Console): `SELECT sourceip, destinationip, destinationport, QIDNAME(qid) AS event, LOGSOURCENAME(logsourceid) AS src FROM events WHERE destinationport=22 GROUP BY sourceip ORDER BY COUNT(*) DESC LAST 24 HOURS LIMIT 50`; `SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS t, username, UTF8(payload) FROM events WHERE REFERENCESETCONTAINS('KEV_CVEs', "cve") START '2026-11-01 00:00' STOP '2026-11-02 00:00'`.
- A lab can let learners write AQL against a DuckDB/SQLite table named `events` with the same column names (sourceip, destinationip, destinationport, username, qid, logsourceid, starttime epoch ms, payload) and a thin translator for `LAST n HOURS` → `starttime >= now()-n h`; Sigma→AQL via pySigma gives realistic rule queries.

### Gaps
- The IBM AQL guide PDF (`b_qradar_aql.pdf`) and the "Sample ... AQL statements" page returned 403/unfetchable; no verbatim IBM AQL examples were captured. Author should copy examples from the Console's AQL guide or the pySigma backend tests.

---

## Part B — Key question B4: Public QRadar sample data, Community Edition status (2026), sample apps on GitHub

### Takeaway
No official IBM "sample offense/event export" dataset was found; the realistic public assets are the (archived) `IBM/qradar-sample-apps` and `IBM/api-samples` repos, active `IBM/qpylib`, `IBM/qradar-mcp*`, `IBM/pySigma-backend-QRadar-AQL`, and QRadar Community Edition, which IBM's page still offers free (IBMid required) at 100 EPS / 5,000 FPM with a quarterly-renewed 3-month key, currently based on 7.5.0 UP15 / 7.6 FP1 with no discontinuation notice.

### Cited Findings
- DOC (ibm.com): Community Edition is "a fully-featured free version of QRadar SIEM" built on "QRadar SIEM 7.5.0 Update Package 15 and 7.6 Fix Pack 1", RHEL 8.10; 3-month license renewed quarterly via new key file; 100 EPS and 5,000 FPM; default 30-day license after install until key upload; one All-in-One Console only (plus optional App Host); 24 GB RAM, 250 GB disk, 4 cores (6 recommended), static IP, FQDN hostname; IBMid required — register at `https://www.ibm.com/account/us-en/signup/register.html`, ISO at `https://www.ibm.com/resources/mrs/assets?S_PKG=ov60294&source=swg-qradarcom`; "provided without warranty or support" (no support cases; help via r/QRadar and IBM Community); upgrades not supported — reinstall latest ISO; some countries blocked by U.S. export rules; apps from X-Force App Exchange allowed, apps share 10% of RAM; personal non-commercial app development permitted; **no discontinuation notice on the page** — [IBM QRadar Community Edition](https://www.ibm.com/community/101/qradar/ce/)
- SECONDARY (search snippets, IBM Community): earlier CE builds were UP8 (May 2024) and UP14; lifecycle page has no CE entry — [IBM Community blog 2024](https://community.ibm.com/community/user/blogs/shivam-sharma/2024/05/07/qradar-classic-siem-community-edition)
- LIVE: `https://github.com/ibm-security/qradar-sample-apps` → **404**; the repo lives at `https://github.com/IBM/qradar-sample-apps` (HTTP 200) and is **archived** (last push 2025-09-17) — [IBM/qradar-sample-apps](https://github.com/IBM/qradar-sample-apps)
- LIVE README: sample apps built on "v2 of the QRadar App Framework", Red Hat UBI based; requires QRadar App SDK v2 (X-Force App Exchange), Python 3, Docker; samples include `HelloWorld`, `Ariel` ("Use the QPyLib Ariel features"), `APIVersion`, `RESTMethod`, `CustomColumnsOffenses`, `IPHoverOverMetaData`, `OAuth`, `PostgreSQL`, `SQLite`, `Multitenancy`, `NGINX`, `NodeJS` — [IBM/qradar-sample-apps README](https://raw.githubusercontent.com/IBM/qradar-sample-apps/master/README.md)
- LIVE (GitHub API): `IBM/api-samples` (REST API sample code, archived 2020), `IBM/sample-apps` (older framework, archived 2021), `IBM/qpylib` (active), `IBM/qjslib` (archived), `IBM/qradar-sigma-app-samples` & `IBM/qradar-yara-app-samples`, `IBM/qradar-misp-ioc-importer` (MISP → reference sets), `IBM/qradar-mcp`, `IBM/qradar-mcp-server`, `IBM/pySigma-backend-QRadar-AQL`, `IBM/pySigma-backend-QRadar-KQL`, `IBM/qradar-aqlcodegen-app` — [GitHub search](https://api.github.com/search/repositories?q=qradar+org:ibm-security+org:IBM)
- Web search for "QRadar sample event data download" surfaced only LEEF format docs (IBM, NXLog) and a Splunk Connect for Syslog commit containing LEEF 2.0 sample lines; no IBM sample-data package — [search result: NXLog LEEF](https://docs.nxlog.co/integrations/format/leef.html)

### Inferences
- For "QRadar-shaped" lab data, generate it: LEEF lines (B1) for events, and offense JSON matching the `GET /siem/offenses` schema (B2) for offenses. The `IBM/api-samples` repo (archived, Python 2-era) still shows canonical request/response flows and can be mined for JSON shapes.
- QRadar CE at 24 GB RAM is feasible for an instructor demo VM but not per-student laptops; keep it optional.

### Gaps
- No IBM-published sample offense/event export dataset located (searched ibm.com and GitHub).
- CE ISO link requires IBMid sign-in; not tested (no sign-up performed per constraints).
- GitHub-Pages reference for API > 23.0 and IBM "QRadar App SDK v2" docs not fetched.

---

## Part B — Key question B5: 2024–2026 ownership change (Palo Alto / IBM) and end-of-support status

### Takeaway
Official sources confirm Palo Alto Networks closed the acquisition of IBM's **QRadar SaaS assets** on 4 Sept 2024 and lists "IBM Security QRadar on Cloud" with an End-of-Life of **April 14, 2026** (second SaaS wave 31 Aug 2026 per secondary sources); IBM's own May 2025 blog states "QRadar on-premise remains a core focus of IBM ... no plans for end-of-life", and IBM's lifecycle page shows 7.5.0 and 7.6.0 as "Current Patched (Fixed) Release" with no end date; Community Edition has no lifecycle entry or EOL notice.

### Cited Findings
- OFFICIAL (IBM Community blog): "Palo Alto Networks completed its acquisition of IBM's QRadar Software as a Service (SaaS) assets, announced on 4 September [2024]"; IBM Consulting provides advisory/integration/threat-detection services in the partnership — [IBM Community: Palo Alto completes acquisition](https://community.ibm.com/community/user/blogs/cameron-clarke/2024/09/12/palo-alto-completes-acquisition-of-ibm-qradar-saas)
- OFFICIAL (paloaltonetworks.com EOL summary): section "Threat Management (including QRadar) SaaS Products acquired from IBM" lists "IBM Security QRadar on Cloud — April 14, 2026" as End of Life; page offers transition help ("Planning your transition from QRadar?") — [Palo Alto Networks End-of-Life Summary](https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary)
- OFFICIAL (paloaltonetworks.com datasheet landing): "End-of-Sale and End-of-Life Dates for Threat Management SaaS Products", dated April 14, 2025, covering SKUs acquired from IBM (PDF itself not fetched) — [PAN EoS/EoL datasheet](https://paloaltonetworks.com/resources/datasheets/eos-and-eol-for-threat-management-saas-products)
- SECONDARY (search summary of PAN pages + vendor blogs): first wave EOL **April 14, 2026** (QRadar on Cloud, Cloud-Native SIEM, SOAR SaaS, Log Insights, Randori Recon); second wave **August 31, 2026** (QRadar Suite EDR, XDR, X-Force TI, Randori Attack, QRadar Advisor with Watson); PAN summary states the announcement "does not affect any IBM QRadar on-premise products or SKUs" — [Blumira (competitor)](https://www.blumira.com/qradar-alternative), [endoflife.ai](https://endoflife.ai/article-qradar-saas-shutdown-august-2026), [Secure ISS (MSSP)](https://www.secure-iss.com/newsroom/qradar-cortex-xsiam-migration-options)
- SECONDARY (press): closing announced September 4, 2024; free migration to Cortex XSIAM for eligible customers with IBM Consulting; IBM continues on-prem QRadar support — [TechRadar](https://www.techradar.com/pro/palo-alto-networks-completes-ibm-s-qradar-acquisition), [Dark Reading](https://www.darkreading.com/cybersecurity-operations/palo-alto-networks-closes-acquisition-of-ibm-s-qradar-saas-assets); PAN investor press release URL returned 403 to fetch — [PAN press release (NOT FETCHED)](https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networksr-closes-acquisition-ibms-qradar-saas-assets)
- OFFICIAL (IBM Community blog, posted 05/15/25): "QRadar on-premise remains a core focus of IBM." and "Active development, strategic investment and full support for the platform will continue, with no plans for end-of-life." — [IBM Community: QRadar continuous innovation & support](https://community.ibm.com/community/user/blogs/lauren-hogge/2025/05/08/qradar-continuous-innovation-support)
- OFFICIAL (IBM support lifecycle): QRadar 7.6.0 (date shown June 30th, 2026) and 7.5.0 (GA Jan-22) both listed as "Current Patched (Fixed) Release"; 7.5 "follows the Continuous Delivery software support model", 7.6 follows SC-5; 7.4.1–7.4.3 end of support 28 April 2023; 7.3.x and 7.4.0 ended 30 Sept 2022; **no entries for Community Edition or QRadar on Cloud** — [IBM QRadar Support Lifecycle](https://www.ibm.com/support/pages/ibm-qradar-support-lifecycle) (reached via ibm.biz/qradarlifecycle redirect chain)
- OFFICIAL (IBM support): hardware appliances e.g. QRadar Network Insights 1920 G3 / 1940 G2 (7.5.x) withdrawn 31-Dec-2026, extended support to 31-Dec-2030; each appliance's hardware EOS is 5 years from purchase — [IBM node 7258124](https://www.ibm.com/support/pages/node/7258124), [IBM node 7258123](https://www.ibm.com/support/pages/node/7258123)
- OFFICIAL (IBM CE page): no discontinuation or end-of-availability notice; CE tracks 7.5.0 UP15 / 7.6 FP1 — [IBM QRadar Community Edition](https://www.ibm.com/community/101/qradar/ce/)

### Inferences
- As of Nov 2026 the SaaS/QRoC line is gone (both PAN EOL dates have passed); learners "running QRadar in production" are necessarily on **on-prem QRadar SIEM 7.5.x (continuous delivery) or 7.6.x**, so the course should target REST API versions 28.0/29.0 shapes and LEEF for ingestion, not QRoC specifics.
- Competitor/MSSP sources (Blumira, Secure ISS, Stellar Cyber, D3) consistently frame IBM's on-prem commitment as uncertain; IBM's own statement is the only primary source and says the opposite — present both to learners as "official position vs market commentary".

### Gaps
- The PAN datasheet PDF with the full per-SKU EoS/EoL table was not downloaded; the 31 Aug 2026 second-wave date rests on secondary sources plus the PAN summary page section (only the QRadar on Cloud row was extracted).
- IBM's lifecycle page gives no explicit EOL for 7.5.0; whether a future announcement exists cannot be verified.
- IBM press release on the original May 2024 agreement (purchase terms, incremental payments for migrating on-prem customers) not fetched; those details appear only in TechTarget/TechRadar coverage.
