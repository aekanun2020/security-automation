# Threat Intelligence Automation with Python (Module 5 – Python for Cybersecurity, SOC/blue-team)

Research date: 2026-11-01. Star counts and "archived" statuses are as shown on GitHub on that date. Layer (a) = foundational/official sources, (b) = community writings and repositories, (c) = code examples (final section). Every snippet is either attributed to the documentation page it was taken from or explicitly marked "illustrative, assembled from documented APIs".

## Key Question 1: What are the standards and data models for CTI exchange, and where are the official specs?

### Takeaway
The de facto exchange stack is OASIS STIX 2.1 (data model: 18 SDOs, 2 SROs, 18 SCOs) transported over OASIS TAXII 2.1 (HTTPS/JSON, media type `application/taxii+json;version=2.1`), framed analytically by three older models (Kill Chain 2011, Diamond Model 2013, Pyramid of Pain 2013), governed organisationally by NIST SP 800-150 (2016) and labelled for handling with FIRST TLP 2.0 (2022). MITRE ATT&CK is itself published as STIX 2.1 and served over a public TAXII 2.1 server.

### Cited Findings

**STIX 2.1 (OASIS)**
- The current STIX 2.1 document is titled "STIX Version 2.1 Errata 01", shown as "OASIS Standard incorporating Draft 01 of Errata 01", dated 02 April 2025; editors are Rich Piazza (MITRE), Emily Ratliff (IBM), Stephan Relitz (Peraton) and Christian Studer (CIRCL) — [OASIS STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- STIX Domain Objects (SDOs, 18): Attack Pattern, Campaign, Course of Action, Grouping, Identity, Indicator, Infrastructure, Intrusion Set, Location, Malware, Malware Analysis, Note, Observed Data, Opinion, Report, Threat Actor, Tool, Vulnerability — [OASIS STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- STIX Relationship Objects (SROs, 2): Relationship and Sighting — [OASIS STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- STIX Cyber-observable Objects (SCOs, 18): Artifact, Autonomous System, Directory, Domain Name, Email Address, Email Message, File, IPv4 Address, IPv6 Address, MAC Address, Mutex, Network Traffic, Process, Software, URL, User Account, Windows Registry Key, X.509 Certificate — [OASIS STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- For Indicator objects, "`pattern` and `pattern_type` are required and cannot be set automatically"; `valid_from` is required but defaults to the current time if omitted; serialized objects carry `"spec_version": "2.1"` and indicators also carry `"pattern_version": "2.1"` — [stix2 docs: Creating STIX Content](https://stix2.readthedocs.io/en/latest/guide/creating.html)
- Malware objects require `is_family`; Relationship requires `relationship_type`, `source_ref`, `target_ref`; Bundle sets `type`, `id`, `spec_version` automatically — [stix2 docs: Creating STIX Content](https://stix2.readthedocs.io/en/latest/guide/creating.html)

**TAXII 2.1 (OASIS)**
- "TAXII Version 2.1" is an OASIS Standard dated 10 June 2021; it is "an application layer protocol for the communication of cyber threat information" over HTTPS — [OASIS TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- Core concepts: Discovery endpoint (`/taxii2/`), API Roots (logical groupings of Collections), Collections (repositories of CTI objects, request/response), Objects (wrapped in an envelope); Channels are reserved but unspecified in 2.1 — [OASIS TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- Media type `application/taxii+json;version=2.1`; endpoint paths must end with a trailing slash; key endpoints: `{api-root}/collections/`, `{api-root}/collections/{id}/objects/` (GET, POST), `{api-root}/collections/{id}/manifest/`, `{api-root}/collections/{id}/objects/{object-id}/versions/`, `{api-root}/status/{status-id}/` — [OASIS TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- Filtering and pagination parameters: `added_after` (timestamp), `limit`, `next` (opaque cursor), envelope `more` boolean, `match[type]`, `match[id]`, `match[spec_version]`, `match[version]`; comma-separated values within one match are ORed, separate match fields are ANDed — [OASIS TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)

**MITRE ATT&CK as STIX/TAXII**
- ATT&CK data access methods listed officially: STIX 2.1 at github.com/mitre-attack/attack-stix-data, STIX 2.0 at github.com/mitre/cti, a TAXII 2.1 server (usage docs in attack-workbench-taxii-server), Excel files, ATT&CK Navigator, mitreattack-python, ATT&CK Workbench, and the Zod-schema "ATT&CK Data Model" library — [attack.mitre.org: ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- attack-stix-data: "STIX data representing MITRE ATT&CK", 707 stars; STIX 2.1 JSON collections laid out as `enterprise-attack/enterprise-attack.json` (latest) plus versioned files such as `enterprise-attack-9.0.json`, `mobile-attack/`, `ics-attack/`, with `index.json` / `index.md` collection indexes; STIX 2.0 users are pointed to mitre/cti — [GitHub mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- Public TAXII 2.1 server: base URL `https://attack-taxii.mitre.org`, default API root `/api/v21/` ("always serves STIX content from the latest ATT&CK release"), pinned roots `/api/v21/attack-<x.y>` (e.g. `attack-19.1`), discovery `GET /taxii2/`, required `Accept: application/taxii+json;version=2.1`; collection IDs: Enterprise `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019`, ICS `x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09`, Mobile `x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858`; rate limited to 50 requests per 10 minutes per source IP, with heavier users told to download the JSON bundles — [attack-workbench-taxii-server USAGE.md](https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md)

**Analytic models (foundational papers)**
- Lockheed Martin kill chain paper: "Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains", Eric M. Hutchins, Michael J. Cloppert, Rohan M. Amin, Lockheed Martin Corporation; 14 pages; the PDF metadata shows creation 2010-10-24 — [Lockheed Martin white paper PDF](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf) (text extracted locally from the PDF)
- The paper defines seven phases ending with "7. Actions on Objectives", a Courses of Action Matrix with columns Detect, Deny, Disrupt, Degrade, Deceive, Destroy against each phase (e.g. Reconnaissance: Web analytics / Firewall ACL; Weaponization: NIDS / NIPS; Delivery: Vigilant user / Proxy filter / In-line AV), and three indicator types: Atomic (IP addresses, email addresses, vulnerability IDs), Computed (hash values, regular expressions) and Behavioral (collections of atomic and computed indicators) — [Lockheed Martin white paper PDF](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf) (text extracted locally)
- Journal version cited as *Leading Issues in Information Warfare & Security Research*, vol. 1, 2011 (page ranges differ between listings: 1–14 vs starting at 80) — [connections-qj.org listing](https://connections-qj.org/article/intelligence-driven-computer-network-defense-informed-analysis-adversary-campaigns-and); [BibSonomy entry](https://bibsonomy.org/bibtex/ce281b592eb8dc68cb35e45ff801bd3c); a mirror PDF is also at [securityandtechnology.org](https://securityandtechnology.org/wp-content/uploads/2020/07/lm-white-paper-intel-driven-defense.pdf)
- Diamond Model: "The Diamond Model of Intrusion Analysis", Sergio Caltagirone, Andrew Pendergast, Christopher Betz (cciatr.org addresses, i.e. the Center for Cyber Intelligence Analysis and Threat Research), 61 pages, "Approved for public release; distribution is unlimited"; the abstract defines the event as the atomic element with four core features — adversary, infrastructure, capability, victim — plus meta-features that link events into activity threads and activity groups — [DTIC ADA586960 PDF](https://apps.dtic.mil/sti/pdfs/ADA586960.pdf); [activeresponse.org mirror PDF](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf) (text extracted locally; PDF metadata creation date 10 June 2013)
- Diamond Model meta-features listed in the table of contents: Timestamp, Phase, Result, Direction, Methodology, Resources; extended model adds Social-Political and Technology axes; sections cover Activity Threads, Activity-Attack Graph, and a six-step Activity Group process — [activeresponse.org mirror PDF](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- Pyramid of Pain: David J. Bianco, published 1 March 2013, updated 17 January 2014 to add the Hash Values level; six levels bottom to top: Hash Values, IP Addresses, Domain Names, Network & Host Artifacts, Tools, TTPs; thesis: the higher the level a defender detects and responds at, the more costly the disruption to the adversary — [detect-respond.blogspot.com](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)

**Governance and handling**
- NIST SP 800-150 "Guide to Cyber Threat Information Sharing", Christopher Johnson, Mark Badger, David Waltermire (NIST), Julie Snyder, Clem Skorupka (MITRE), final published October 2016, DOI 10.6028/NIST.SP.800-150; defines cyber threat information as "any information that can help an organization identify, assess, monitor, and respond to cyber threats" and covers establishing sharing goals, identifying sources, scoping, publication/distribution rules, engaging sharing communities and applying threat information — [NIST CSRC SP 800-150](https://csrc.nist.gov/pubs/sp/800/150/final); [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf)
- FIRST Traffic Light Protocol v2.0 is authoritative from August 2022 (v1.0 deprecated then); labels: TLP:RED (individual recipients only), TLP:AMBER (need-to-know within organisation and its clients), TLP:AMBER+STRICT (organisation only), TLP:GREEN (community, not public channels), TLP:CLEAR (no limit, standard copyright); font colours RED #FF2B2B, AMBER #FFC000, GREEN #33FF00, CLEAR #FFFFFF on #000000 — [FIRST TLP](https://www.first.org/tlp/)

**Other formats catalogued by the community**
- The awesome-threat-intelligence "Formats" section lists STIX 2.0, TAXII, CybOX, OpenIOC, MAEC, IODEF (RFC 5070) and VERIS — [GitHub hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)

### Inferences
- For a Python course, the practical standard is STIX 2.1 + TAXII 2.1 only; CybOX and STIX 1.x are legacy (CybOX was folded into STIX 2 as SCOs) and OpenIOC/MAEC/IODEF matter mostly for reading older feeds.
- Because ATT&CK is itself published as STIX 2.1 and served from a conformant TAXII 2.1 server, one `taxii2client` + `stix2` skill set covers both "IOC exchange" and "technique mapping" exercises.
- The Pyramid of Pain explains why automation pipelines should not stop at hash/IP feeds: the ATT&CK/STIX Attack Pattern layer is where durable detections live.

### Gaps
- The Indicator object's required-property table in STIX 2.1 section 4.7 was not read directly from the OASIS HTML (page is ~700k characters; only the first 100k were read); the requirement is cited from the official stix2 library docs instead.
- The OASIS HTML page is internally inconsistent about its own status label ("OASIS Standard incorporating Draft 01 of Errata 01" vs. a citation block saying "Committee Specification Draft 01"); the report writer should cite it as STIX 2.1 Errata 01 (2025).
- No official page was found confirming the retirement date of the legacy TAXII 2.0 server `cti-taxii.mitre.org`; only community pages still reference it. Treat `attack-taxii.mitre.org` as current.
- The journal page range of the Hutchins et al. paper is inconsistent across indexes (1–14 vs 80–).

## Key Question 2: Which Python libraries are the de facto tools for CTI automation, and who maintains them?

### Takeaway
Core stack: `stix2` and `taxii2-client` (OASIS TC Open Repositories), `mitreattack-python` (MITRE), `pymisp` (MISP project/CIRCL), `pycti` (Filigran/OpenCTI, now in the main opencti monorepo), `OTXv2` (AlienVault OTX), `iocextract` (InQuest) / `ioc-finder` (fhightower) for extraction, and `msticpy` (Microsoft MSTIC) for notebook-driven enrichment. `pyattck` (Swimlane) was archived in March 2026 and should be presented as legacy.

### Cited Findings

**Standards libraries**
- `cti-python-stix2`: "OASIS TC Open Repository: Python APIs for STIX 2", 440 stars, `pip install stix2`, requires Python 3.6+, maintainers Emily Ratliff (IBM), Rich Piazza (MITRE), Alexandre Dulaunoy (CIRCL), Christian Studer (CIRCL); docs at stix2.readthedocs.io — [GitHub oasis-open/cti-python-stix2](https://github.com/oasis-open/cti-python-stix2)
- `cti-taxii-client`: "OASIS TC Open Repository: TAXII 2 Client Library Written in Python", 129 stars, `pip install taxii2-client`, exposes `taxii2client.v21.Server / ApiRoot / Collection`, `collection.get_objects()`, `collection.add_objects(bundle)` and `as_pages(collection.get_objects, per_request=50)` for pagination; docs at taxii2client.readthedocs.io — [GitHub oasis-open/cti-taxii-client](https://github.com/oasis-open/cti-taxii-client)

**ATT&CK libraries**
- `mitreattack-python`: "A python module for working with ATT&CK", 755 stars, `pip install mitreattack-python`, docs at mitreattack-python.readthedocs.io; `MitreAttackData` reads ATT&CK STIX content — [GitHub mitre-attack/mitreattack-python](https://github.com/mitre-attack/mitreattack-python)
- `MitreAttackData(stix_filepath=None, src=None)` accepts a file path or a `stix2.MemoryStore`; methods include `get_techniques(include_subtechniques=True, remove_revoked_deprecated=False)`, `get_techniques_by_tactic(tactic_shortname, domain, ...)` with domain in `enterprise-attack|mobile-attack|ics-attack`, `get_object_by_attack_id(attack_id, stix_type)` (type required because technique IDs are not globally unique), `get_attack_id(stix_id)`, `get_groups_using_technique(technique_stix_id)`, `remove_revoked_deprecated(objects)`; the docs link the STIX 2.0 Enterprise file at `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` — [mitreattack-python docs: MitreAttackData](https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html)
- `pyattck` (Swimlane): "A Python package to interact with the Mitre ATT&CK Framework", 480 stars, `pip install pyattck`, current version 7.1.1, initial author Josh Rickard (MSAdministrator); repository archived by the owner on 17 March 2026 and now read-only — [GitHub swimlane/pyattck](https://github.com/swimlane/pyattck)

**Platform clients**
- `PyMISP`: "Python library using the MISP Rest API", 494 stars, `pip3 install pymisp` (extras: `pymisp[virustotal,email]`, also fileobjects, openioc, docs, pdfexport, url, brotli), Python 3.10+, docs at pymisp.readthedocs.io; example scripts live in `examples/` using a `keys.py` with URL and API key from the MISP "Automation" page — [GitHub MISP/PyMISP](https://github.com/MISP/PyMISP); [PyMISP README on readthedocs](https://pymisp.readthedocs.io/en/latest/README.html)
- PyMISP's `examples/last.py` constructs `PyMISP(misp_url, misp_key, misp_verifycert, cert=misp_client_cert)` and calls `misp.search(publish_timestamp=..., limit=..., page=..., pythonify=True)`, writing one JSON line per event — [PyMISP examples/last.py](https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py)
- `pycti` (OpenCTI Python client): the standalone repo `OpenCTI-Platform/client-python` (145 stars) was archived 5 Dec 2025 and is read-only; code now lives in the `client-python` directory of the OpenCTI monorepo; "OpenCTI is a product designed and developed by the company Filigran" — [GitHub OpenCTI-Platform/client-python](https://github.com/OpenCTI-Platform/client-python)
- pycti usage: `pip3 install pycti`; `OpenCTIApiClient("https://myopencti.server", "mysupersecrettoken")`; `opencti_api_client.indicator.create(name=..., pattern_type="stix", pattern="[domain-name:value = 'www.5z8.info']", x_opencti_main_observable_type=..., valid_from=..., update=True, markingDefinitions=[...])`; examples at github.com/OpenCTI-Platform/opencti/tree/master/client-python/examples — [OpenCTI docs: Python library](https://docs.opencti.io/latest/development/python/)
- `OTX-Python-SDK`: "The Python SDK for AlienVault OTX", 402 stars, `pip install OTXv2`, `otx = OTXv2("API_KEY")`, `otx.get_pulse_indicators("pulse_id")`, `otx.get_indicator_details_full(IndicatorTypes.DOMAIN, "google.com")`, `otx.create_pulse(...)`; README examples still use Python 2 `print` syntax — [GitHub AlienVault-OTX/OTX-Python-SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK); [README raw](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/README.md)
- OTXv2 class methods (from source): `getall`, `getall_iter`, `getsince`, `getsince_iter`, `getevents_since`, `search_pulses`, `get_all_indicators`, `get_pulse_details`, `get_pulse_indicators`, `get_indicator_details_by_section`, `get_indicator_details_full`, `create_pulse`, `get_my_pulses`, `submit_file`, `submit_url`; default server `https://otx.alienvault.com` with `API_V1_ROOT = /api/v1`; HTTPS session uses urllib3 `Retry` (5 retries, backoff 1) on 429/500/502/503/504; 403 maps to `InvalidAPIKey` — [OTXv2.py source](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py)

**Extraction and enrichment libraries**
- `iocextract`: "Defanged Indicator of Compromise (IOC) Extractor", 581 stars, `pip install iocextract`, developed by InQuest; extracts URLs, IPs, MD5/SHA hashes, emails, YARA rules, phone numbers; `extract_urls(content, refang=True)` returns an iterator and refangs `hxxp://example[.]com`; only URLs, emails and IPv4s can be refanged; handles `[.]`, `(.)`, `\.`, `[/]`, `[:]`, `hxxp`, `_dot_`, `_at_`, hex/URL/base64-encoded URLs; CLI `iocextract --input FILE --output FILE --extract-urls --refang` with `--extract-emails/--extract-ips/--extract-ipv4s/--extract-ipv6s/--extract-yara-rules/--extract-hashes/--custom-regex` — [GitHub InQuest/iocextract](https://github.com/InQuest/iocextract)
- `ioc-finder`: grammar-based (not regex) IOC extractor, 184 stars, maintained by fhightower, LGPL-3.0/GPL-3.0; `pip install ioc-finder`; `from ioc_finder import find_iocs; iocs = find_iocs(text); iocs['domains']; iocs['urls']`; options to parse domains from URLs/emails/XMPP, IPs from CIDR, URLs without scheme, and `included_ioc_types` to restrict types (e.g. `ipv4s`, `urls_complete`, `imphashes`, `authentihashes`) — [GitHub fhightower/ioc-finder](https://github.com/fhightower/ioc-finder); [ioc-finder docs](https://hightower.space/ioc-finder/)
- `msticpy`: "Microsoft Threat Intelligence Security Tools", "a library for InfoSec investigation and hunting in Jupyter Notebooks", 2.0k stars, Python 3.10+, `pip install msticpy`; README notes PyPI publishing is temporarily halted and recommends `python -m pip install --upgrade --force-reinstall git+https://github.com/microsoft/msticpy.git`; maintained by MSTIC (Microsoft Threat Intelligence Center) — [GitHub microsoft/msticpy](https://github.com/microsoft/msticpy); [msticpy docs](https://msticpy.readthedocs.io/en/latest/)
- msticpy TI providers: VirusTotal, AlienVault OTX, RiskIQ, IBM XForce, MS Sentinel TI (AzSTI), GreyNoise, CrowdSec, AbuseIPDB, ScanMalware, IntSights; pseudo-providers TOR exit nodes, Open Page Rank, IP Quality Score, BinaryEdge; configured under `TIProviders:` in `msticpyconfig.yaml` (`Args: AuthKey`, `Primary`, `Provider`), with advice to use environment variables or Azure Key Vault rather than plaintext keys; usage `ti_lookup = mp.TILookup(); ti_lookup.lookup_ioc("162.244.80.235")` and `ti_lookup.lookup_iocs(data=df)` — [msticpy docs: TI Providers](https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html)
- `ThreatIngestor` (InQuest): "An extendable tool to extract and aggregate IOCs from threat feeds", 932 stars, `pip install threatingestor` (`[all]` extras), YAML `config.yml` with source plugins (RSS, Twitter, GitHub repo search, sitemap, git repos, gists, images, SQS, web pages) and operator plugins (CSV, MISP, ThreatKB, SQS, MySQL, SQLite, Twitter); Python 3.6+; docs at inquest.readthedocs.io/projects/threatingestor — [GitHub InQuest/ThreatIngestor](https://github.com/InQuest/ThreatIngestor)
- `iocingestor` is a PyPI fork of ThreatIngestor focused on MISP integration that swaps iocextract for ioc-finder and drops YARA extraction — [PyPI iocingestor](https://pypi.org/project/iocingestor/)

**Platforms (not libraries, but the targets of automation)**
- IntelOwl: "manage your Threat Intelligence at scale", 4.8k stars, AGPL-3.0, "Enrichment of Threat Intel for files as well as observables (IP, Domain, URL, hash, etc)", official clients `pyintelowl` and `go-intelowl`, demo at intelowl.honeynet.org, docs at intelowlproject.github.io/docs — [GitHub intelowlproject/IntelOwl](https://github.com/intelowlproject/IntelOwl)
- Yeti: "Your Everyday Threat Intelligence", 2.0k stars, Apache-2.0, "Forensics Intelligence platform and pipeline for DFIR teams"; stores observables, TTPs, campaigns, YARA, Sigma and DFIQ; web API for automated queries and enrichment; docs at yeti-platform.io/docs — [GitHub yeti-platform/yeti](https://github.com/yeti-platform/yeti)
- awesome-threat-intelligence lists MISP, OpenCTI, Yeti and IntelOwl under "Frameworks & Platforms" and iocextract, IOC Finder, ThreatIngestor, msticpy under "Tools" — [GitHub hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)

### Inferences
- The maintainers overlap heavily (CIRCL people on both stix2 and MISP; MITRE on stix2 and mitreattack-python), which is why STIX 2.1 interoperates cleanly between MISP, OpenCTI and ATT&CK tooling.
- Teach `mitreattack-python` rather than `pyattck` for ATT&CK (pyattck archived March 2026); teach `pycti` from the OpenCTI monorepo (standalone repo archived Dec 2025).
- `iocextract` (regex, refang-capable, CLI) is the better fit for "paste a report, get IOCs"; `ioc-finder` is better when you also want CVEs/ATT&CK IDs parsed from prose, though the dict keys for those types were not confirmed this session.
- `msticpy` effectively bundles the enrichment pattern (multi-provider fan-out + DataFrame output) that a course would otherwise build by hand with `requests`.

### Gaps
- No release version numbers were visible on the GitHub pages for stix2, taxii2-client, msticpy or PyMISP (Releases sections empty in the fetched HTML); use PyPI for current versions.
- PyMISP's full `search()` signature (controller, type_attribute, to_ids, tags, etc.) could not be confirmed from the readthedocs index page; parameters cited above are only those used in `examples/last.py`.
- The `iocextract.extract_iocs()` aggregate function was not visible in the fetched README; only `extract_urls` and the CLI flags are confirmed.
- `ioc-finder`'s full output-key list (cves, attack_techniques, etc.) was not confirmed from the docs landing page.

## Key Question 3: Which free feeds and enrichment APIs are commonly used, with URLs and usage limits?

### Takeaway
The most-used free sources are abuse.ch (URLhaus, Feodo Tracker, ThreatFox, SSLBL), the MISP default feed catalogue (108 feeds from 52 providers), AlienVault OTX pulses, and enrichment APIs AbuseIPDB (1,000 checks/day standard) and VirusTotal public API (4/min, 500/day, non-commercial). Note that abuse.ch has moved most bulk downloads behind a free Auth-Key, and the old `urlhaus.abuse.ch/downloads/csv_recent/` endpoint now returns HTTP 410 Gone.

### Cited Findings

**abuse.ch**
- URLhaus API: all API interactions require an `Auth-Key` HTTP header; keys are free via the abuse.ch Authentication Portal at https://auth.abuse.ch/; endpoints `GET https://urlhaus-api.abuse.ch/v1/urls/recent/` (optionally `/limit/N/`, max 1000, last 3 days), `GET /v1/payloads/recent/`, `POST /v1/url/`, `POST /v1/host/`, `POST /v1/payload/` (md5_hash or sha256_hash), `POST /v1/tag/`, `POST /v1/signature/`, `GET /v1/download/<sha256>`; batch dumps at https://datalake.abuse.ch/urlhaus/hourly/ and /daily/ (00:00 UTC); JSON fields include `query_status`, `url_status`, `date_added`, `tags` — [URLhaus API docs](https://urlhaus-api.abuse.ch/)
- URLhaus feed page: database dumps (full = active + last 90 days; active-only; last-30-days) in CSV or JSON, RPZ zone and IDS ruleset regenerated every 5 minutes ("Please do not fetch it more often than every 5 minutes"); ClamAV signatures every minute; MISP feed daily; Auth-Key required and embedded in the download URL, e.g. `https://urlhaus-api.abuse.ch/v2/files/exports/YOUR-AUTH-KEY-HERE/recent.csv`; API "available free of charge under the fair use principles", commercial use may need the paid commercial API — [URLhaus API/feeds page](https://urlhaus.abuse.ch/api/)
- The legacy unauthenticated URL `https://urlhaus.abuse.ch/downloads/csv_recent/` returned HTTP 410 Gone on 2026-11-01 — [URLhaus csv_recent](https://urlhaus.abuse.ch/downloads/csv_recent/)
- Feodo Tracker blocklist: recommended list `/downloads/ipblocklist_recommended.txt|.json` (active C2s), standard 30-day list `/downloads/ipblocklist.csv|.json|.txt`, aggressive list `/downloads/ipblocklist_aggressive.csv|.txt` (warned: "will cause false positives"), Suricata/Snort rules `/downloads/feodotracker.rules`; regenerated every 5 minutes, recommended fetch interval 5–15 minutes; families Dridex, Heodo (Emotet), TrickBot, QakBot, BazarLoader; page states the datasets are "currently empty"; governed by https://abuse.ch/terms-of-use/; no auth requirement stated on this page — [Feodo Tracker blocklist](https://feodotracker.abuse.ch/blocklist/)
- MISP default feed catalogue lists abuse.ch feeds with full URLs: SSL IPBL CSV `https://sslbl.abuse.ch/blacklist/sslblacklist.csv`, Feodo IP Blocklist CSV `https://feodotracker.abuse.ch/downloads/ipblocklist.csv`, URLhaus MISP feed `https://urlhaus.abuse.ch/downloads/misp/`, ThreatFox MISP feed `https://threatfox.abuse.ch/downloads/misp/` — [MISP feeds](https://www.misp-project.org/feeds/)

**MISP feeds**
- The MISP default feed list contains 108 feeds from 52 providers (18 MISP-format, 47 CSV, 43 free-text; counts overlap); examples: CIRCL OSINT Feed (MISP, `https://www.circl.lu/doc/misp/feed-osint`), Botvrij.eu (MISP, `https://www.botvrij.eu/data/feed-osint`); the catalogue includes disabled entries and does not check availability; some providers require licences, authentication or impose rate limits; the machine-readable list is `https://github.com/MISP/MISP/blob/2.5/app/files/feed-metadata/defaults.json` — [MISP feeds](https://www.misp-project.org/feeds/)

**AlienVault OTX**
- OTX DirectConnect SDK talks to `https://otx.alienvault.com/api/v1`; pulses are retrieved with `getall()/getall_iter()`, `getsince(timestamp)/getsince_iter()`, indicators with `get_pulse_indicators(pulse_id)`; endpoint details at https://otx.alienvault.com/api — [OTXv2.py source](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py); [GitHub AlienVault-OTX/OTX-Python-SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK)
- No official OTX rate limit figure was found; a Graylog community thread reports a user who "couldn't find any details about rate limits for the API on OTX" — [Graylog community](https://community.graylog.org/t/no-longer-receiving-results-after-using-my-otx-api-key/12267)

**AbuseIPDB**
- CHECK endpoint `GET https://api.abuseipdb.com/api/v2/check` with `ipAddress` (required), `maxAgeInDays` (default 30, range 1–365), `verbose` flag; headers `Key: <api key>` and `Accept: application/json`; response `data` fields `abuseConfidenceScore` (recommended over `isWhitelisted` for decisions), `totalReports`, `isp`, `countryCode`, `usageType`, `lastReportedAt`; daily limits for `check`: Standard 1,000; Webmaster 3,000; Supporter 5,000; Basic 10,000; Premium 50,000; exceeding returns HTTP 429; the docs' Python sample is Python-2 syntax — [AbuseIPDB API docs](https://docs.abuseipdb.com/)

**VirusTotal**
- Public API: 4 requests/minute, 500 requests/day; not for commercial products/services or business workflows that do not contribute new files; multiple accounts to evade limits prohibited; Premium API has no per-request rate/daily allowance — [VirusTotal: Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)
- Quotas are per minute, daily and monthly; daily quotas reset at 00:00 UTC; exceeding returns HTTP 429 in API v3; uploading a never-seen file does not consume quota — [VirusTotal: quota consumption](https://docs.virustotal.com/docs/quota-consumption); [VirusTotal: consumption quotas handled](https://docs.virustotal.com/docs/consumption-quotas-handled)

**Aggregators / enrichment front-ends**
- msticpy TILookup fans out to VirusTotal, OTX, RiskIQ, IBM XForce, Sentinel TI, GreyNoise, CrowdSec, AbuseIPDB, ScanMalware, IntSights and pseudo-providers (TOR exit nodes, Open Page Rank, IP Quality Score, BinaryEdge) from one config file — [msticpy docs: TI Providers](https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html)
- IntelOwl exposes many analyzers for observables and files behind one API with a `pyintelowl` client — [GitHub intelowlproject/IntelOwl](https://github.com/intelowlproject/IntelOwl)
- MITRE's hosted ATT&CK TAXII server is limited to 50 requests per 10 minutes per source IP — [attack-workbench-taxii-server USAGE.md](https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md)

### Inferences
- Lab exercises that assume anonymous URLhaus CSV downloads will break; the course should have students register a free abuse.ch Auth-Key, or use Feodo Tracker / MISP-format feeds that are still unauthenticated, or the datalake hourly dumps.
- Free-tier quotas (VT 4/min, AbuseIPDB 1,000/day) make caching, de-duplication and batching mandatory design points in any enrichment script, not optimisations.
- Fetch cadence guidance from abuse.ch (every 5–15 minutes) and MITRE (50 req/10 min) is a natural place to teach `added_after`-style incremental polling instead of full re-downloads.

### Gaps
- URLhaus CSV column names could not be verified (download docs are login-gated and the legacy CSV endpoint is gone); snippets below treat the header as something to inspect at runtime.
- Feodo Tracker CSV column names were not fetched (the blocklist page lists URLs only).
- No authoritative OTX API rate limit was found.
- VirusTotal public monthly quota and the `x-apikey` header name were not confirmed from the fetched page (header is in the "Getting started" page, not fetched).
- The ThreatFox API (threatfox-api.abuse.ch) was not fetched this session; it is referenced only via the MISP feed catalogue.

## Key Question 4: What is the accepted CTI lifecycle, and how do automation steps map to it?

### Takeaway
The accepted model is the six-phase intelligence cycle — Direction (planning/requirements), Collection, Processing, Analysis, Dissemination, Feedback — taught by SANS FOR578 as the "Traditional Intelligence Cycle" and popularised by Recorded Future; Python automation lands mostly in Collection (feed/TAXII/OTX polling), Processing (IOC extraction, de-duplication, STIX normalisation, enrichment) and Dissemination (pushing to MISP/OpenCTI/SIEM with TLP markings), with the Kill Chain, Diamond Model and ATT&CK supplying the analytic vocabulary.

### Cited Findings
- Recorded Future's six phases: Direction (stakeholders set goals: assets to protect, impact of loss, intelligence needed, priorities), Collection (internal logs, threat feeds, interviews, open and closed sources such as dark-web forums), Processing (convert data into usable format "by people or machines, such as extracting indicators for security tools"), Analysis (turn processed information into decision-supporting intelligence), Dissemination (deliver to teams in their format/timing/channel), Feedback (consumer input adjusts earlier phases); post originally published 15 January 2020, last updated 5 February 2024 (page also shows a republish date of 9 October 2026) — [Recorded Future: 6 Phases of the Threat Intelligence Lifecycle](https://www.recordedfuture.com/blog/threat-intelligence-lifecycle-phases)
- Some lifecycle models have five phases because they merge dissemination and feedback — [CSO Online](https://www.csoonline.com/article/575001/dissecting-threat-intelligence-lifecycle-problems.html/amp/)
- SANS FOR578 "Cyber Threat Intelligence" (GIAC GCTI), authored by Rebekah Brown and Robert M. Lee, 6 days / 36 hours, 20 labs; outline: (1) CTI and Requirements including the "Traditional Intelligence Cycle" and threat modelling; (2) Intrusion Analysis covering the Kill Chain, the Diamond Model and MITRE ATT&CK; (3) Collection Sources (domains, malware, external datasets, TLS certificates); (4) Analysis including storing threat data in MISP, cognitive biases, ACH; (5) Dissemination and Attribution covering YARA, STIX/TAXII and attribution models; (6) Capstone — [SANS FOR578](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/)
- NIST SP 800-150 frames sharing around establishing goals, identifying sources, scoping what to share and with whom, controlling publication and distribution, engaging communities and applying threat information to the organisation's security practices — [NIST CSRC SP 800-150](https://csrc.nist.gov/pubs/sp/800/150/final)
- TLP 2.0 provides the dissemination labels (RED/AMBER/AMBER+STRICT/GREEN/CLEAR) that govern who may receive automated outputs — [FIRST TLP](https://www.first.org/tlp/); OpenCTI's client expresses them as `markingDefinitions` (e.g. `TLP_GREEN_CTI["id"]`) when creating indicators — [OpenCTI docs: Python library](https://docs.opencti.io/latest/development/python/)
- Kill Chain phases and the Courses of Action matrix (Detect/Deny/Disrupt/Degrade/Deceive/Destroy) map indicators to defensive actions per phase, and classify indicators as atomic, computed or behavioral — [Lockheed Martin white paper PDF](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf)
- The Diamond Model's four core features (adversary, infrastructure, capability, victim) and meta-features (timestamp, phase, result, direction, methodology, resources) link events into activity threads and activity groups — [DTIC ADA586960 PDF](https://apps.dtic.mil/sti/pdfs/ADA586960.pdf)
- The Pyramid of Pain ranks indicator types by adversary cost (hashes lowest, TTPs highest) — [detect-respond.blogspot.com](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- "Intelligence-Driven Incident Response", 2nd edition, Rebekah Brown and Scott J. Roberts, O'Reilly, June 2023, 343 pages (O'Reilly listing), ISBN 9781098120672 on the O'Reilly platform page; print ISBN 9781098120689 appears on retailer/library pages (325 pages, 23 June 2023); e-book ISBN 9781098120641 — [O'Reilly listing](https://www.oreilly.com/library/view/intelligence-driven-incident-response/9781098120672/); [Heidelberg library catalogue](https://katalog.ub.uni-heidelberg.de/titel/69152504); [wristers.nl](https://www.wristers.nl/boek/9781098120689)
- "Practical Threat Intelligence and Data-Driven Threat Hunting", Valentina Costa-Gazcón, Packt, February 2021; print ISBN-13 9781838556372 (ISBN-10 1838556370), e-book ISBN-13 9781838551636 — [O'Reilly listing](https://oreilly.com/library/view/practical-threat-intelligence/9781838556372); [Packt](https://packtpub.com/product/practical-threat-intelligence-and-data-driven-threat-hunting/9781838556372); [Lehmanns e-book listing](https://www.lehmanns.de/shop/mathematik-informatik/55989559-9781838551636-practical-threat-intelligence-and-data-driven-threat-hunting)

**Mapping of automation steps to lifecycle phases (supported by the documented tool capabilities above)**
- Collection: TAXII 2.1 `added_after` polling and `as_pages` pagination — [OASIS TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html); [GitHub oasis-open/cti-taxii-client](https://github.com/oasis-open/cti-taxii-client); OTX `getsince()` — [OTXv2.py source](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py); ThreatIngestor source plugins for RSS/Twitter/GitHub — [GitHub InQuest/ThreatIngestor](https://github.com/InQuest/ThreatIngestor); MISP `search(publish_timestamp=...)` — [PyMISP examples/last.py](https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py)
- Processing: refang/extract with iocextract — [GitHub InQuest/iocextract](https://github.com/InQuest/iocextract); normalise to STIX 2.1 with stix2 — [stix2 docs](https://stix2.readthedocs.io/en/latest/guide/creating.html); MISP feeds in freetext format rely on MISP detecting indicator types — [MISP feeds](https://www.misp-project.org/feeds/)
- Analysis/enrichment: msticpy TILookup multi-provider lookups into DataFrames — [msticpy docs: TI Providers](https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html); AbuseIPDB `abuseConfidenceScore` — [AbuseIPDB API docs](https://docs.abuseipdb.com/); ATT&CK technique/group lookups — [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html)
- Dissemination: ThreatIngestor operators to MISP/CSV/SQS — [GitHub InQuest/ThreatIngestor](https://github.com/InQuest/ThreatIngestor); pycti `indicator.create` with TLP markings — [OpenCTI docs](https://docs.opencti.io/latest/development/python/); TAXII `collection.add_objects(bundle)` — [GitHub oasis-open/cti-taxii-client](https://github.com/oasis-open/cti-taxii-client)

### Inferences
- The Pyramid of Pain and the kill-chain indicator taxonomy together justify a two-tier pipeline: cheap atomic/computed IOC feeds for blocking, and ATT&CK-mapped behavioral intelligence for detection engineering.
- "Processing" is the phase where almost all Python course content lives; "Direction" and "Feedback" are human phases that scripts can only support (e.g. by logging false-positive rates from AbuseIPDB scores back into requirements).
- Brown/Roberts (FOR578 authors) and the Recorded Future handbook describe the same six-phase cycle, so the course can cite either without conflict; the five-phase variant is a merge, not a competing model.

### Gaps
- The Recorded Future page carries three dates (15 Jan 2020 original, 5 Feb 2024 updated, 9 Oct 2026 republished); the report should cite "2020, updated 2024".
- Chapter lists for both books were not retrievable (O'Reilly and Packt pages returned HTTP 403); the F3EAD model is known to be central to Brown/Roberts but was not confirmed from a fetched page this session.
- The SANS FOR578 page does not mention the Pyramid of Pain, so attributing it to FOR578 would be unsupported.

## Key Question 5: Which community writings, repositories and talks are most cited on CTI automation?

### Takeaway
The single most-cited community index is hslatman/awesome-threat-intelligence (10.8k stars, Apache-2.0, since 2015). On the tooling side, IntelOwl (4.8k), msticpy (2.0k), Yeti (2.0k), ThreatIngestor (932), mitreattack-python (755), attack-stix-data (707), iocextract (581), PyMISP (494), pyattck (480, archived), stix2 (440), OTX SDK (402), ioc-finder (184) and taxii2-client (129) are the reference repositories. For SANS, the CTI Summit is the main venue (2024 talks "OSINTer" and "Intellimation" on automation; 2025 Summit 27 Jan–3 Feb) but no single widely-cited "Python CTI automation" talk was found.

### Cited Findings

**GitHub repositories with star counts (2026-11-01)**
- hslatman/awesome-threat-intelligence: 10.8k stars, Apache-2.0, sections Sources / Formats / Frameworks & Platforms / Tools / Research, Standards & Books — [GitHub](https://github.com/hslatman/awesome-threat-intelligence); created 21 Dec 2015 by Herman Slatman, with dependency-bot commits in late 2025 showing continued maintenance — [awesome.ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2Fhslatman%2Fawesome-threat-intelligence)
- intelowlproject/IntelOwl: 4.8k stars, 705 forks — [GitHub](https://github.com/intelowlproject/IntelOwl) (a third-party tracker showed an older 4.6k figure — [gittrend.io](https://gittrend.io/repo/intelowlproject/IntelOwl))
- microsoft/msticpy: 2.0k — [GitHub](https://github.com/microsoft/msticpy)
- yeti-platform/yeti: 2.0k, 328 forks, 3,571 commits — [GitHub](https://github.com/yeti-platform/yeti)
- InQuest/ThreatIngestor: 932 — [GitHub](https://github.com/InQuest/ThreatIngestor)
- mitre-attack/mitreattack-python: 755, 176 forks — [GitHub](https://github.com/mitre-attack/mitreattack-python)
- mitre-attack/attack-stix-data: 707 — [GitHub](https://github.com/mitre-attack/attack-stix-data)
- InQuest/iocextract: 581, 93 forks — [GitHub](https://github.com/InQuest/iocextract)
- MISP/PyMISP: 494 — [GitHub](https://github.com/MISP/PyMISP)
- swimlane/pyattck: 480, archived 17 Mar 2026 — [GitHub](https://github.com/swimlane/pyattck)
- oasis-open/cti-python-stix2: 440 — [GitHub](https://github.com/oasis-open/cti-python-stix2)
- AlienVault-OTX/OTX-Python-SDK: 402, 178 commits — [GitHub](https://github.com/AlienVault-OTX/OTX-Python-SDK)
- fhightower/ioc-finder: 184, 45 forks — [GitHub](https://github.com/fhightower/ioc-finder)
- OpenCTI-Platform/client-python: 145, archived 5 Dec 2025 (code moved into the opencti monorepo) — [GitHub](https://github.com/OpenCTI-Platform/client-python)
- oasis-open/cti-taxii-client: 129 — [GitHub](https://github.com/oasis-open/cti-taxii-client)

**SANS material**
- SANS white paper "Automated Network Defense through Threat Intelligence and Knowledge Management", Christopher O'Brien, January 2016: argues that automation and structuring of threat intelligence "need not be prescriptive nor expensive", using bulk feeds and open-source reporting structured in STIX and tested against Bro and Snort — [SANS white paper 36572](https://www.sans.org/white-papers/36572); also indexed as a [GIAC research paper](https://www.giac.org/research-papers/36572)
- SANS CTI Summit 2024 visual summary lists the talks "OSINTer - Automating the CTI heavylifting the open source way!" and "Intellimation: Guidance for Integrating Automation in Your Cyber Threat Intelligence Program" — [SANS blog: visual summary CTI Summit 2024](https://sans.org/blog/a-visual-summary-of-sans-cti-summit-2024)
- SANS CTI Summit 2025 ran 27 Jan–3 Feb 2025 in Alexandria, VA and virtually; keynote "The Anticipatory Approach: Actionable (not Reactionable) Cyber Threat Intelligence"; the co-chairs' preview notes cognitive biases as a recurring theme and pushes AI content to the separate AI Summit — [SANS blog: visual summary CTI Summit 2025](https://www.sans.org/blog/a-visual-summary-of-sans-cti-summit-2025); [SANS Threat Analysis Rundown CTI Summit preview](https://www.sans.org/blog/sans-threat-analysis-rundown-in-review-sans-cti-summit-preview); [GovEvents listing](https://govevents.com/event/9358)
- SANS webcast "Agentic CTI Automation For Fun and Profit" by Rebekah Brown covers automating exposure analysis — [SANS webcast](https://www.sans.org/webcasts/agentic-cti-automation-for-fun-and-profit)
- The SANS 2025 CTI Survey webcast lists "how automation and engineering are supporting cyber threat intelligence operations" as a topic — [GovEvents: SANS 2025 CTI Survey webcast](https://govevents.com/pub/83651/cc54a)
- A 2026 CTI Summit Solutions Track session, "CTI in the AI Arms Race: Building Resilient, Adaptive Intelligence Platforms for 2026", covers LLM-assisted pipelines and integrating TI into IR automation — [SANS webcast](https://www.sans.org/webcasts/cti-ai-arms-race-building-resilient-adaptive-intelligence-platforms-2026)
- The Sqrrl "A Framework for Cyber Threat Hunting Part 1: The Pyramid of Pain" PDF is a widely shared secondary write-up of Bianco's model — [threathunting.net PDF](https://www.threathunting.net/files/A%20Framework%20for%20Cyber%20Threat%20Hunting%20Part%201_%20The%20Pyramid%20of%20Pain%20_%20Sqrrl.pdf); Bianco's own slide deck "The Pyramid of Pain: Intel-Driven Detection & Response to Increase Your Adversary's Cost of Operations" is on Speaker Deck — [Speaker Deck](https://speakerdeck.com/davidjbianco/the-pyramid-of-pain-intel-driven-detection-and-response-to-increase-your-adversarys-cost-of-operations)

**Other community writings**
- PyCon US 2022 talk "Python for Threat Intelligence" — [PyCon archive](https://pycon-archive.python.org/2022/schedule/presentation/43/index.html)
- Recorded Future "Intelligence Handbook, Fourth Edition" (free e-book) covers the lifecycle — [Recorded Future PDF](https://go.recordedfuture.com/hubfs/ebooks/intelligence-handbook-fourth-edition.pdf?hsLang=en)
- Vendor/SOAR blogs on enrichment automation exist (Torq "The Best Threat Intelligence Tools & How to Automate Alert Enrichment", Tines "Streamlining threat intelligence with Pulsedive and Tines") but are vendor-authored — [Torq blog](https://torq.io/blog/threat-intelligence-tools/); [Tines blog](https://www.tines.com/blog/streamlining-threat-intelligence-with-pulsedive-and-tines)

### Inferences
- Star counts show the community's weight is on platforms (IntelOwl, Yeti) and notebook tooling (msticpy) rather than on the standards libraries themselves; the standards libraries are small but authoritative because they are OASIS/MITRE-maintained.
- The scarcity of a canonical "Python IOC enrichment" blog post means the course's own worked examples (below) will likely be the students' primary reference; cite the API docs directly rather than blogs.

### Gaps
- No neutral, widely-cited blog post walking through a VirusTotal + AbuseIPDB + OTX Python enrichment script was found; search results were dominated by vendor blogs and third-party "agent skill" mirrors of uncertain provenance, which are not cited here.
- Full SANS CTI Summit 2025 session list and speaker names for automation talks were not retrieved (only the agenda PDFs' existence: https://www.sans.org/event-downloads/40892/agenda.pdf and /45002/agenda.pdf).
- SANS Reading Room has no recent paper specifically on Python-based CTI automation that surfaced in search; the 2016 O'Brien paper is the closest.
- Stars for awesome-threat-intelligence differ between an aggregator (10,483) and GitHub today (10.8k); GitHub is authoritative.

## Key Question 6 (Layer c): Which concrete, runnable Python snippets illustrate each automation step?

### Takeaway
Nine snippets below cover extraction (iocextract, ioc-finder), STIX 2.1 authoring (stix2), TAXII 2.1 polling of the public ATT&CK server (taxii2-client), MISP search (PyMISP), OTX pulse pull (OTXv2), AbuseIPDB enrichment + ATT&CK mapping (requests + mitreattack-python), abuse.ch feed ingestion with pandas de-duplication, OpenCTI indicator creation (pycti) and multi-provider lookup (msticpy). Each is attributed; where I combined documented calls into a complete script it is marked "illustrative".

### Cited Findings

**Snippet 1 — Extract and refang IOCs from a report with iocextract**
Source: core call and defang handling from the iocextract README — [GitHub InQuest/iocextract](https://github.com/InQuest/iocextract). Combining the four extractor functions into one script is illustrative; `extract_urls(..., refang=True)` is verbatim from the README, the other three function names mirror the documented CLI flags `--extract-ips`, `--extract-hashes`, `--extract-emails`.
```python
# pip install iocextract
import iocextract

report = """
Phishing wave 2026-10: hxxp://login-update[.]example[.]com/portal
C2 observed at 185.220.101[.]4 and 45(.)155(.)205(.)233
Dropper md5 d41d8cd98f00b204e9800998ecf8427e sent from billing[@]evil-corp[.]biz
"""

iocs = {
    "urls":   sorted(set(iocextract.extract_urls(report, refang=True))),
    "ips":    sorted(set(iocextract.extract_ips(report, refang=True))),
    "hashes": sorted(set(iocextract.extract_hashes(report))),
    "emails": sorted(set(iocextract.extract_emails(report, refang=True))),
}
for kind, values in iocs.items():
    print(f"{kind:7s} ({len(values)}):")
    for v in values:
        print("   ", v)
```

**Snippet 2 — Grammar-based extraction with ioc-finder**
Source: `find_iocs` usage from the ioc-finder docs — [ioc-finder docs](https://hightower.space/ioc-finder/). Printing all keys is illustrative; only `domains` and `urls` keys are confirmed in the docs page.
```python
# pip install ioc-finder
from ioc_finder import find_iocs

text = ("Actor used T1566.001 to deliver a loader from "
        "https://cdn.bad-example.net/a.exe (sha256 "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855). "
        "Exploited CVE-2024-3400 on 203.0.113.0/24.")

iocs = find_iocs(text)
for key, values in iocs.items():
    if values:                      # skip empty categories
        print(f"{key}: {values}")
# Restrict parsing to a few types to reduce noise:
subset = find_iocs(text, included_ioc_types=["urls", "ipv4s"])
print(subset)
```

**Snippet 3 — Create a STIX 2.1 Indicator, Malware, Relationship and Bundle**
Source: verbatim pattern from the stix2 "Creating STIX Content" guide — [stix2 docs](https://stix2.readthedocs.io/en/latest/guide/creating.html); `valid_from`, `indicator_types` and the file write are added (illustrative; `indicator_types` appears in the GitHub README example — [GitHub oasis-open/cti-python-stix2](https://github.com/oasis-open/cti-python-stix2)).
```python
# pip install stix2
from datetime import datetime, timezone
from stix2 import Indicator, Malware, Relationship, Bundle

indicator = Indicator(
    name="File hash for malware variant",
    indicator_types=["malicious-activity"],
    pattern_type="stix",                       # required
    pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",  # required
    valid_from=datetime.now(timezone.utc),     # required; defaults to now if omitted
)
malware = Malware(name="Poison Ivy", is_family=False)   # is_family is required
relationship = Relationship(relationship_type="indicates",
                            source_ref=indicator.id,
                            target_ref=malware.id)
bundle = Bundle(indicator, malware, relationship)       # type/id/spec_version auto-set

print(bundle.serialize(pretty=True))
with open("bundle.json", "w") as fh:
    fh.write(bundle.serialize(pretty=True))
```

**Snippet 4 — Poll the public MITRE ATT&CK TAXII 2.1 server with taxii2-client**
Source: `Collection` / `as_pages` usage from the taxii2-client README — [GitHub oasis-open/cti-taxii-client](https://github.com/oasis-open/cti-taxii-client); server URL, API root and Enterprise collection ID from MITRE's USAGE.md — [attack-workbench-taxii-server USAGE.md](https://github.com/mitre-attack/attack-workbench-taxii-server/blob/main/docs/USAGE.md). Combination is illustrative. Respect the documented 50 requests / 10 min limit.
```python
# pip install taxii2-client stix2
from taxii2client.v21 import Server, Collection, as_pages

server = Server("https://attack-taxii.mitre.org/taxii2/")
for root in server.api_roots:
    print("API root:", root.url)

ENTERPRISE = ("https://attack-taxii.mitre.org/api/v21/collections/"
              "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019/")
collection = Collection(ENTERPRISE)
print("Collection:", collection.title)

# Pull only attack-pattern objects, 100 per page (match[type] + limit per TAXII 2.1)
techniques = []
for envelope in as_pages(collection.get_objects, per_request=100, type="attack-pattern"):
    techniques.extend(envelope.get("objects", []))
    if len(techniques) >= 300:        # stay well under 50 req / 10 min
        break
print(len(techniques), "attack-pattern objects fetched")
for t in techniques[:5]:
    ext_id = next((r["external_id"] for r in t.get("external_references", [])
                   if r.get("source_name") == "mitre-attack"), "?")
    print(ext_id, "-", t["name"])
```

**Snippet 5 — Search recent MISP events/attributes with PyMISP**
Source: constructor and `search(publish_timestamp=..., limit=..., page=..., pythonify=True)` from PyMISP `examples/last.py` — [PyMISP examples/last.py](https://raw.githubusercontent.com/MISP/PyMISP/main/examples/last.py); API-key location from the README — [PyMISP README](https://pymisp.readthedocs.io/en/latest/README.html). Iterating `event.attributes` and the `controller="attributes"` call are illustrative (not confirmed from a fetched page this session).
```python
# pip3 install pymisp
import os
from pymisp import PyMISP

misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"],
              ssl=True)                      # ssl=False only for lab instances

# Events published in the last 24 hours, as PyMISP objects
events = misp.search(publish_timestamp="24h", limit=20, page=1, pythonify=True)
print(len(events), "events")
for ev in events:
    print(ev.id, ev.info, ev.date)
    for attr in ev.attributes:
        if attr.to_ids:                      # only detection-grade attributes
            print("   ", attr.type, attr.value, attr.category)

# Attribute-level search for a single value (illustrative)
hits = misp.search(controller="attributes", value="185.220.101.4", pythonify=True)
for a in hits:
    print("seen in event", a.event_id, "as", a.type)
```

**Snippet 6 — Pull OTX pulses modified since a timestamp and flatten indicators**
Source: `OTXv2("API_KEY")`, `get_pulse_indicators`, `IndicatorTypes` from the SDK README — [OTX SDK README](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/README.md); `getsince_iter` method name from the SDK source — [OTXv2.py](https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py). Assembly is illustrative; README examples use Python-2 `print`, corrected here.
```python
# pip install OTXv2
import os
from datetime import datetime, timedelta, timezone
from OTXv2 import OTXv2, IndicatorTypes

otx = OTXv2(os.environ["OTX_API_KEY"])      # free key from otx.alienvault.com
since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

rows = []
for pulse in otx.getsince_iter(since, limit=50):
    for ind in pulse.get("indicators", []):
        rows.append({
            "pulse": pulse["name"], "tlp": pulse.get("TLP"),
            "type": ind["type"], "indicator": ind["indicator"],
        })
print(len(rows), "indicators from pulses modified in the last 24h")

# Enrich one domain with OTX's own context
detail = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, "example.com")
general = detail.get("general", {})
print(general.get("pulse_info", {}).get("count"), "pulses reference example.com")
```

**Snippet 7 — Enrich IPs with AbuseIPDB and map a technique to ATT&CK with mitreattack-python**
Source: AbuseIPDB request shape, headers and fields from the official docs — [AbuseIPDB API docs](https://docs.abuseipdb.com/); `MitreAttackData` calls from the official docs — [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/mitre_attack_data/mitre_attack_data.html); STIX 2.1 JSON location — [GitHub mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data). Combination and caching are illustrative. Standard plan: 1,000 checks/day.
```python
# pip install requests mitreattack-python
import os, json, time, functools, requests
from mitreattack.stix20 import MitreAttackData

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Accept": "application/json", "Key": os.environ["ABUSEIPDB_KEY"]}

@functools.lru_cache(maxsize=4096)            # never re-spend quota on the same IP
def check_ip(ip, max_age=90):
    r = requests.get(ABUSE_URL, headers=HEADERS,
                     params={"ipAddress": ip, "maxAgeInDays": max_age}, timeout=15)
    if r.status_code == 429:
        raise RuntimeError("AbuseIPDB daily quota exceeded")
    d = r.json()["data"]
    return {k: d.get(k) for k in ("ipAddress", "abuseConfidenceScore",
                                  "totalReports", "countryCode", "isp", "usageType")}

for ip in ["118.25.6.39", "185.220.101.4"]:
    print(json.dumps(check_ip(ip), indent=1)); time.sleep(1)

# ATT&CK: download https://raw.githubusercontent.com/mitre-attack/attack-stix-data/
#         master/enterprise-attack/enterprise-attack.json first
attack = MitreAttackData("enterprise-attack.json")
t = attack.get_object_by_attack_id("T1071.001", "attack-pattern")   # Web Protocols C2
print(attack.get_attack_id(t.id), t.name)
for entry in attack.get_groups_using_technique(t.id)[:5]:
    print("  used by", entry["object"].name)
```

**Snippet 8 — Ingest an abuse.ch feed with pandas and de-duplicate indicators**
Source: feed URLs and 5-minute regeneration from Feodo Tracker — [Feodo Tracker blocklist](https://feodotracker.abuse.ch/blocklist/) — and the authenticated URLhaus export URL form from the URLhaus feed page — [URLhaus API page](https://urlhaus.abuse.ch/api/). Column handling is illustrative because CSV headers could not be verified this session; the script discovers them at runtime. Do not fetch more often than every 5 minutes.
```python
# pip install pandas requests
import io, os, requests, pandas as pd

def fetch_abusech_csv(url):
    r = requests.get(url, timeout=30); r.raise_for_status()
    # abuse.ch CSVs carry '#' comment lines; the header row is itself commented
    lines = [l.lstrip("# ") for l in r.text.splitlines()
             if l.strip() and not l.startswith("##") and "abuse.ch" not in l]
    return pd.read_csv(io.StringIO("\n".join(lines)))

feodo = fetch_abusech_csv("https://feodotracker.abuse.ch/downloads/ipblocklist.csv")
print("Feodo columns:", list(feodo.columns)); print(len(feodo), "rows")

# URLhaus now requires a free Auth-Key embedded in the export URL
key = os.environ.get("ABUSECH_AUTH_KEY")
if key:
    urlhaus = fetch_abusech_csv(
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv")
    print("URLhaus columns:", list(urlhaus.columns))

# Normalise to one indicator table and de-duplicate
ip_col = next(c for c in feodo.columns if "ip" in c.lower())
ind = pd.DataFrame({"indicator": feodo[ip_col].astype(str).str.strip(),
                    "type": "ipv4-addr", "source": "feodotracker"})
before = len(ind)
ind = ind.drop_duplicates(subset=["indicator", "type"]).reset_index(drop=True)
print(f"{before} -> {len(ind)} after de-duplication")
ind.to_csv("indicators_dedup.csv", index=False)
```

**Snippet 9 — Create a TLP-marked indicator in OpenCTI with pycti**
Source: install, client constructor and `indicator.create(...)` from the OpenCTI developer docs — [OpenCTI docs: Python library](https://docs.opencti.io/latest/development/python/). The marking lookup is illustrative (the docs example uses a pre-fetched `TLP_GREEN_CTI["id"]`).
```python
# pip3 install pycti
import os
from datetime import datetime, timezone
from pycti import OpenCTIApiClient

client = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"])

tlp_green = client.marking_definition.read(
    filters={"mode": "and", "filterGroups": [],
             "filters": [{"key": "definition", "values": ["TLP:GREEN"]}]})

indicator = client.indicator.create(
    name="C2 server of the new campaign",
    description="This is the C2 server of the campaign",
    pattern_type="stix",
    pattern="[domain-name:value = 'www.5z8.info']",
    x_opencti_main_observable_type="Domain-Name",
    valid_from=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    update=True,
    markingDefinitions=[tlp_green["id"]] if tlp_green else [],
)
print("created", indicator["standard_id"])
```

**Snippet 10 — Multi-provider enrichment in a notebook with msticpy TILookup**
Source: `TILookup`, `lookup_ioc`, `lookup_iocs(data=df)`, `result_to_df` and the `msticpyconfig.yaml` structure from the msticpy TI Providers page — [msticpy docs: TI Providers](https://msticpy.readthedocs.io/en/latest/data_acquisition/TIProviders.html). DataFrame column names are illustrative (the docs do not state them).
```python
# pip install msticpy   (or from GitHub while PyPI publishing is paused)
# msticpyconfig.yaml:
# TIProviders:
#   OTX:        {Args: {AuthKey: {EnvironmentVar: OTX_API_KEY}}, Primary: True, Provider: "OTX"}
#   AbuseIPDB:  {Args: {AuthKey: {EnvironmentVar: ABUSEIPDB_KEY}}, Primary: True, Provider: "AbuseIPDB"}
import pandas as pd
import msticpy as mp

mp.init_notebook()
ti = mp.TILookup()
print(ti.provider_status)                     # which providers loaded

single = mp.TILookup.result_to_df(ti.lookup_ioc("162.244.80.235"))
print(single[["Provider", "Severity", "Details"]])

df = pd.DataFrame({"IoC": ["162.244.80.235", "38.75.137.9"],
                   "IoCType": ["ipv4", "ipv4"]})
results = ti.lookup_iocs(data=df, ioc_col="IoC", ioc_type_col="IoCType")
print(results.groupby("Provider")["Severity"].value_counts())
```

### Inferences
- Snippets 1, 3, 4, 7 and 8 need no paid account (abuse.ch key and AbuseIPDB standard tier are free; ATT&CK TAXII is anonymous), so they suit a classroom lab; snippets 5, 6, 9 and 10 need a MISP/OpenCTI instance or API keys.
- Every official README fetched for OTX and AbuseIPDB still shows Python-2 `print` statements, so students should be warned to adapt vendor samples.

### Gaps
- Snippets were not executed in this session (no API keys, no network execution); they are assembled from documented signatures and should be smoke-tested before publication.
- URLhaus and Feodo Tracker CSV column names are unverified (Feodo page lists URLs only; URLhaus download docs are login-gated); snippet 8 discovers columns dynamically for that reason.
- `misp.search(controller="attributes", ...)`, `otx.getsince_iter(since, limit=...)` parameters, and the pycti `marking_definition.read(filters=...)` filter syntax are from library conventions, not from pages fetched this session; verify against the current PyMISP, OTXv2 and pycti API references.
