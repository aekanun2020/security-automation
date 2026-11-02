# Module 6 – Security Automation Project: Security Workflow Automation (SOAR) and Automated Alert Processing

Research date: 2026-11-01. Star counts were pulled live from the GitHub REST API on this date (see Q4). Several primary pages (gartner.com, mitre.org, docs.splunk.com, Shuffle PyPI page) blocked automated fetching (HTTP 403/404); where that happened it is noted in Gaps and a secondary source or an official mirror is cited instead.

## Q1. Who originally defined SOAR, and what are the authoritative frameworks for incident response and SOC operations?

### Takeaway
Gartner is universally credited with coining "SOAR" (security orchestration, automation and response) in 2017 as the convergence of three product categories (SIRP, SOA, TIP); Gartner later (2024 Hype Cycle for Security Operations) marked standalone SOAR "obsolete before plateau". The authoritative IR/SOC frameworks are NIST SP 800-61 Rev. 3 (April 2025, now a CSF 2.0 Community Profile), the SANS Incident Handler's Handbook (six-phase PICERL model), MITRE's "11 Strategies of a World-Class Cybersecurity Operations Center" (2022, free PDF), and for machine-readable playbooks the OASIS CACAO Security Playbooks v2.0 (Committee Specification 01, Nov 2023); OCSF supplies the normalization schema (Detection Finding class_uid 2004, schema v1.9.0).

### Cited Findings

**Gartner and the SOAR term**
- Gartner is "credited with coining" SOAR "around April 2017", judged by the earliest web artifacts; Gartner sees SOAR as a convergence of three formerly distinct technologies: security incident response platforms (SIRPs), security orchestration and automation (SOA), and threat intelligence platforms (TIPs) — [D3 Security, "What's the Difference Between SOAR and SAO?"](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)
- Gartner's later (2022-era) definition, as quoted by D3: "Solutions that combine incident response, orchestration and automation, and threat intelligence (TI) management capabilities in a single platform" — [D3 Security](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/); same wording reported as Gartner's 2022 definition by [Solutions Review](https://solutionsreview.com/security-information-event-management/wp-json/wp/v2/posts/3178)
- TechTarget states the acronym was first used by Gartner in 2015 to mean "security operations, analytics and reporting" before being redefined in 2017 — [TechTarget, SOAR definition](https://www.techtarget.com/searchsecurity/definition/SOAR); a Chinese-language history (secrss) also describes a 2015 definition then a 2017 redefinition — [secrss](https://www.secrss.com/articles/24043)
- The 2017 Gartner report that introduced the modern meaning is titled "Innovation Insight for Security Orchestration, Automation and Response" (vendor summary) — [Swimlane](https://swimlane.com/?p=9805)
- An older Gartner paraphrase (widely copied): SOAR is "technologies that enable organizations to collect inputs monitored by the security operations team" (e.g., SIEM alerts) and apply workflows aligned to processes and procedures — [Wikipedia, "Security orchestration"](https://en.wikipedia.org/wiki/Security_orchestration); Gartner's own glossary page is at [gartner.com glossary](https://www.gartner.com/en/information-technology/glossary/security-orchestration-automation-response-soar) (returned HTTP 403 to automated fetch; verify wording manually)
- Gartner published a "Market Guide for Security Orchestration, Automation and Response Solutions" (2019, 2020, 2022, 2023 editions); the 2023 edition is distributed via vendors — [TechRepublic listing of 2023 Gartner Market Guide for SOAR](https://www.techrepublic.com/resource-library/whitepapers/2023-gartner-market-guide-for-security-orchestration-automation-and-response-solutions/); key findings of the 2019 guide summarized by [Solutions Review](https://solutionsreview.com/security-information-event-management/key-findings-from-gartners-2019-market-guide-for-soar)
- Gartner's "Hype Cycle for Security Operations, 2024" (published 29 July 2024) labeled SOAR "obsolete before plateau" and lowered its benefit rating to "moderate"; critiques cited the development resources needed to maintain SOAR tools — [Netenrich analysis of the 2024 Hype Cycle](https://netenrich.com/blog/a-strategic-perspective-of-gartner-hype-cycle-for-security-operations-2024); Dark Reading reported the label "created a kerfuffle" — [Dark Reading, "SOAR Is Dead, Long Live SOAR"](https://darkreading.com/cybersecurity-operations/soar-is-dead-long-live-soar); some vendors attribute the phrasing to Gartner's June 17, 2024 ITSM Hype Cycle instead — [Torq](https://torq.io/?p=9180), [Blink Ops](https://www.blinkops.com/blog/gartner-says-goodbye-to-soar-whats-next-for-security-operations); Gartner's own (paywalled) Hype Cycle abstract: [gartner.com/en/documents/5622491](https://www.gartner.com/en/documents/5622491)
- Gartner Peer Insights now labels the SOAR category as "transitioning to Security Information and Event Management" — [Intezer, "Gartner's Changing Views on SOAR"](https://intezer.com/guides/soar-security/gartner-view-on-soar)

**NIST SP 800-61 Rev. 3 (2025)**
- Title: "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile"; final version dated 04/03/2025 (April 2025); authors Alexander Nelson, Sanjay Rekhi, Murugiah Souppaya (NIST), Karen Scarfone (Scarfone Cybersecurity); supersedes SP 800-61 Rev. 2 (08/06/2012); DOI https://doi.org/10.6028/NIST.SP.800-61r3 — [NIST CSRC publication page](https://csrc.nist.gov/pubs/sp/800/61/r3/final); PDF: [nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
- Abstract (verbatim): "This publication seeks to assist organizations with incorporating cybersecurity incident response recommendations and considerations throughout their cybersecurity risk management activities as described by the NIST Cybersecurity Framework (CSF) 2.0. Doing so can help organizations prepare for incident responses, reduce the number and impact of incidents that occur, and improve the efficiency and effectiveness of their incident detection, response, and recovery activities." — [NIST CSRC](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- NIST announcement (April 2025) and incident response project page encouraging use of online companion resources — [NIST news](https://nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations); [CSRC Incident Response project](https://csrc.nist.gov/projects/incident-response)
- Rev. 3 is organized around the CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) instead of Rev. 2's four-phase lifecycle (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity) — [Linford & Co analysis](https://linfordco.com/blog/nist-sp-800-61/); Rev. 3 has fewer tactical recommendations than Rev. 2 but more current terminology — [Tandem analysis](https://tandem.app/blog/updated-nist-incident-response-guidance-sp-800-61-rev-3)

**SANS Incident Handler's Handbook**
- "Incident Handler's Handbook", created by Patrick Kral, published 21 Feb 2012 (SANS Reading Room); scope "is limited to the six phases of the incident handling process"; defines an incident (citing Bejtlich 2005) as "any violation of policy, law, or unacceptable act that involves information assets" — [SANS white paper 33901](https://www.sans.org/white-papers/33901/)

**MITRE 11 Strategies**
- "11 Strategies of a World-Class Cybersecurity Operations Center", 2nd edition (fully revised from "Ten Strategies..."), authors Kathryn Knerler, Ingrid Parker, Carson Zimmerman; published 2022 (press release 29 March 2022); free download at mitre.org/11strategies; ~452 pages; audience "all cybersecurity operations center personnel" — [MITRE publication page](https://www.mitre.org/news-insights/publication/11-strategies-world-class-cybersecurity-operations-center); [MITRE short URL](https://www.mitre.org/11strategies); [BusinessWire release](https://www.businesswire.com/news/home/20220329005299/en/MITRE-Publishes-11-Strategies-of-a-World-Class-Cybersecurity-Operations-Center); highlights booklet PDF: [11-strategies-world-class-csoc-highlights.pdf](https://www.mitre.org/sites/default/files/2022-04/11-strategies-world-class-csoc-highlights.pdf)
- The book calls SOAR an "indispensable capability" for the modern SOC (vendor review of the book) — [D3 Security, "Why MITRE Calls SOAR 'Indispensable'"](https://d3security.com/blog/why-mitre-calls-soar-indispensable-in-its-latest-book)
- RSA Conference podcast on the book: [RSAC library, "Turn it up to 11"](https://www.rsaconference.com/library/podcast/turn-it-up-to-11-csoc)

**OASIS CACAO Security Playbooks**
- CACAO Security Playbooks Version 2.0, OASIS Committee Specification 01, 27 November 2023; editors Bret Jordan (Afero) and Allan Thomson; supersedes v1.0/v1.1; a playbook is "a workflow for security orchestration containing a set of steps" — [OASIS spec (latest v2.0)](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html); CS01 announcement: [oasis-open.org/?p=10546](https://www.oasis-open.org/?p=10546); approval press release (Cisco, Cyware, IBM, US NIST among backers): [oasis-open.org/?p=10491](https://www.oasis-open.org/?p=10491)
- playbook-type-ov vocabulary: notification, detection, investigation, prevention, mitigation, remediation, attack, engagement; workflow-step-type-enum: start, end, action, playbook-action, parallel, if-condition, while-condition, switch-condition; command types: manual, bash, caldera, elastic, http-api, jupyter, kestrel, openc2-http, powershell, ssh, sigma, yara — [OASIS CACAO v2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html)
- Serialization is JSON (RFC 8259); digital signatures use JCS canonicalization (RFC 8785); reuses STIX 2.1 Identity and Relationship objects and STIX Patterning for conditions — [OASIS CACAO v2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html)

**OCSF**
- OCSF "Detection Finding" class: class_uid 2004, category Findings (category_uid 2); description: "A Detection Finding describes detections or alerts generated by security products using correlation engines, detection engines or other methodologies"; activity_id: 0 Unknown, 1 Create, 2 Update, 3 Close, 99 Other; required attributes: activity_id, category_uid, class_uid, finding_info, metadata, severity_id, time, type_uid; recommended: confidence_id, evidences, is_alert, message, observables, resources, status_code, status_detail, status_id, timezone_offset; current schema version shown: 1.9.0 — [schema.ocsf.io/classes/detection_finding](https://schema.ocsf.io/classes/detection_finding)
- type_uid = class_uid * 100 + activity_id (e.g., 200401 = Detection Finding: Create) — [Tenzir OCSF reference, detection_finding 1.4.0](https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding)
- The older "Security Finding" class (class_uid 2001, OCSF 1.0.0) "describes findings, detections, anomalies, alerts and/or actions performed by security products" — [Tenzir OCSF 1.0.0 security_finding](https://docs.tenzir.com/reference/ocsf/1-0-0/classes/security_finding); OCSF FAQ: a finding is "the result of some type of enrichment, correlation, aggregation, analysis or other processing of one or more events or alerts" — [OCSF FAQ via Tenzir](https://docs.tenzir.com/reference/ocsf/faqs/when-should-i-use-a-finding-event-class)
- OCSF schema source repo: [github.com/ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) (910 stars, GitHub API 2026-11-01)

**Google SRE (philosophical background for alerting)**
- SRE Book ch. 6 "Monitoring Distributed Systems" (Rob Ewaschuk, ed. Betsy Beyer, 2017, CC BY-NC-ND 4.0): "Every page should be actionable"; "Every page response should require intelligence"; "Pages should be about a novel problem or an event that hasn't been seen before"; rule-writing test: "Does this rule detect an otherwise undetected condition that is urgent, actionable, and actively or imminently user-visible?"; also "Will I ever be able to ignore this alert, knowing it's benign?" and "Can I take action in response to this alert... could that action... be automated?"; four golden signals: latency, traffic, errors, saturation; page on symptoms, not causes — [sre.google SRE Book ch.6](https://sre.google/sre-book/monitoring-distributed-systems/)

### Inferences
- The curriculum can present SOAR historically in three phases: (1) 2015 "security operations, analytics and reporting"; (2) 2017 redefinition as SIRP+SOA+TIP convergence; (3) 2024 onward, Gartner treating standalone SOAR as being absorbed into SIEM/XDR and "AI SOC" tooling. Students should therefore learn the *capabilities* (case management, orchestration, automation, TI management) rather than a product category.
- NIST 800-61r3's move to CSF functions means the classic 4-phase lifecycle is now "legacy" framing; the SANS PICERL six phases remain the most commonly taught operational model. A course can map PICERL -> CSF 2.0 functions (Prepare -> Govern/Identify/Protect; Identification -> Detect; Containment/Eradication/Recovery -> Respond/Recover; Lessons Learned -> Identify.IM/Govern).
- CACAO's step and command vocabulary (if-condition, parallel, http-api, sigma, yara) is a good "neutral" language for teaching playbook structure before students touch a vendor's playbook editor.

### Gaps
- Gartner's glossary page and Hype Cycle documents are paywalled/403 to automated access; the exact 2017 wording could not be quoted from Gartner directly. The "obsolete before plateau" attribution is contested between the Security Operations Hype Cycle (29 Jul 2024) and the ITSM Hype Cycle (17 Jun 2024); both are vendor-reported.
- mitre.org returned 403 for the publication page and highlights PDF, so the exact titles of the 11 strategies were not verified from the source in this session. (From the book's table of contents, as recalled and NOT verified here: 1 Know what you are protecting and why; 2 Give the SOC the authority to do its job; 3 Build a SOC structure to match your organizational needs; 4 Hire and grow quality staff; 5 Prioritize incident response; 6 Illuminate adversaries with cyber threat intelligence; 7 Select and collect the right data; 8 Leverage tools to support analyst workflow; 9 Communicate clearly, collaborate often, share generously; 10 Measure performance to improve performance; 11 Turn up the volume by expanding SOC functionality. Verify at https://www.mitre.org/11strategies before publishing.)
- The SANS Handbook page confirms "six phases" but does not list them; the names Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned must be verified in the PDF at the same URL.
- Could not confirm from a primary source whether OCSF formally deprecated Security Finding (2001) in favor of Detection Finding (2004); the version ranges in the Tenzir mirror suggest so.

## Q2. Which open-source and commercial SOAR platforms support Python playbooks/automations, and how are they documented?

### Takeaway
Python is the lingua franca of SOAR extensibility: TheHive/Cortex (thehive4py, cortexutils), Shuffle (shuffle_sdk AppBase), Splunk SOAR (phantom.rules playbook API), Cortex XSOAR (demisto/CommonServerPython automations), StackStorm (python-script runner), Wazuh (active response scripts), Tines ("Run Python Script" action), and n8n (Code node, native Python since n8n 2) all expose documented Python entry points; Elastic Security and Sigma contribute the detection/rule side with Python tooling (detection-rules CLI, pySigma/sigma-cli).

### Cited Findings

**TheHive + thehive4py**
- thehive4py is "the de facto Python API client of TheHive"; install: `pip install thehive4py`; client: `from thehive4py import TheHiveApi; hive = TheHiveApi(url="http://localhost:9000", apikey="h1v3b33")` — [thehive4py docs](https://thehive-project.github.io/TheHive4py/latest/)
- Alert API: `hive.alert.create({...})` with required fields `type`, `source`, `sourceRef`, `title`, `description`; observables can be embedded in the alert as a list with `dataType`/`data`; `hive.alert.promote_to_case(alert_id=alert["_id"])` (optional `fields` arg to modify the resulting case); `hive.alert.create_observable(alert_id=..., observable={...})` (bulk creation requires one shared dataType); `hive.alert.find(filters=Eq(field="tags", value="antivirus") | Eq(field="tags", value="phishing"))` using class-based filters or raw Query API dicts — [thehive4py alert examples](https://thehive-project.github.io/TheHive4py/latest/examples/alert/)
- TheHive is "a Cybersecurity Incident Response Management (CIRM) platform, now distributed commercially" (StrangeBee); the public TheHive repo is archived (3,950 stars); TheHive4py repo 244 stars — GitHub API 2026-11-01: [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive), [TheHive-Project/TheHive4py](https://github.com/TheHive-Project/TheHive4py); vendor docs: [docs.strangebee.com](https://docs.strangebee.com/)

**Cortex + cortexutils**
- Cortex: "a Powerful Observable Analysis and Active Response Engine" (1,640 stars; actively pushed Oct 2026) — [TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex); analyzers repo 494 stars — [TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers); cortexutils: "a set of classes that aims to make users write Cortex analyzers easier", AGPL-3.0 — [TheHive-Project/cortexutils](https://github.com/TheHive-Project/cortexutils)
- Official how-to: an analyzer "can be written in any programming language that is supported by Linux"; "The Cortexutils library is in Python. It greatly facilitates analyzer development and it also provides some methods to quickly format the output"; each analyzer needs a JSON service-interaction file (fields: name, version, author, url, license, description, dataTypeList, command, baseConfig, config, configurationItems) and, for Python, a requirements.txt; output JSON uses `success: false` + error on failure and a summary whose color depends on verdict safe/info/suspicious/malicious — [StrangeBee docs, How to Write and Submit an Analyzer](https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/) (mirror: [docs.thehive-project.org](https://docs.thehive-project.org/cortex/api/how-to-create-an-analyzer/))
- cortexutils Analyzer methods: `get_param(name, default, message)`, `get_data()`, `report(dict)`, `summary(raw)`, `build_taxonomy(level, namespace, predicate, value)`, `artifacts()`/`build_artifact()` — [DeepWiki developer guide (third-party)](https://deepwiki.com/TheHive-Project/Cortex-Analyzers/6-developer-guide); TheHive blog: "The short report is built with the summary() function of an analyzer. The build_taxonomy() of cortexutils... should help building it" — [TheHive Project blog](https://blog.thehive-project.org/tag/misp/page/4)

**Shuffle**
- "Shuffle: A general purpose security automation platform"; core AGPLv3, apps and App SDK MIT; "Easy to learn Python library for custom apps"; 2,466 stars — [Shuffle/Shuffle](https://github.com/Shuffle/Shuffle); apps repo (130 stars): "Most of Shuffle's apps (2500+) are generated from" OpenAPI — [Shuffle/python-apps](https://github.com/Shuffle/python-apps)
- Three ways to build apps: App Creator (exports OpenAPI), AI generation, or Python "which makes it possible to connect literally any tool"; "Always prioritize using the App Creator when applicable" — [Shuffle/Shuffle README](https://github.com/Shuffle/Shuffle)
- Python app pattern documented in shuffle-docs/apps.md: a class subclassing `AppBase` with `__version__`, `app_name` ("this needs to match 'name' in api.yaml"), `__init__(self, redis, logger, console_logger=None)` calling `super().__init__(redis, logger, console_logger)`, and one method per action — [Shuffle/shuffle-docs docs/apps.md](https://github.com/Shuffle/shuffle-docs/blob/master/docs/apps.md) (rendered at [shuffler.io/docs/apps](https://shuffler.io/docs/apps))
- `shuffle-sdk` on PyPI: "the SDK used for app development, testing and production of ALL apps in Shuffle. Works with manual runs, Docker, k8s, cloud serverless" — [pypi.org/project/shuffle-sdk/0.0.8/](https://pypi.org/project/shuffle-sdk/0.0.8/)

**Splunk SOAR (formerly Phantom)**
- Python Playbook API: every playbook defines `on_start(container)` and `on_finish(container, summary)`; `phantom.act()` "can be called from on_start() or the callback of any phantom.act() call" and "is not supported from within a custom function"; callbacks receive keyword args such as `action`, `success`, `container`, `results`; multiple `phantom.act()` calls in the same function execute in parallel; actions on assets with approvers are not executed until approved — [Splunk SOAR (Cloud) Playbook automation API](https://help.splunk.com/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api); [Splunk SOAR On-prem Playbook API (docs.splunk.com)](https://docs.splunk.com/Documentation/SOARonprem/latest/PlaybookAPI/PlaybookAPI)
- Tutorial: `on_start` calls `phantom.act` with action `"geolocate ip"` (default asset MaxMind), then adds a `callback=geolocate_ip_cb` because actions run asynchronously; `phantom.debug()` writes to the debug console; `on_finish` logs `summary` and is where to "send a summary email, close an incident, or update a ticket" — [Tutorial: Create a simple playbook (SOAR Cloud)](https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial/playbook-api-tutorial/tutorial-create-a-simple-playbook-in-splunk-soar-cloud); [Python Playbook Tutorial overview (On-prem)](https://help.splunk.com/en/splunk-soar/soar-on-premises/python-playbook-tutorial)
- Legacy custom-function code shows `phantom.collect2(container=container, datapath=['artifact:*.cef.message', ...])`, `phantom.act("run query", parameters=parameters, assets=['mysql'], callback=filter_2, name="SearchDB")`, `phantom.save_run_data(key=..., value=json.dumps(...))`; output variables become `<block_name>__<variable_name>`; the legacy block is deprecated in favor of custom functions introduced in Phantom 4.9 — [Splunk help, legacy custom function block (6.3.0)](https://help.splunk.com/en/splunk-soar/soar-on-premises/build-playbooks/6.3.0/use-the-classic-playbook-editor-to-create-and-view-playbooks-to-automate-analyst-workflows/add-custom-code-to-your-splunk-soar-on-premises-playbook-with-the-legacy-custom-function-block-using-the-classic-playbook-editor)

**Palo Alto Cortex XSOAR**
- Content repo: "Demisto is now Cortex XSOAR"; scripts "written in Python or Javascript perform Security Operations tasks"; integrations provide commands mapping to product APIs; "We use docker to run python scripts and integrations in a controlled environment"; playbooks exportable in COPS format; developer portal https://xsoar.pan.dev/ — [demisto/content README](https://github.com/demisto/content) (1,322 stars; demisto-sdk 90 stars — [demisto/demisto-sdk](https://github.com/demisto/demisto-sdk))
- Automation script snippets: `demisto.args()` (dict) / `demisto.args()['argumentName']`; `demisto.incident()`; `tableToMarkdown("Table Name", outputContext)`; `CommandResults(...)` passed to `return_results()` (writes to War Room and context); `return_error(message)`; `demisto.executeCommand("setIncident", {'details': fieldValue})`; entry guard `if __name__ in ("__main__", "__builtin__", "builtins"): main()` — [Cortex XSOAR Python Dev Quick Start: Script Code Snippets](https://cortex-docs.paloaltonetworks.com/python-development-quick-start-guide/cortex-xsoar-python-development-quick-start-guide/script-code-snippets)
- Code conventions: imports `import demistomock as demisto`, `from CommonServerPython import *`, `from CommonServerUserPython import *`; `main()` reads `demisto.params()`, dispatches on `demisto.command()`, wraps in try/except with `return_error(f'Failed to execute {command} command. Error: {str(e)}')`; `CommandResults(outputs_prefix, outputs_key_field, outputs, readable_output)` — [xsoar.pan.dev Code Conventions](https://xsoar.pan.dev/docs/integrations/code-conventions); helper reference: [Common Server Python](https://xsoar.pan.dev/docs/reference/api/common-server-python)

**StackStorm**
- "StackStorm (aka 'IFTTT for Ops') is event-driven automation for auto-remediation, incident..."; 6,554 stars — [StackStorm/st2](https://github.com/StackStorm/st2)
- Actions are code triggered by rules, chained in workflows, or run from CLI/API/UI; Python action = YAML metadata (`runner_type: "python-script"`, `entry_point`, `parameters`) + class subclassing `st2common.runners.base_action.Action` with `def run(self, message)` returning `(True, result)`/`(False, result)` — [docs.stackstorm.com/actions.html](https://docs.stackstorm.com/actions.html)

**Wazuh active response**
- Custom active response scripts read one JSON line from stdin, dispatch on `command` (add/delete), use constants `ADD_COMMAND = 0`, `DELETE_COMMAND = 1`, `CONTINUE_COMMAND = 2`, `ABORT_COMMAND = 3`, send a `check_keys` message (`{"version": 1, "origin": {"name": argv[0], "module": "active-response"}, ...}`) and proceed only on `continue`; log to `/var/ossec/logs/active-responses.log`; wired via `<command><name>linux-custom-ar</name><executable>custom-ar.py</executable>...` and `<active-response><command>linux-custom-ar</command><location>local</location><rules_id>503</rules_id><timeout>60</timeout></active-response>` — [Wazuh docs, Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html); Wazuh repo 17,528 stars — [wazuh/wazuh](https://github.com/wazuh/wazuh)

**Tines**
- "Run Python Script" template action: inputs referenced as `input["<<object_name>>"]`; "Your script's return value should be a JSON object" which becomes the emitted event; dependencies "listed in the format of a requirements.txt file"; timeout defaults to 10 s, max 25 s; historically python3.9 only and cloud-only — [Tines docs, Run Python Script](https://www.tines.com/docs/actions/templates/templates/frequently-used-templates/run-python-script/); Tines Tunnel lets scripts run inside your network with custom packages — [Tines What's New](https://www.tines.com/stories/whats-new/execute-python-code-via-tines-tunnel/); how-to: [Tines blog](https://tines.com/blog/python-tines-how-to-guide)

**n8n**
- Code node runs JavaScript or Python; Pyodide Python "is removed from n8n 2.0"; native Python (task runners) is stable as of n8n 2; modes "Run Once for All Items" and "Run Once for Each Item"; native Python exposes only `_items` / `_item` with bracket notation; the Code node cannot make HTTP requests or touch the filesystem (use HTTP Request node); Python imports not allowed on n8n Cloud — [docs.n8n.io Code node](https://docs.n8n.io/code/code-node/); n8n repo 209,280 stars, "Fair-code workflow automation platform with native AI capabilities" — [n8n-io/n8n](https://github.com/n8n-io/n8n)

**Elastic Security**
- Rule types: Custom query, Event correlation (EQL), Threshold, Indicator match, New terms, ES|QL, Machine learning; "(Optional) Set up rule actions" — [Elastic docs, Create a detection rule](https://www.elastic.co/docs/solutions/security/detect-and-alert/create-detection-rule)
- Alerts are stored in hidden indices `.alerts-security.alerts-<space-id>` (8.x; 7.x used `.siem-signals-<space-id>`); legacy `signal.*` fields map to `kibana.alert.*` (e.g., `kibana.alert.rule.name`); `kibana.alert.severity` must be low/medium/high/critical; Elastic recommends the search API `fields` option rather than `_source` — [Elastic Security alert schema (8.18)](https://www.elastic.co/guide/en/security/8.18/alert-schema.html)
- detection-rules repo: "Detection Rules is the home for rules used by Elastic Security"; rules in `rules/` and `rules_building_block/` as TOML; Python 3.12+ via `make` or `pip3 install ".[dev]"`; CLI `python -m detection_rules --help`; Elastic License v2; 2,946 stars — [elastic/detection-rules README](https://github.com/elastic/detection-rules)
- elasticsearch-py: `python -m pip install elasticsearch`; `client = Elasticsearch("https://...", api_key=os.environ["ELASTIC_API_KEY"])`; `client.search(index="my_index", query={"match": {...}})`; requires Python 3.10+ — [Elastic Python client getting started](https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started)

**Sigma**
- "Sigma - Generic Signature Format for SIEM Systems": "a generic and open signature format that allows you to describe relevant log events in a straightforward manner"; "more than 3000 detection rules"; folders rules/, rules-threat-hunting/, rules-emerging-threats/, rules-compliance/, rules-placeholder/; Sigma CLI is "the official command-line converter", pySigma for integrating into your own toolchain; rules licensed under Detection Rule License (DRL) 1.1; 11,383 stars — [SigmaHQ/sigma README](https://github.com/SigmaHQ/sigma)
- Sigma was introduced in 2017 by Florian Roth and Thomas Patzke; README links a 2017 Hack.lu talk by Patzke and Roth's slides — [CSO Online, Sigma rules explained](https://www.csoonline.com/article/572973/sigma-rules-explained-when-and-how-to-use-them-to-log-events.html); [SigmaHQ README via jsDelivr mirror](https://cdn.jsdelivr.net/gh/sigmahq/sigma@master/README.md)

### Inferences
- A practical "Module 6" stack that is fully open-source and Python-first: Wazuh or Elastic (detection) -> webhook -> FastAPI normalizer (OCSF) -> dedupe/score -> TheHive alert via thehive4py -> Cortex analyzer enrichment -> Shuffle or n8n workflow -> Jira/TheHive case. Every hop has an official Python API documented above.
- Commercial platforms (Splunk SOAR, XSOAR, Tines) converge on the same shape: a sandboxed Python function receiving a dict of inputs and returning a dict/result object; the vendor-specific parts are the entry guard (`on_start`, `main()` + `__builtin__`, `input[...]`) and the result wrapper (`phantom.act` callback, `CommandResults`, JSON return).
- Gartner's "SOAR is obsolete" stance plus n8n's 200k+ stars suggests the curriculum should teach general-purpose workflow engines (n8n, StackStorm) alongside security-specific SOAR.

### Gaps
- docs.splunk.com (On-prem Playbook API, tutorial) returned 403; the SOAR Cloud help.splunk.com pages were used instead. Exact verbatim code of the tutorial could not be captured (summarized above).
- The Shuffle PyPI page did not render; the current shuffle-sdk version (last seen 0.0.8) is unconfirmed. shuffler.io/docs/app_creation returns "Couldn't find documentation"; apps.md on GitHub was used.
- Elastic "rule actions" connector list (Slack, Webhook, Jira, TheHive, etc.) and alert-suppression details live on the "common rule settings" page, which was not fetched.
- Tines limits (python3.9, 25 s) may be outdated per the docs' own caveat.

## Q3. What are accepted designs for alert pipelines (ingest -> normalize -> dedupe -> enrich -> score -> route/auto-close/escalate), and what writings describe them?

### Takeaway
Industry writing converges on a staged pipeline: normalize to a common schema (OCSF / ECS), deduplicate on a fingerprint ("dedupe key") within a time window, enrich with asset/identity/threat-intel/case-history context, compute a composite risk score that overrides static vendor severity, then route (auto-close known-benign, escalate to case/ticket), with analyst dispositions fed back into detection tuning. The motivation is well documented alert-overload data (Critical Start: ~half of SOCs report >=50% false positives; SANS 2025: most SOCs trigger IR from endpoint alerts and run AI tools "out of the box"), and the philosophical backbone is Google SRE's "every page should be actionable".

### Cited Findings

**Alert fatigue / overload evidence**
- Critical Start 2019 SOC survey (~50 SOCs, Q2 2019): "70% of respondents investigate 10+ alerts each day (up from 45% last year)"; "78% said it takes 10+ minutes to investigate each alert (up from 64%)"; nearly half report a false-positive rate of 50% or higher; 38% respond by hiring more analysts or turning off high-volume alerting features — [Critical Start press release](https://criticalstart.com/resources/criticalstart-releases-third-annual-security-operations-center-soc-professional-survey); [Help Net Security coverage](https://www.helpnetsecurity.com/2019/08/29/soc-alert-overload/); Critical Start report PDF: [CS_MDR_Survey_Report.pdf](https://www.criticalstart.com/wp-content/uploads/CS_MDR_Survey_Report.pdf). Note: other coverage reports 79% (10+ alerts/day) and 74% (10+ minutes) — [Dark Reading](https://www.darkreading.com/analytics/overburdened-soc-analysts-shift-priorities/d/d-id/1335698); figures conflict across outlets.
- Critical Start 2021 survey (100 SOC professionals across enterprises, MSSPs, MDRs): "Nearly 70% of respondents (68%) said that 25 to 75% of the alerts they investigate on a daily basis are false positives" — [Help Net Security, 2021](https://www.helpnetsecurity.com/2021/03/11/alert-overload-still-plagues-cybersecurity-industry/)
- SANS 2025 SOC Survey (sponsored by Elastic): "42% of SOCs use AI/ML tools 'out of the box' with no customization"; "85% of SOCs primarily trigger incident response from endpoint alerts, rather than proactive detection" (vendor summaries of the survey) — [Swimlane summary](https://swimlane.com/blog/global-soc-survey-insights/); [Torq summary](https://torq.io/blog/sans-2025-soc-survey); landing page: [Elastic, 2025 State of the SOC Survey](https://www.elastic.co/resources/security/report/2025-state-of-the-soc-survey); PDF: [elastic.co/pdf/sans-soc-survey-2025.pdf](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)
- SANS 2026 SOC survey (vendor summary): 79% of SOCs use AI tools but only 36% have integrated them into defined workflows — [Dropzone AI infographic page](https://content.dropzone.ai/2025-sans-soc-survey-infographic) (reported there; verify)
- SANS "State of Automation in Security Operations" survey: IOC matches were cited by 37% as the alert type that takes longest to triage — [SANS white paper](https://www.sans.org/white-papers/state-automation-security-operations-sans-survey/)
- SANS/Rapid7 2025 Detection & Response survey: continued concern about false positives, shift toward automation, growing confidence in ML — [Rapid7 survey PDF](https://www.rapid7.com/cdn/assets/blt2e3e3f0d1864c31f/6937f5fa43c2f8cbe153e2a5/Survey_Detection-Response_Rapid7_2025.pdf)

**Pipeline stage designs**
- Normalization: map alerts from different tools into one common schema; "without a reliable normalization layer, even high-quality detection logic will produce inconsistent results across heterogeneous enterprise environments" — [UnderDefense, AI-enabled incident triage (Apr 2026)](https://underdefense.com/blog/ai-enabled-incident-triage/)
- Deduplication: "Merge duplicate or overlapping alerts from multiple sources. A single login anomaly shouldn't generate three separate tickets." — [Dropzone AI, Alert Triage Guide 2025](https://dropzone.ai/resource-guide/alert-triage-guide-2025)
- Dedupe-key design (Vincent van Dijk, Security Scientist): keys ("dedupe keys" or "causal fingerprints") typically combine source/destination IP or hostname, ports, protocol, event type/signature ID, and optionally user, process, file hash, checked "within a defined time window" (example: identical src/dst IPs within 5 minutes = same event); signature-based matching uses "hashes of alert data"; risk: over-aggressive rules create "false negatives" where a unique attack is missed "because it looked too much like something you've seen before" — [Security Scientist, 12 Q&A about alert deduplication](https://www.securityscientist.net/blog/12-questions-and-answers-about-alert-deduplication/) (its "up to 90% MTTC reduction" claim is unsourced; treat as marketing)
- Enrichment inputs: threat intelligence feeds, asset inventory, user identity context, historical incident records — [Deepwatch glossary, Automated Incident Triage](https://www.deepwatch.com/glossary/automated-incident-triage/)
- Scoring: a composite score replaces static vendor severity, e.g., a "medium" alert on a crown-jewel asset outranks a "high" on a test server; analyst accept/override decisions "flow back into the system to improve future scoring accuracy" — [Deepwatch glossary](https://www.deepwatch.com/glossary/automated-incident-triage/)
- Alert management overview (normalize, dedupe, correlate, prioritize, route) — [NHI Mgmt Group glossary, Alert management](https://nhimg.org/glossary/alert-management/)
- High-volume event pipeline webinar ("hundreds of alerts per minute") — [D3 Security, Event Pipeline](https://d3security.com/resources/event-pipeline-automate-handling-of-hundreds-of-alerts-per-minute/)
- Red Canary alert states: many alerts labeled "Not a Threat" are handled through automation ("Workflow Rule"); detection engineers categorize historical alerts — [Red Canary docs, Alert states](https://docs.redcanary.com/docs/alert-states); Alert Center: suppress by chosen attributes so the platform applies suppression to future alerts; automation for high-confidence/high-impact alerts — [Red Canary, Alert Center](https://redcanary.com/blog/alert-center/); "Agentic Tuning": layered global and per-customer tuning, early-access customers saw up to 80% reduction in identity-related false positives, suppressions remain auditable — [Red Canary, AI agentic tuning](https://redcanary.com/blog/product-updates/ai-agentic-tuning/)
- Detection quality over triage speed: "alert volume isn't a function of investigation speed; it's a function of detection quality"; feeding triage outcomes back into detection logic keeps volume falling — [Panther, Tuning detections without a backlog](https://panther.com/blog/tuning-detections-without-a-backlog)
- Expel: reducing false positives through better detection engineering delivers the highest ROI against alert fatigue — [Expel, How to implement alert fatigue solutions](https://expel.com/cyberspeak/how-to-implement-alert-fatigue-solutions/); see also [Expel, Reduce false positives in SOC operations](https://expel.com/cyberspeak/reduce-false-positives-in-soc-operations/)
- Target's detection confidence/rule-management approach — [Target Tech blog, Boost Detection Confidence](https://tech.target.com/blog/boost_detection_confidence)
- Sequence automation after tuning: start with high-volume alert types, automate only once the rule is clean and enrichment reliable — [NHI Mgmt Group, SOC automation and detection quality](https://nhimg.org/community/cybersecurity-beyond-identity/soc-automation-and-detection-quality-where-should-teams-start/); triage as a control feedback loop, measuring suppression quality, alert recurrence, % of triage outcomes that change rules — [NHI Mgmt Group FAQ](https://nhimg.org/faq/how-should-security-teams-turn-triage-outcomes-into-better-detections/)
- Academic: "Decision-Aware Trust Signal Alignment for SOC Alert Triage" (arXiv 2601.04486): signal quality determines triage quality — [arXiv](https://arxiv.org/pdf/2601.04486)
- Vendor claim (unverified): ">80% of alerts lead to dead ends, while fewer than 5% of rules generate most of the noise" — [AiStrike via Security Boulevard](https://securityboulevard.com/2026/03/aistrike-launches-continuous-detection-engineering-to-fix-alert-noise-at-the-source/)

**Detection-engineering voices on alert quality**
- Florian Roth (Sigma co-creator) on rule quality: rules "differ widely in purpose, quality, and how often they produce false positives"; his tooling yarGen, Panopticon, yaraQA checks rule quality; YARA Forge's "core" set keeps only high-quality, low-FP, low-performance-impact rules — [cyb3rops, Introducing YARA Forge](https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab)
- Alex Teixeira: Editor of Detect FYI, SIEM (Splunk, Sentinel)/EDR detection-engineering consultant — [ateixei.medium.com/about](https://ateixei.medium.com/about); related community series "Detections -> Alerts" — [zendannyy Substack](https://zendannyy.substack.com/p/detection-engineering-series-detections); TryHackMe "How detection engineering actually works" — [TryHackMe blog](https://tryhackme.com/resources/blog/how-detection-engineering-actually-works); Elastic Security Labs detection-engineering category — [elastic.co/security-labs](https://www.elastic.co/pt/security-labs/category/detection-engineering)
- Black Hills InfoSec slides "The Detection Engineering Process" (Nov 2024) — [BHIS PDF](https://www.blackhillsinfosec.com/wp-content/uploads/2024/11/SLIDES_The-Detection-Engineering-Process.pdf)

**Escalation to ticketing**
- jira (Python): `JIRA(basic_auth=('email', 'API token'))` (Cloud) or `JIRA(token_auth='API token')` (self-hosted); `jira.create_issue(project='PROJ_key_or_id', summary='...', description='...', issuetype={'name': 'Bug'})` or `create_issue(fields=issue_dict)`; `jira.add_comment('JRA-1330', 'new comment')`; `jira.transition_issue(issue, '5', ...)`; `jira.search_issues('project=PROJ')` — [jira.readthedocs.io examples](https://jira.readthedocs.io/examples.html)
- TheHive promote alert to case: `hive.alert.promote_to_case(alert_id=...)` — [thehive4py alert examples](https://thehive-project.github.io/TheHive4py/latest/examples/alert/)

### Inferences
- The accepted reference design is: (1) ingest via webhook/queue; (2) normalize to OCSF Detection Finding (required fields give you the minimum schema); (3) fingerprint = hash(rule_id, primary entity such as host/user/src_ip, dst) within a sliding window (5-15 min typical per the examples); (4) enrich (asset criticality, identity, TI reputation, prior dispositions); (5) score = base severity x asset criticality x TI confidence +/- historical FP rate; (6) route: score below threshold with known-benign fingerprint -> auto-close with audit trail; above threshold -> case/ticket; (7) record analyst verdicts and feed them back as suppression/tuning. Every stage maps to a documented Python API in Q2.
- The SRE rule set ("actionable", "requires intelligence", "novel") translates directly into SOC auto-close criteria: anything that fails all three should be suppressed or automated, not paged.
- Red Canary's practice (auditable suppressions, workflow rules for "Not a Threat") is the clearest public example of auto-closing false positives safely.

### Gaps
- No vendor-neutral, peer-reviewed specification of scoring formulas or dedupe windows was found; all concrete numbers (5 min window, 80% FP reduction) are from single vendors.
- Could not locate a specific Alex Teixeira article on alert triage/quality, nor a Florian Roth "Detection Engineering" essay; only his YARA Forge piece was fetched. The Red Canary detection-engineering post that says they accept false positives in exchange for a wide net was referenced in search results but not fetched directly.
- The SANS 2025 SOC Survey PDF at elastic.co fetched as a 1-page cover only; percentages above come from vendor summaries. An "IDC alert overload" survey was not found in this session.

## Q4. Which community resources and repositories are most cited (with approximate star counts)?

### Takeaway
By GitHub stars (API snapshot 2026-11-01): n8n (209k) dwarfs the security-specific tools; Wazuh (17.5k), Sigma (11.4k), awesome-incident-response (9.5k), StackStorm (6.6k), Security Onion (5.0k), TheHive (4.0k, archived), elastic/detection-rules (2.9k), Shuffle (2.5k), Cortex (1.6k), XSOAR content (1.3k), Awesome-SOAR (1.0k), OCSF schema (0.9k), SOCFortress CoPilot (0.5k), Cortex-Analyzers (0.5k).

### Cited Findings
All counts below from the GitHub REST API (`stargazers_count`) queried 2026-11-01:
- n8n-io/n8n — 209,280 stars; "Fair-code workflow automation platform with native AI capabilities" — [github.com/n8n-io/n8n](https://github.com/n8n-io/n8n)
- wazuh/wazuh — 17,528; "Unified XDR and SIEM protection for endpoints..." — [github.com/wazuh/wazuh](https://github.com/wazuh/wazuh)
- SigmaHQ/sigma — 11,383; "Main Sigma Rule Repository" — [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- meirwah/awesome-incident-response — 9,521; "A curated list of tools for incident response", Apache-2.0 — [github.com/meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response) (a tracker reported 9,376 stars / 1,743 forks in Sep 2026 — [awesome.ecosyste.ms](https://awesome.ecosyste.ms/projects/github.com%2Fmeirwah%2Fawesome-incident-response))
- StackStorm/st2 — 6,554 — [github.com/StackStorm/st2](https://github.com/StackStorm/st2)
- Security-Onion-Solutions/securityonion — 4,961; "a free and open platform for threat hunting, enterprise security monitoring..." — [github.com/Security-Onion-Solutions/securityonion](https://github.com/Security-Onion-Solutions/securityonion)
- TheHive-Project/TheHive — 3,950; repository archived (last push 2025-07-25); TheHive now commercial via StrangeBee — [github.com/TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive)
- elastic/detection-rules — 2,946 — [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules)
- Shuffle/Shuffle — 2,466 — [github.com/Shuffle/Shuffle](https://github.com/Shuffle/Shuffle)
- TheHive-Project/Cortex — 1,640 — [github.com/TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex)
- demisto/content (Cortex XSOAR content) — 1,322 — [github.com/demisto/content](https://github.com/demisto/content)
- correlatedsecurity/Awesome-SOAR — 1,007; "A curated Cyber 'Security Orchestration, Automation and Response (SOAR)' awesome list"; last push 2024-08-26 — [github.com/correlatedsecurity/Awesome-SOAR](https://github.com/correlatedsecurity/Awesome-SOAR)
- ocsf/ocsf-schema — 910 — [github.com/ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema)
- socfortress/CoPilot — 538; "SOCFortress CoPilot" — [github.com/socfortress/CoPilot](https://github.com/socfortress/CoPilot)
- TheHive-Project/Cortex-Analyzers — 494 — [github.com/TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers)
- TheHive-Project/TheHive4py — 244 — [github.com/TheHive-Project/TheHive4py](https://github.com/TheHive-Project/TheHive4py)
- Shuffle/python-apps — 130 — [github.com/Shuffle/python-apps](https://github.com/Shuffle/python-apps)
- demisto/demisto-sdk — 90 — [github.com/demisto/demisto-sdk](https://github.com/demisto/demisto-sdk)
- TheHive-Project/cortexutils — 8 — [github.com/TheHive-Project/cortexutils](https://github.com/TheHive-Project/cortexutils)
- Other IR lists: hevnsnt/Awesome_Incident_Response (phase-by-phase guide) — [github.com/hevnsnt/Awesome_Incident_Response](https://github.com/hevnsnt/Awesome_Incident_Response)
- SANS Reading Room / surveys: Incident Handler's Handbook — [sans.org/white-papers/33901](https://www.sans.org/white-papers/33901/); State of Automation in Security Operations — [sans.org](https://www.sans.org/white-papers/state-automation-security-operations-sans-survey/); 2025 SOC Survey (Elastic-hosted) — [elastic.co](https://www.elastic.co/resources/security/report/2025-state-of-the-soc-survey)
- Developer portals most referenced: [xsoar.pan.dev](https://xsoar.pan.dev/), [shuffler.io/docs](https://shuffler.io/docs/apps), [docs.strangebee.com](https://docs.strangebee.com/), [docs.stackstorm.com](https://docs.stackstorm.com/actions.html), [documentation.wazuh.com](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html), [help.splunk.com SOAR](https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial), [docs.n8n.io](https://docs.n8n.io/code/code-node/), [tines.com/docs](https://www.tines.com/docs/actions/templates/templates/frequently-used-templates/run-python-script/), [schema.ocsf.io](https://schema.ocsf.io/classes/detection_finding)

### Inferences
- Awesome-SOAR has not been updated since Aug 2024, so treat it as a historical index; awesome-incident-response (updated Oct 2026) is the better living list.
- TheHive's archived public repo means course material should target TheHive 5 (StrangeBee) with thehive4py 2.x; students should not clone the archived repo.

### Gaps
- Shuffle/Shuffle-Tools does not exist as a repo (API returned null); "Shuffle Tools" is an app inside Shuffle/python-apps.
- Star counts are a point-in-time snapshot and will drift.

## Q5. Code examples (6+ runnable Python snippets, 10-40 lines, attributed)

### Takeaway
Eleven snippets follow. Snippets 1, 4, 5, 9, 10, 11 are adapted closely from official docs (URL given); snippets 2, 3, 6, 7, 8 are marked ILLUSTRATIVE and built only from the documented APIs cited in Q2/Q3. All require the noted pip packages and credentials; none were executed against live services in this session.

### Cited Findings

**Snippet 1 — Create a TheHive alert with observables and promote it to a case (thehive4py)**
Source: adapted from [thehive4py alert examples](https://thehive-project.github.io/TheHive4py/latest/examples/alert/) and [quickstart](https://thehive-project.github.io/TheHive4py/latest/). `pip install thehive4py`
```python
from thehive4py import TheHiveApi
from thehive4py.query.filters import Eq

hive = TheHiveApi(url="http://localhost:9000", apikey="h1v3b33")

alert = hive.alert.create(
    alert={
        "type": "siem",                      # required
        "source": "elastic-security",        # required
        "sourceRef": "rule-1234:host-77:1762000000",  # required, unique dedupe ref
        "title": "Suspicious PowerShell download cradle",
        "description": "EQL rule matched on host-77",
        "severity": 3,                       # 1 low .. 4 critical
        "tags": ["powershell", "t1059.001"],
        "observables": [
            {"dataType": "ip", "data": "1.2.3.4"},
            {"dataType": "domain", "data": "example.com"},
        ],
    }
)
print("alert id:", alert["_id"])

# Escalate: promote the alert to a case
case = hive.alert.promote_to_case(alert_id=alert["_id"])
print("case number:", case["number"])

# Find all open alerts tagged powershell
for a in hive.alert.find(filters=Eq(field="tags", value="powershell")):
    print(a["title"], a["status"])
```

**Snippet 2 — Minimal Cortex analyzer with cortexutils (ILLUSTRATIVE, based on documented API)**
Based on method names documented at [StrangeBee, How to Write and Submit an Analyzer](https://docs.strangebee.com/cortex/api/how-to-create-an-analyzer/), [cortexutils repo](https://github.com/TheHive-Project/cortexutils) and the TheHive blog note on `summary()`/`build_taxonomy()` ([blog.thehive-project.org](https://blog.thehive-project.org/tag/misp/page/4)). Pair with a JSON service file (name, version, author, url, license, description, dataTypeList, command, baseConfig, configurationItems) and requirements.txt (`cortexutils`).
```python
#!/usr/bin/env python3
# File: IPReputation/ipreputation.py  (declared in "command" of the JSON service file)
import requests
from cortexutils.analyzer import Analyzer


class IPReputationAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        # read from "configurationItems" in the analyzer JSON definition
        self.api_key = self.get_param("config.api_key", None, "Missing api_key")

    def summary(self, raw):
        level = "malicious" if raw.get("score", 0) >= 70 else "safe"
        return {"taxonomies": [self.build_taxonomy(level, "IPRep", "Score", str(raw.get("score", 0)))]}

    def run(self):
        if self.data_type != "ip":
            self.error("This analyzer only supports the 'ip' data type")
        ip = self.get_data()
        r = requests.get(f"https://reputation.example/api/v1/ip/{ip}",
                         headers={"X-Api-Key": self.api_key}, timeout=10)
        if r.status_code != 200:
            self.error(f"Upstream error {r.status_code}")
        body = r.json()
        self.report({"ip": ip, "score": body.get("score", 0), "raw": body})


if __name__ == "__main__":
    IPReputationAnalyzer().run()
```

**Snippet 3 — Splunk SOAR playbook: geolocate an IP and act on the result (ILLUSTRATIVE, based on documented API)**
Based on [Splunk SOAR Cloud tutorial, Create a simple playbook](https://help.splunk.com/en/splunk-soar/soar-cloud/python-playbook-tutorial/playbook-api-tutorial/tutorial-create-a-simple-playbook-in-splunk-soar-cloud) and [Playbook automation API](https://help.splunk.com/splunk-soar/soar-cloud/python-playbook-api-reference/automation-api/playbook-automation-api). Runs only inside the SOAR playbook runtime.
```python
import phantom.rules as phantom
import json


def on_start(container):
    # collect2 pulls artifact fields: one parameter dict per artifact
    rows = phantom.collect2(container=container,
                            datapath=["artifact:*.cef.sourceAddress", "artifact:*.id"])
    parameters = [{"ip": r[0], "context": {"artifact_id": r[1]}} for r in rows if r[0]]
    if parameters:
        # actions run asynchronously; results arrive in the callback
        phantom.act("geolocate ip", parameters=parameters, callback=geolocate_ip_cb,
                    name="geolocate_ip_1")
    return


def geolocate_ip_cb(action=None, success=None, container=None, results=None, handle=None, **kwargs):
    if not success:
        phantom.debug("geolocate ip failed")
        return
    for result in results:
        for item in result.get("action_results", []):
            data = item.get("data", [{}])[0]
            country = data.get("country_name")
            phantom.debug(f"{item['parameter']['ip']} -> {country}")
            if country not in ("United States", "Thailand"):
                phantom.set_severity(container, "high")
                phantom.add_tags(container, tags="foreign-geo")
    return


def on_finish(container, summary):
    phantom.debug(json.dumps(summary, indent=2))
    return
```

**Snippet 4 — Cortex XSOAR automation script skeleton**
Adapted from [XSOAR Script Code Snippets](https://cortex-docs.paloaltonetworks.com/python-development-quick-start-guide/cortex-xsoar-python-development-quick-start-guide/script-code-snippets) and [Code Conventions](https://xsoar.pan.dev/docs/integrations/code-conventions). Runs inside XSOAR's Python docker runtime.
```python
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401


def score_alert(args: dict) -> CommandResults:
    severity = int(args.get("severity", 1))
    asset_criticality = int(args.get("asset_criticality", 1))   # 1..5
    ti_hits = int(args.get("ti_hits", 0))
    score = min(100, severity * 10 + asset_criticality * 8 + ti_hits * 15)
    verdict = "escalate" if score >= 60 else "auto-close"
    outputs = {"Score": score, "Verdict": verdict}
    return CommandResults(
        outputs_prefix="AlertTriage",
        outputs_key_field="Score",
        outputs=outputs,
        readable_output=tableToMarkdown("Alert triage", outputs),
    )


def main():
    try:
        res = score_alert(demisto.args())
        return_results(res)
        if res.outputs["Verdict"] == "auto-close":
            demisto.executeCommand("closeInvestigation", {"closeReason": "False Positive"})
    except Exception as e:
        return_error(f"Failed to execute ScoreAlert. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
```

**Snippet 5 — Shuffle Python app (AppBase)**
Adapted from [Shuffle shuffle-docs/docs/apps.md](https://github.com/Shuffle/shuffle-docs/blob/master/docs/apps.md) (class/`__init__` pattern verbatim from the docs) and [shuffle-sdk on PyPI](https://pypi.org/project/shuffle-sdk/0.0.8/). `pip install shuffle-sdk`; `app_name` must match `name` in api.yaml, which declares each method as an action with parameters.
```python
import json
import hashlib
from shuffle_sdk import AppBase   # older apps: from walkoff_app_sdk.app_base import AppBase


class AlertTools(AppBase):
    __version__ = "1.0.0"
    app_name = "alert_tools"  # this needs to match "name" in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """Each app should have this __init__ to set up Redis and logging."""
        super().__init__(redis, logger, console_logger)

    def fingerprint(self, alert_json, fields="rule_id,host,user"):
        """Build a dedupe key from selected alert fields (action exposed in api.yaml)."""
        alert = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
        parts = [str(alert.get(f, "")) for f in fields.split(",")]
        key = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        return {"fingerprint": key, "fields": parts}

    def risk_score(self, severity, asset_criticality="1", ti_hits="0"):
        score = int(severity) * 10 + int(asset_criticality) * 8 + int(ti_hits) * 15
        return {"score": min(score, 100), "escalate": score >= 60}


if __name__ == "__main__":
    AlertTools.run()
```

**Snippet 6 — Sliding-window deduplication and risk scoring (ILLUSTRATIVE, pure Python)**
Design informed by the dedupe-key guidance in [Security Scientist](https://www.securityscientist.net/blog/12-questions-and-answers-about-alert-deduplication/) and the composite-scoring/feedback pattern in [Deepwatch](https://www.deepwatch.com/glossary/automated-incident-triage/). No external deps.
```python
import hashlib, time
from collections import deque, defaultdict

WINDOW_SECONDS = 600          # 10-minute sliding window
ASSET_CRIT = {"dc01": 5, "web-prod": 4, "lab-vm": 1}

class Deduper:
    def __init__(self, window=WINDOW_SECONDS):
        self.window, self.seen = window, defaultdict(deque)   # fingerprint -> timestamps

    @staticmethod
    def fingerprint(a):
        key = f"{a['rule_id']}|{a.get('host','')}|{a.get('user','')}|{a.get('src_ip','')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def observe(self, a, now=None):
        now = now or time.time(); fp = self.fingerprint(a); q = self.seen[fp]
        while q and now - q[0] > self.window:      # evict old timestamps
            q.popleft()
        q.append(now)
        return fp, len(q)                           # count within window

def risk_score(a, repeats, fp_history):
    base = {"low": 10, "medium": 30, "high": 60, "critical": 85}[a["severity"]]
    score = base + 8 * ASSET_CRIT.get(a.get("host"), 2) + 15 * a.get("ti_hits", 0)
    score += min(10, 2 * (repeats - 1))             # burst bonus, capped
    score -= 25 * fp_history.get(a["rule_id"], 0)   # analyst FP rate 0..1 feedback
    return max(0, min(100, int(score)))

def route(a, score, repeats):
    if repeats > 1: return "merge-into-existing"
    if score < 25:  return "auto-close:known-benign"
    return "escalate:create-case" if score >= 60 else "queue:analyst-review"

if __name__ == "__main__":
    d, fp_rate = Deduper(), {"R-1001": 0.9}
    alerts = [{"rule_id": "R-1001", "host": "lab-vm", "user": "svc", "severity": "medium"},
              {"rule_id": "R-2002", "host": "dc01", "user": "admin", "severity": "high", "ti_hits": 1},
              {"rule_id": "R-2002", "host": "dc01", "user": "admin", "severity": "high", "ti_hits": 1}]
    for a in alerts:
        fp, n = d.observe(a); s = risk_score(a, n, fp_rate)
        print(fp, n, s, route(a, s, n))
```

**Snippet 7 — Consume Elastic Security alerts with elasticsearch-py and enrich with a reputation lookup (ILLUSTRATIVE)**
Based on [Elastic Python client getting started](https://www.elastic.co/docs/reference/elasticsearch/clients/python/getting-started) (client/search API) and the [Elastic Security alert schema](https://www.elastic.co/guide/en/security/8.18/alert-schema.html) (`.alerts-security.alerts-*`, `kibana.alert.*`, use `fields` not `_source`). `pip install elasticsearch requests`
```python
import os, requests
from elasticsearch import Elasticsearch

client = Elasticsearch(os.environ["ELASTIC_URL"], api_key=os.environ["ELASTIC_API_KEY"])

def fetch_open_alerts(size=50):
    resp = client.search(
        index=".alerts-security.alerts-default",
        size=size,
        query={"bool": {"filter": [
            {"term": {"kibana.alert.workflow_status": "open"}},
            {"range": {"@timestamp": {"gte": "now-15m"}}}]}},
        fields=["kibana.alert.rule.name", "kibana.alert.severity",
                "kibana.alert.risk_score", "host.name", "source.ip"],
        _source=False,
    )
    return [h["fields"] for h in resp["hits"]["hits"]]

def reputation(ip):
    # Replace with VirusTotal / AbuseIPDB / OTX; marked illustrative
    r = requests.get(f"https://reputation.example/api/v1/ip/{ip}",
                     headers={"X-Api-Key": os.environ.get("REP_KEY", "")}, timeout=10)
    return r.json().get("score", 0) if r.ok else 0

if __name__ == "__main__":
    for f in fetch_open_alerts():
        ip = (f.get("source.ip") or [None])[0]
        rep = reputation(ip) if ip else 0
        print(f["kibana.alert.rule.name"][0], f["kibana.alert.severity"][0],
              f.get("host.name", ["?"])[0], ip, "rep=", rep)
```

**Snippet 8 — Escalate to a Jira ticket with the jira library**
Adapted from [jira.readthedocs.io examples](https://jira.readthedocs.io/examples.html). `pip install jira`
```python
import os
from jira import JIRA

jira = JIRA(server=os.environ["JIRA_URL"],
            basic_auth=(os.environ["JIRA_EMAIL"], os.environ["JIRA_API_TOKEN"]))  # Jira Cloud
# Self-hosted / Data Center alternative: JIRA(server=..., token_auth=os.environ["JIRA_PAT"])

def escalate(alert: dict, score: int):
    jql = f'project=SOC AND labels="fp-{alert["fingerprint"]}" AND statusCategory != Done'
    existing = jira.search_issues(jql)
    if existing:                                   # dedupe at the ticket layer too
        jira.add_comment(existing[0], f"Recurrence observed. Current score {score}.")
        return existing[0].key
    issue = jira.create_issue(fields={
        "project": {"key": "SOC"},
        "summary": f"[{alert['severity'].upper()}] {alert['rule_name']} on {alert['host']}",
        "description": f"Score: {score}\nFingerprint: {alert['fingerprint']}\n{alert['description']}",
        "issuetype": {"name": "Task"},
        "labels": ["soc-auto", f"fp-{alert['fingerprint']}"],
        "priority": {"name": "High" if score >= 60 else "Medium"},
    })
    return issue.key

if __name__ == "__main__":
    print(escalate({"fingerprint": "ab12cd34", "severity": "high", "rule_name": "Credential dumping",
                    "host": "dc01", "description": "LSASS access by procdump"}, 82))
```

**Snippet 9 — FastAPI webhook receiver that normalizes vendor alerts to an OCSF Detection Finding (ILLUSTRATIVE)**
Field set follows the required/recommended attributes of OCSF `detection_finding` (class_uid 2004, type_uid = class_uid*100 + activity_id) at [schema.ocsf.io](https://schema.ocsf.io/classes/detection_finding) and [Tenzir OCSF reference](https://docs.tenzir.com/reference/ocsf/1-4-0/classes/detection_finding). `pip install fastapi uvicorn`
```python
import time, uuid
from fastapi import FastAPI, Request

app = FastAPI()
SEV = {"low": 2, "medium": 3, "high": 4, "critical": 5}   # OCSF severity_id

def to_ocsf(vendor: str, a: dict) -> dict:
    activity_id = 1                                       # 1 = Create
    return {
        "class_uid": 2004, "category_uid": 2, "activity_id": activity_id,
        "type_uid": 2004 * 100 + activity_id,              # 200401
        "time": int(time.time() * 1000),
        "severity_id": SEV.get(str(a.get("severity", "low")).lower(), 1),
        "metadata": {"version": "1.9.0", "product": {"vendor_name": vendor},
                     "uid": str(uuid.uuid4())},
        "finding_info": {"uid": str(a.get("id", uuid.uuid4())),
                         "title": a.get("rule_name") or a.get("title", "untitled"),
                         "analytic": {"name": a.get("rule_id", "unknown"), "type": "Rule"}},
        "is_alert": True, "status_id": 1,                  # 1 = New
        "message": a.get("description", ""),
        "observables": [{"name": "source.ip", "type_id": 2, "value": a["src_ip"]}]
                        if a.get("src_ip") else [],
        "unmapped": {k: v for k, v in a.items() if k not in
                     ("id", "severity", "rule_name", "title", "rule_id", "description", "src_ip")},
    }

@app.post("/webhook/{vendor}")
async def receive(vendor: str, request: Request):
    payload = await request.json()
    finding = to_ocsf(vendor, payload)
    # TODO: enqueue finding -> dedupe/score (Snippet 6) -> TheHive/Jira (Snippets 1, 8)
    return {"accepted": True, "type_uid": finding["type_uid"], "uid": finding["metadata"]["uid"]}
# run: uvicorn app:app --port 8080  ;  curl -XPOST localhost:8080/webhook/wazuh -d '{"severity":"high","rule_id":"5712","src_ip":"1.2.3.4"}' -H 'content-type: application/json'
```

**Snippet 10 — StackStorm Python action (near-verbatim from docs)**
Source: [docs.stackstorm.com/actions.html](https://docs.stackstorm.com/actions.html). YAML metadata (`my_echo_action.yaml`): `name: "echo_action"`, `runner_type: "python-script"`, `entry_point: "my_echo_action.py"`, `parameters: {message: {type: string, required: true, position: 0}}`.
```python
import sys

from st2common.runners.base_action import Action

class MyEchoAction(Action):
    def run(self, message):
        print(message)

        if message == 'working':
            return (True, message)
        return (False, message)
```

**Snippet 11 — Wazuh custom active response skeleton (condensed from the documented sample)**
Source structure and constants from [Wazuh docs, Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html); deployed to the agent's active-response/bin and bound via `<command>`/`<active-response>` in ossec.conf (e.g., `<rules_id>503</rules_id><timeout>60</timeout>`).
```python
#!/usr/bin/env python3
import sys, json, datetime
from pathlib import PureWindowsPath, PurePosixPath

LOG_FILE = "/var/ossec/logs/active-responses.log"
ADD_COMMAND, DELETE_COMMAND, CONTINUE_COMMAND, ABORT_COMMAND = 0, 1, 2, 3

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(f"{datetime.datetime.now()} {ar_name}: {msg}\n")

def main(argv):
    raw = sys.stdin.readline()
    data = json.loads(raw)
    command = {"add": ADD_COMMAND, "delete": DELETE_COMMAND}.get(data.get("command"), ABORT_COMMAND)
    alert = data.get("parameters", {}).get("alert", {})
    if command == ADD_COMMAND:
        keys = [alert.get("rule", {}).get("id")]
        keys_msg = json.dumps({"version": 1, "origin": {"name": argv[0], "module": "active-response"},
                               "command": "check_keys", "parameters": {"keys": keys}})
        write_debug_file(argv[0], keys_msg); print(keys_msg, flush=True)
        answer = json.loads(sys.stdin.readline()).get("command")
        if answer != "continue":
            write_debug_file(argv[0], "aborted by manager"); sys.exit(0)
        # --- the actual response goes here (e.g., block src_ip, isolate host) ---
        write_debug_file(argv[0], f"ADD for rule {keys[0]} src {alert.get('data', {}).get('srcip')}")
    elif command == DELETE_COMMAND:
        write_debug_file(argv[0], "DELETE: reverting action after timeout")
    else:
        write_debug_file(argv[0], "invalid command"); sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
```

### Inferences
- Snippets 9 -> 6 -> 1/8 chain into a complete minimal "Module 6" project: webhook ingest + OCSF normalization, dedupe/score, then case (TheHive) or ticket (Jira), with Cortex (Snippet 2) providing enrichment and Wazuh/StackStorm/Shuffle (Snippets 11/10/5) providing response actions.
- The vendor runtimes (Splunk SOAR, XSOAR, Shuffle, StackStorm, Wazuh) cannot be executed locally with plain `python`; students need the platform (all except Splunk SOAR/XSOAR are free/open-source).

### Gaps
- Snippets marked ILLUSTRATIVE have not been executed against live platforms; parameter names for `phantom.set_severity`/`phantom.add_tags` and XSOAR's `closeInvestigation` arguments were taken from general knowledge of those APIs and should be verified against the current vendor references before use in class.
- Could not fetch a verbatim official Cortex analyzer code sample (the StrangeBee how-to page only exposed the JSON definition in this session); Snippet 2 follows documented method names.
