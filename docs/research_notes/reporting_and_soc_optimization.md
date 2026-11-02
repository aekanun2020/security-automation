# Module 6 – Automated Reporting and Security Operations Optimization (research notes)

Research date: 2026-11-01. GitHub star counts were pulled live from the GitHub REST API (`https://api.github.com/repos/<owner>/<repo>`) on 2026-11-01 and rounded; all documentation URLs marked "verified live" returned HTTP 200 on that date. Code snippets are marked either with a source URL or as *illustrative, written from the documented API* (not copied from any source).

---

## Key Question 1: Which libraries and formats are standard for automated security reporting, and where are they documented?

### Takeaway
The de-facto Python reporting stack is pandas (data) → Jinja2 (HTML templating) → WeasyPrint or ReportLab (PDF), with python-docx / python-pptx for Office deliverables, matplotlib / plotly for charts, and Streamlit for live dashboards; SIEM-side reporting goes through the Kibana Reporting endpoints (internal, unstable) or the Grafana Enterprise `/api/reports` API, and ATT&CK coverage is exchanged as Navigator layer JSON (layer format 4.5).

### Cited Findings

**Templating and PDF generation**
- Jinja2 official documentation (Pallets) is at the stable URL; repo `pallets/jinja` has ≈11.8k stars (last push 2025-06-14) — [Jinja2 docs](https://jinja.palletsprojects.com/en/stable/) (verified live); [GitHub API star count](https://api.github.com/repos/pallets/jinja)
- WeasyPrint ("The awesome document factory", HTML/CSS → PDF) official docs; repo `Kozea/WeasyPrint` ≈9.8k stars, last push 2026-10-30 — [WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/) (verified live); [GitHub](https://github.com/Kozea/WeasyPrint)
- ReportLab official documentation portal and the ReportLab User Guide PDF (the canonical reference for `canvas`, `platypus` flowables, `SimpleDocTemplate`, `Table`) — [docs.reportlab.com](https://docs.reportlab.com/) (verified live); [ReportLab User Guide PDF](https://www.reportlab.com/docs/reportlab-userguide.pdf) (verified live)
- Markdown-to-PDF: Pandoc's user manual is the reference for `pandoc report.md -o report.pdf` (requires a LaTeX or wkhtmltopdf/weasyprint engine via `--pdf-engine`) — [Pandoc MANUAL](https://pandoc.org/MANUAL.html) (verified live)

**Office formats**
- python-docx ("Create and modify Word documents with Python") official docs; repo `python-openxml/python-docx` ≈5.8k stars, last push 2026-08-01 — [python-docx docs](https://python-docx.readthedocs.io/en/latest/) (verified live); [GitHub](https://github.com/python-openxml/python-docx)
- python-pptx official docs; repo `scanny/python-pptx` ≈3.6k stars — [python-pptx docs](https://python-pptx.readthedocs.io/en/latest/) (verified live); [GitHub](https://github.com/scanny/python-pptx)

**Charts, data and dashboards**
- matplotlib stable docs; repo ≈23.4k stars — [matplotlib docs](https://matplotlib.org/stable/) (verified live); [GitHub](https://github.com/matplotlib/matplotlib)
- plotly.py docs ("The interactive graphing library for Python"); repo ≈18.9k stars — [plotly python docs](https://plotly.com/python/) (verified live); [GitHub](https://github.com/plotly/plotly.py)
- pandas docs — [pandas docs](https://pandas.pydata.org/docs/) (verified live)
- Streamlit ("A faster way to build and share data apps") docs; repo ≈46.2k stars, last push 2026-11-01 — [Streamlit docs](https://docs.streamlit.io/) (verified live); [GitHub](https://github.com/streamlit/streamlit)

**SIEM / observability reporting APIs**
- Kibana: report generation is automated by POSTing to `/api/reporting/generate/<exportType>?jobParams=<rison>` (e.g. `/api/reporting/generate/printablePdfV2?jobParams=...`); every POST needs the `kbn-xsrf` header; requests can be authenticated with API keys instead of session cookies; Kibana returns 200 when the job is *queued* "even if the job somehow fails later"; PDF/PNG generation needs a Kibana instance with at least 2 GB RAM — [Elastic docs: Automating report generation](https://www.elastic.co/docs/explore-analyze/report-and-share/automating-report-generation) (verified live); [Kibana legacy guide](https://www.elastic.co/guide/en/kibana/current/automating-report-generation.html)
- Kibana reporting integration docs warn these are internal APIs "not guaranteed to be supported across future versions of Kibana" — [Reporting integration](https://www.elastic.co/pt/guide/en/kibana/current/reporting-integration.html)
- Grafana: scheduled PDF/CSV/image reports are created with `POST /api/reports` (requires `reports:create`, `Authorization: Bearer <SERVICE_ACCOUNT_TOKEN>`), body includes `name`, `recipients`, `schedule{startDate,endDate,frequency}`, `dashboards[].dashboard.uid`, `formats[]` (`pdf` default, also `csv`, `image`); "only available in Grafana Enterprise"; the API "is not stabilized yet and may change without prior notice"; Grafana 13 deprecates `/api` in favour of `/apis` — [Grafana Reporting HTTP API (next)](https://grafana.com/docs/grafana/next/developers/http_api/reporting/); [v12.4 reference](https://grafana.com/docs/grafana/v12.4/developer-resources/api-reference/http-api/reporting.md)

**ATT&CK layer format and ATT&CK data access**
- The ATT&CK Navigator Layer File Format v4.5 defines required fields `name` (string) and `domain` (one of `enterprise-attack`, `mobile-attack`, `ics-attack`); optional `description`, `versions{attack, navigator, layer}` where `versions.layer` "Must be '4.5'" and `versions.navigator` "Must be at least '4.9.0'"; `techniques[]` objects carry `techniqueID` ("T####" or "T####.###"), optional `tactic` (e.g. "lateral-movement"; omitted → annotation appears under every tactic), `score` (number; omitted = unscored, no gradient colour), `color` (overrides score colour), `comment`, `enabled`, `showSubtechniques`, `metadata[]`, `links[]`; `gradient` defaults to red→green with minValue 0, maxValue 100; `sorting` 0–3; `hideDisabled`; `legendItems[]`; `filters.platforms[]` — [Layer format v4.5 spec](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md) (verified live; raw text read 2026-11-01)
- ATT&CK Navigator web app and repo (`mitre-attack/attack-navigator`, ≈2.5k stars, last push 2026-11-01) — [Navigator app](https://mitre-attack.github.io/attack-navigator/); [GitHub](https://github.com/mitre-attack/attack-navigator)
- `mitreattack-python` (≈755 stars) is MITRE's official Python module for ATT&CK STIX data; docs are on Read the Docs; `mitre-attack/attack-stix-data` (≈707 stars) hosts the STIX 2.1 bundles — [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/) (verified live); [attack-stix-data](https://github.com/mitre-attack/attack-stix-data); [ATT&CK resources](https://attack.mitre.org/resources/)

**Vulnerability scoring specs used in reports**
- CVSS v4.0 specification is hosted by FIRST; secondary summaries describe four metric groups (Base, Threat, Environmental, Supplemental), the nomenclature CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE that "should be used wherever a numerical CVSS value is displayed or communicated", and that Supplemental metrics (Automatable, Value Density, Recovery, Provider Urgency, Vulnerability Response Effort, Safety) "do not modify the final score" — [CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document) (verified live); [CVSS v4.0 landing](https://www.first.org/cvss/v4-0/); summary via [Sysdig](https://www.sysdig.com/blog/cvss-version-4-0-whats-new) and [Qualys](https://blog.qualys.com/product-tech/2023/11/02/cvss-v4-is-now-live-and-what-do-you-need-to-know)
- EPSS REST API: endpoint `https://api.first.org/data/v1/epss` (status "BETA"); parameters `cve` (comma-separated, max 2000 characters), `date` (YYYY-MM-DD, history since 2021-04-14), `days`, `epss-gt`, `epss-lt`, `percentile-gt`, `percentile-lt`, `q` (partial CVE match), `scope=public|time-series` (time-series returns last 30 days); response fields `cve`, `epss`, `percentile`, `date` inside `data[]` with `status`, `total`, `offset`, `limit` — [FIRST API docs: GET /epss](https://api.first.org/epss/) (verified live; the older page `first.org/epss/api` now returns 404)
- Live check 2026-11-01: `GET /data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400` returned `epss 0.99999`, `percentile 1.0`, `date 2026-11-01` for both — [EPSS API](https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400&pretty=true)
- EPSS home and the probability/percentile explainer — [EPSS](https://www.first.org/epss/) (verified live); [Probability vs percentile article](https://www.first.org/epss/articles/prob_percentile_bins) (verified live)

**Jupyter / notebook ecosystem for security reporting**
- msticpy ("Microsoft Threat Intelligence Security Tools"; ≈2.0k stars) is "a library for InfoSec investigation and hunting in Jupyter Notebooks", originally for Azure Sentinel, now with providers for Splunk, M365 Defender, Microsoft Graph, Sumo Logic and the OTRF Security Datasets — [msticpy docs](https://msticpy.readthedocs.io/); [GitHub](https://github.com/microsoft/msticpy)
- Open Threat Research (Roberto Rodriguez et al.): `OTRF/ThreatHunter-Playbook` (≈4.7k stars, "community-driven, open-source project to share detection logic, adversary tradecraft" with notebooks mapped to ATT&CK) and `OTRF/infosec-jupyter-book` ("The Infosec Community Definitive Guide to Jupyter Notebooks", ≈134 stars, last push 2020-10-17, site live at infosecjupyterbook.com) — [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook); [infosec-jupyter-book](https://github.com/OTRF/infosec-jupyter-book); [infosecjupyterbook.com](https://infosecjupyterbook.com/) (verified live, content rendered client-side so not readable by fetch)

### Inferences
- Because Kibana's reporting endpoints are explicitly internal and Grafana's `/api/reports` is Enterprise-only and "not stabilized", a course project is more portable if it pulls raw data (Elasticsearch/Grafana data-source queries, SIEM exports) into pandas and renders with Jinja2 + WeasyPrint, using the SIEM APIs only as optional integrations.
- Navigator layer JSON is the lingua franca of coverage reporting: DeTT&CT, Splunk Detection Studio-style tooling, and hand-rolled scripts all emit it, so teaching the v4.5 schema once pays off across the module.
- The EPSS API accepts up to 2000 characters in `cve`, i.e. roughly 130 CVE IDs per call; batching is required for larger scan exports.

### Gaps
- I could not retrieve the full text of the CVSS v4.0 specification (page is JS-heavy; summary came from Sysdig/Qualys/IriusRisk write-ups). Document version number (reported as v1.2, 2023-11-01 by a mirror) should be verified on first.org.
- The current EPSS model version (v4, reported released March 2025 in general industry coverage) could not be confirmed from first.org pages during this session (the `/epss/model` page returned 404); treat the model version as unverified.
- Kibana `jobParams` schema was not found in docs; Elastic recommends copying the POST URL from the UI (Share → Export → Copy POST URL).

---

## Key Question 2: What report types does a SOC produce and what sources define their contents?

### Takeaway
Authoritative content expectations come from NIST SP 800-61 Rev. 3 (incident reporting, follow-up reports and lessons learned mapped to CSF 2.0 subcategories), MITRE's 11 Strategies (Strategy 10, measurement for improvement), SOC-CMM's Reporting aspect and Metrics 101 suite (shift handover completeness, reports on time, regulatory reporting within deadline), SANS incident-handling forms and the SRE postmortem culture; compliance evidence is framed by PCI DSS v4.0.1 Requirement 10 (daily log review) and 12.10 (IR plan testing), and ISO/IEC 27001:2022 clause 9.1 (monitoring, measurement, analysis, evaluation).

### Cited Findings

**Incident reports and post-mortems**
- NIST SP 800-61 Rev. 3, "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile", final 2025-04-03, authors Alexander Nelson, Sanjay Rekhi, Murugiah Souppaya (NIST) and Karen Scarfone; supersedes Rev. 2 (2012); DOI 10.6028/NIST.SP.800-61r3 — [CSRC record](https://csrc.nist.gov/pubs/sp/800/61/r3/final); [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf); [NIST news release](https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations)
- Rev. 3 replaces the Rev. 2 four-phase life cycle (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity) with a model based on the six CSF 2.0 Functions; Table 1 maps old phases to Functions, Table 2 is "CSF 2.0 Community Profile part 1: Preparation and Lessons Learned", Table 3 is "part 2: Incident Response"; "Detect, Respond, and Recover help organizations discover, … perform incident reporting, notification, and other incident-related communications"; lessons learned from all Functions feed the Improvement category (ID.IM) — [SP 800-61r3 PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf) (text extracted 2026-11-01)
- Rev. 3 recommendations are numbered per CSF subcategory (e.g. "GV.OC-03.R1"); GV.OC-03 covers legal/regulatory obligations including "notifications, data breach reporting"; ID.IM-03 covers improvements identified "when creating follow-up reports for incidents or holding 'lessons learned'" sessions; RS.MA-02 states "Incident reports are triaged and validated" — [SP 800-61r3 PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
- NIST CSF 2.0 (NIST CSWP 29, Feb 2024) is the parent framework (Govern, Identify, Protect, Detect, Respond, Recover) — [NIST CSF 2.0 PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) (verified live)
- SANS publishes incident-handling forms (e.g. "IH-Identification") under its SCORE project; the SANS "Incident Handler's Handbook" by Patrick Kral defines the six handling phases that vendor playbooks (e.g. Palo Alto Cortex XSOAR "SANS – Lessons Learned" playbook) encode — [SANS IH-Identification form](https://www.sans.org/media/score/incident-forms/IH-Identification.pdf); [XSOAR SANS Lessons Learned playbook](https://demisto.pan.dev/docs/reference/playbooks/sans---lessons-learned)
- Lenny Zeltser's widely shared "Report Template for Incident Response" is organised around "high-level categories in anticipation of what the report's readers expect to see" — [zeltser.com](https://zeltser.com/incident-response-report-template)
- Google SRE book, "Postmortem Culture: Learning from Failure" (blameless postmortems, action items, timeline) is the standard reference for post-incident review culture in operations teams — [SRE book: Postmortem Culture](https://sre.google/sre-book/postmortem-culture/) (URL from the SRE book site; chapter content not re-fetched this session)

**Shift handover, weekly metrics, management reports (SOC-CMM)**
- SOC-CMM "Metrics 101 – A best practice for performance measurement in the SOC" (©2024, 21 pages) states that "the SOC-CMM model includes the reporting and communication aspect, in the SOC-CMM process domain", that "metrics that provide an indication of risk within the organisation are most fitting" for management reporting, and that "Many operational metrics (like number of incidents) lack the right context to be meaningful to higher management" — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
- Metrics 101 defines each metric by Type ($ budget, % percentage, # absolute, timing, trend, ✔ KPI/KRI), Metric, Description, Level (L1→L2→L3 implementation order), Target, Differentiation (e.g. by severity, category, or per MSSP customer) — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
- Metrics 101 includes shift/reporting metrics: "% Completeness of shift [handover]" (L1), "% Percentage of reports [delivered …]" and "% Percentage of report contents created […]" (names truncated in text extraction; Reporting aspect), "% Reporting requirements met in a timely manner — the percentage of reportable incidents (i.e. legal obligation to report) reported within the obligatory time window" (L2, target 100%), "# Number of incidents incorrectly escalated" (L2, target 0) — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
- MITRE 11 Strategies, Strategy 10 "Measure Performance to Improve Performance" (pp. 301–318 per awesome-soc) is the cited basis for SOC metric reporting — [awesome-soc README](https://github.com/cyb3rxp/awesome-soc); [MITRE 11 Strategies](https://www.mitre.org/11strategies)

**Executive summaries and how reporting is actually done**
- SANS 2025 SOC Survey (9th annual, author Christopher Crowley, respondents from 57 countries): "69% of SOCs still rely on manual or mostly manual processes to report metrics"; the typical SOC "Reports metrics manually, even though nearly half say it's too time-consuming. Automation remains limited"; "42% of SOC staff don't know the SOC's budget"; "85% of respondents say endpoint security alerts are their primary trigger for response"; "42% of SOCs dump all incoming data into a SIEM, often without a retrieval or management plan"; "42% of SOCs use AI/ML tools 'out of the box' with no customization" — [SANS SOC Survey 2025 PDF (Elastic-hosted)](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf) (text extracted 2026-11-01)
- Gartner's 2025 research series includes "The Journey to SOC: Step 3 Building Reporting and Maturity Roadmaps" (24 Apr 2025) and "A Journey Guide to Building a Security Operations Center" (Pete Shoard, Eric Ahlm, 13 Mar 2025) — [Red Canary-hosted Gartner Journey Guide](https://redcanary.com/resources/guides/gartner-journey-guide-building-soc); [Gartner abstracts (paywalled)](https://www.gartner.com/en/documents/6389843)

**Compliance evidence**
- PCI DSS v4.0.1: Requirement 10.4.1 sets a daily review for defined log categories and 10.4.1.1 requires the review to use automated mechanisms (mandatory since 31 March 2025 per secondary sources); 10.4.2 allows other logs to be reviewed at a frequency set by targeted risk analysis; 12.10.2 requires the IR plan to be reviewed, updated, and tested at least once every 12 months; 12.10.5 covers monitoring and responding to alerts — [PCI SSC document library (official)](https://www.pcisecuritystandards.org/document_library/) (verified live); summaries via [Cloudaware PCI DSS 4.0.1 §10.4.1](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/10/04/01/) and [RSI Security](https://blog.rsisecurity.com/tracking-and-monitoring-under-pci-dss-requirement-10/)
- ISO/IEC 27001:2022 clause 9.1 (monitoring, measurement, analysis and evaluation) and ISO/IEC 27004 (measurement guidance) are the ISMS basis for SOC metric evidence — [ISO/IEC 27001](https://www.iso.org/standard/27001) (iso.org returned HTTP 403 to automated fetch; clause content from training knowledge, not re-verified)

### Inferences
- A practical taxonomy for the course: (1) shift handover (SOC-CMM "completeness of shift handover"), (2) weekly/monthly metrics report (SOC-CMM L1 metrics; MITRE Strategy 10), (3) incident report / post-mortem (NIST 800-61r3 RS.MA-02 incident reports, ID.IM-03 follow-up reports and lessons learned; SRE postmortem), (4) executive/board summary (SOC-CMM: risk-oriented metrics, not raw counts), (5) regulatory/compliance evidence (GV.OC-03 breach-reporting deadlines; PCI DSS 10.4.1 daily log review evidence; ISO 27001 9.1 records).
- The SANS finding that 69% of SOCs report metrics manually is the strongest single justification for the module's automated-reporting project.

### Gaps
- The exact section list of the SANS Incident Handler's Handbook report template was not retrievable (paywalled/registration PDF).
- Official PCI DSS v4.0.1 text was not fetched (document library requires acceptance of a license); requirement numbering came from vendor control-mapping sites that disagree slightly on where "automated mechanisms" sits (10.4.1 vs 10.4.1.1).
- No Forrester SOC-reporting guidance newer than the 2010 Information Security Maturity Model surfaced; Forrester material found was a 2021 Forrester Consulting study on SecOps automation — [Forrester ISMM blog](https://www.forrester.com/blogs/10-07-27-the_forrester_information_security_maturity_model/).

---

## Key Question 3: What SOC metrics and maturity models are authoritative, with original sources?

### Takeaway
The authoritative stack is: MITRE's *11 Strategies of a World-Class Cybersecurity Operations Center* (2022) for SOC design and Strategy 10 on measurement; SOC-CMM (Rob van Os, 2016, current spreadsheet v2.4.2, CC BY-SA 4.0) for maturity/capability assessment and its Metrics 101 suite for KPIs; NIST CSF 2.0 / SP 800-61r3 for the governance vocabulary; Kyle Bailey's Detection Engineering Maturity Matrix and Elastic's DEBMM for detection engineering maturity; and Mandiant M-Trends / Verizon DBIR / Red Canary / Expel for external benchmarks (dwell time, initial-access mix, top techniques).

### Cited Findings

**MITRE 11 Strategies (2022)**
- Published March 2022 as the second edition of "10 Strategies of a World-Class Cybersecurity Operations Center"; authors Kathryn Knerler, Ingrid Parker, Carson Zimmerman; free full book and 20-page summary; strategies: 1 Know What You Are Protecting and Why; 2 Give the SOC the Authority to Do Its Job; 3 Build a SOC Structure to Match Your Organizational Needs; 4 Hire and Grow Quality Staff; 5 Prioritize Incident Response; 6 Illuminate Adversaries with Cyber Threat Intelligence; 7 Select and Collect the Right Data; 8 Leverage Tools to Support Analyst Workflow; 9 Communicate Clearly, Collaborate Often, Share Generously; 10 Measure Performance to Improve Performance; 11 Turn up the Volume by Expanding SOC Functionality — [MITRE 11 Strategies page](https://www.mitre.org/11strategies); [Highlights PDF](https://www.mitre.org/sites/default/files/2022-04/11-strategies-world-class-csoc-highlights.pdf); [MITRE press release](https://www.mitre.org/news-insights/news-release/mitre-publishes-11-strategies-world-class-cybersecurity-operations); [Business Wire 2022-03-29](https://www.businesswire.com/news/home/20220329005299/en/MITRE-Publishes-11-Strategies-of-a-World-Class-Cybersecurity-Operations-Center)
- The soc-cmm.com homepage quotes the MITRE 11 Strategies book endorsing SOC-CMM — [soc-cmm.com](https://www.soc-cmm.com/)

**SOC-CMM**
- "SOC-CMM was launched in 2016 as the very first open standard for measuring and improving Security Operations Center maturity"; "Originating from a master's thesis, SOC-CMM has a strong scientific foundation"; it "has evolved from a methodology for SOC capability maturity assessment into a broader reference framework" with "an extensive metrics suite, an annual SOC maturity report, and a library of best practices"; SOC-CMM® is a registered trademark — [SOC-CMM introduction](https://www.soc-cmm.com/introduction)
- Current self-assessment downloads are named `soc-cmm-242-basic.xlsx` / `soc-cmm-242-advanced.xlsx` (i.e. v2.4.2); "All versions 2.x are compatible"; a SOC-CMM→NIST CSF mapping (v2.3) is provided; "The CC BY-SA 4.0 licence applies to most SOC-CMM products" — [SOC-CMM product page](https://www.soc-cmm.com/products/soc-cmm); downloads: [basic](https://www.soc-cmm.com/img/upload/files/62-soc-cmm-242-basic.xlsx), [advanced](https://www.soc-cmm.com/img/upload/files/63-soc-cmm-242-advanced.xlsx), [NIST CSF mapping](https://www.soc-cmm.com/img/upload/files/6-soc-cmm-23-nist-csf-mapping.xlsx)
- Rob van Os is "the creator of the SOC-CMM assessment methodology" — [SANS instructor profile](https://www.sans.org/profiles/rob-van-os); [Blueprint podcast](https://sans.org/podcasts/blueprint/maturing-your-cyber-defense-with-rob-van-os)
- Secondary sources agree on the five domains Business, People, Process, Technology, Services; all five receive a maturity score (0–5, continuous, "Non-existent" through "Optimizing", additive scoring) and Technology and Services additionally receive a capability score (0–3: Incomplete, Performed, Managed, Defined); aspect counts quoted vary (21/26/27) by version — [andrews.hu SOC-CMM overview](https://andrews.hu/en/blog/soc-cmm-model-security-operations-center-framework/); [CISO Tradecraft](https://cisotradecraft.substack.com/p/the-soc-assessment-tool-every-ciso); [original 2016 v1.1 guide (Scribd copy)](https://www.scribd.com/document/426096902/dd)
- SOC-CMM also publishes SOC-TOM (target operating model), a SOC metrics page and a benchmark, and runs a certification scheme and Discourse community — [SOC-TOM](https://soc-cmm.com/soc-tom/); [SOC metrics](https://www.soc-cmm.com/soc-metrics); [certification](https://certification.soc-cmm.com/); [community](https://soc-cmm.discourse.group/)

**SOC-CMM Metrics 101 – concrete metric definitions (2024)**
- Detection-engineering metrics: "% Percentage of false positives — The percentage of alerts that fired incorrectly" (L1, trend decreasing); "% Percentage of benign positives — alerts that fired correctly but were not a security incident" (L1); "# Number of rule tunings applied" (L2); "# Number of rules effectively tuned — rules that have seen a significant decrease in false positives after tuning" (L3); "# Number of false negatives — incidents that did not yield a corresponding alert" (L3, target 0); "Time to develop new detections" (L2, target 1 week) — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
- Coverage metrics: "% MITRE ATT&CK® coverage — The coverage of detection techniques against the organisation's MITRE ATT&CK® profile. Can be visualised using a heatmap" (L2, trend increasing); "% MITRE ATT&CK® visibility (data sources) — The potential coverage of MITRE ATT&CK® based on available data sources … (see: DETT&CT)" (L2) — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
- Operations metrics include "% Alerts not analysed", "% Percentage of alerts [escalated]", "# Number of false positive call outs to stand-by", "Time to respond to call-out (acknowledge time)", "# Monitoring coverage — the number of relevant assets", "% Availability of SOC", "% Capacity of SOC", "% Turnover rate", "# Number of open positions", "% Incidents closed without [...]", "% Compromise vector" — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)

**SANS**
- SANS SOC Metrics Cheat Sheet (Mark Orlando, 1 May 2025) recommends building metrics top-down from organisational mission and security goals and aligning to SOC-CMM "for a comprehensive measurement approach across SOC domains and aspects" — [SANS SOC Metrics Cheat Sheet](https://www.sans.org/posters/soc-metrics-cheat-sheet)
- SANS 2025 SOC Survey: EDR is "the most trusted and mature tool in use. AI/ML is at the bottom of the satisfaction list"; threat hunting is mostly "partially automated hunting using vendor-provided tools (48%)"; lack of skilled staff is the top barrier to sophisticated hunting (16%); "62% of respondents express a clear lack of confidence" in retention — [SANS SOC Survey 2025 PDF](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf); vendor summaries: [Dropzone](https://content.dropzone.ai/2025-sans-soc-survey-report), [Prophet Security](https://resources.prophetsecurity.ai/sans-soc-survey-2025)
- The 2023 SANS SOC Survey reported that 84% of SOCs collect metrics — [Anomali summary of SANS 2023](https://anomali.com/resources/whitepapers/sans-2023-soc-survey)
- SANS 2026 Detection Engineering Survey (307 practitioners) and a Feb 2025 SANS/Anvilogic webcast covered metrics for detection effectiveness — [SANS/Anvilogic webcast](https://sans.org/webcasts/insights-into-detection-engineering-findings-from-a-sans-and-anvilogic-survey); [SANS white papers index](https://www.sans.org/white-papers/)

**Detection engineering maturity**
- Kyle Bailey's Detection Engineering Maturity Matrix (published Apr 2021, last updated Sep 2022): three levels "Defined", "Managed", "Optimized"; dimensions People (Leadership, Team), Process (Detection Process, Metrics), Technology (Detection-as-Code, SIEM, Visibility), Detection (Detection Content, Response Experience, Threat Operations); the site notes it "needs to be updated to include AI" — [detectionengineering.io](https://detectionengineering.io/) (verified live); [GitHub source](https://github.com/k-bailey/detection-engineering-maturity-matrix/blob/main/index.md)
- Elastic's Detection Engineering Behavior Maturity Model (DEBMM), 6 Sep 2024, by Mika Ayenson, Terrance DeJesus, Samir Bousseaden: five tiers (Tier 0 Foundation, 1 Basic, 2 Intermediate, 3 Advanced, 4 Expert), each criterion scored across Initial/Repeatable/Defined/Managed/Optimized; Tier 2 includes "Continuously Tuning and Reducing False Positives" and "Understanding and Documenting Gaps", Tier 3 "Triaging False Negatives", "External Validation", "Advanced TTP Coverage"; it names the Detection Engineering Maturity Matrix as the closest related model — [Elastic Security Labs DEBMM](https://www.elastic.co/security-labs/elastic-releases-debmm)
- `infosecB/awesome-detection-engineering` (≈1.4k stars) curates detection-engineering resources — [GitHub](https://github.com/infosecB/awesome-detection-engineering)

**Google SRE concepts applied to SOCs**
- SRE book "Eliminating Toil": toil is work that is manual, repetitive, automatable, tactical, without enduring value and scales linearly with service growth; "Our SRE organization has an advertised goal of keeping operational work (i.e., toil) below 50% of each SRE's time"; "Toil becomes toxic when experienced in large quantities" (burnout, stalled careers, attrition) — [SRE book: Eliminating Toil](https://sre.google/sre-book/eliminating-toil/)
- SRE book "Service Level Objectives" (SLIs, SLOs, SLAs, error budgets) — [SRE book: SLOs](https://sre.google/sre-book/service-level-objectives/) (verified live)

**External benchmarks**
- Mandiant M-Trends 2025 (covering 2024): global median dwell time 11 days (up from 10 in 2023; 16 in 2022); 26 days when an external entity notified, 5 days when the adversary notified (mostly ransomware), 10 days for internal detection — [Google Cloud M-Trends 2025 blog](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/)
- Mandiant M-Trends 2026 (covering 2025): global median dwell time 14 days (up from 11); espionage/North-Korean IT-worker cases median 122 days — [Google Cloud M-Trends 2026 blog](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026); [M-Trends executive edition](https://cloud.google.com/security/resources/m-trends-executive-edition)
- Verizon 2025 DBIR: >22,000 incidents, 12,195 confirmed breaches; vulnerability exploitation as initial access in ~20% of breaches (+34% YoY), credential abuse 22%, phishing 16%; ransomware present in 44% of breaches; third-party involvement 30%; median ransom payment $115,000; 64% of victims did not pay — [Verizon 2025 DBIR news release](https://verizon.com/about/news/2025-data-breach-investigations-report); [Tenable summary](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025)
- Verizon 2026 DBIR (current edition on the DBIR page): 31% of breaches now start with software vulnerabilities (ahead of stolen passwords); 48% of breaches involve ransomware "but payouts are shrinking"; 15% of attack techniques bolstered by generative AI — [Verizon DBIR hub](https://www.verizon.com/business/resources/reports/dbir/)
- Red Canary 2026 Threat Detection Report methodology: 305 PB of telemetry from 1,700 organisations in 2025; 110,000 confirmed threats (34,000 higher-severity); detection analytics are mapped to ATT&CK techniques to track technique prevalence; threats ranked by number of customers affected — [Red Canary methodology](https://redcanary.com/threat-detection-report/methodology/)
- Red Canary top-10 techniques (2025 data): T1078.004 Cloud Accounts; T1059.001 PowerShell; T1059.003 Windows Command Shell; T1530 Data from Cloud Storage; T1105 Ingress Tool Transfer; T1114.003 Email Forwarding Rule; T1047 WMI; T1204.004 Malicious Copy and Paste; T1564.008 Email Hiding Rules; T1027 Obfuscated Files or Information — [Red Canary techniques](https://redcanary.com/threat-detection-report/techniques/)
- Red Canary 2025 report (2024 data): ~93,000 threats from >308 PB — [Red Canary 2025 report coverage](https://itbrief.com.au/story/red-canary-warns-of-surge-in-identity-ai-threats-for-2025)
- Expel Annual Threat Report 2025 (4th year, released 2025-02-04, built from a full year of Expel SOC data) and a 2026 edition covering 2025 — [Expel ATR 2025 PDF](https://expel.com/wp-content/uploads/2025/01/Expel-Annual-Threat-Report-2025-013025.pdf); [Expel blog](https://expel.com/blog/its-here-expels-2025-annual-threat-report/); [Expel annual report hub](https://expel.com/annual-report/)
- Expel defines its headline service metric as "the median time from alert arrival in Workbench to the first remediation action completed", split by whether customer verification is needed; Expel states a median analyst triage time of 3 minutes — [Expel Service Review Dashboard Metrics](https://support.expel.io/hc/en-us/articles/7228662328083-Service-Review-Dashboard-Metrics)

**Gartner**
- Gartner's SOC Model Guide (summary translation dated 9 Jan 2024) addresses build vs. outsource vs. hybrid SOC models; "Choose the Right Tools in Your Security Operations Maturity Journey" (21 Jan 2025); Hype Cycle for Security Operations 2025 (23 Jun 2025, Jonathan Nunez, Darren Livingstone) — [Vectra-hosted SOC Model Guide](https://vectra.ai/resources/gartner-soc-model-guide); [Expel-hosted Hype Cycle 2025](https://expel.com/gartner-hype-cycle-security-operations-2025/); [Gartner abstract](https://www.gartner.com/en/documents/5088831)

### Inferences
- SOC-CMM is the only open, licensed (CC BY-SA 4.0), spreadsheet-based model that both MITRE and SANS point to, which makes it the natural "scoring engine" for a Python project (the xlsx can be read with pandas/openpyxl to compute domain scores automatically).
- Dwell-time benchmarks move year to year (10 → 11 → 14 days), so a course should teach students to cite the edition year and the discovery-source breakdown rather than a single number.
- MTTD/MTTR have no single standards-body definition; SOC-CMM's split into "pickup time", "analysis time", "acknowledge time" and Expel's "alert-to-first-remediation" show that a report must state its clock-start and clock-stop events.

### Gaps
- Official SOC-CMM maturity-level and capability-level names were not confirmed from soc-cmm.com (only from third-party write-ups and the 2016 v1.1 PDF); the v2.4.2 spreadsheet itself was not opened.
- Verizon 2025 DBIR figures came from vendor summaries and the Verizon press release, not the report PDF; 2026 DBIR sample sizes were not shown on the hub page.
- Forrester has no recent (2024–2026) SOC maturity model that surfaced in search; Gartner content is paywalled.
- The SANS 2025 survey's exact 24/7 percentage conflicts across secondary sources (79% vs 82%); the PDF text I extracted says "Maintains 24/7 operational coverage in most cases" without a figure in the sections read.

---

## Key Question 4: How is detection coverage measured against MITRE ATT&CK and what tools support it?

### Takeaway
Coverage is measured on two axes—*visibility* (which data sources exist) and *detection* (which techniques have rules)—scored per technique and rendered as a Navigator heat-map layer; DeTT&CT is the reference open-source scorer, Splunk Detection Studio and Elastic detection-rules show the vendor equivalents, and Atomic Red Team / CALDERA validate coverage empirically by executing ATT&CK-mapped tests.

### Cited Findings
- DeTT&CT ("Detect Tactics, Techniques & Combat Threats", Rabobank CDC; ≈2.4k stars, last push 2026-10-19, current version 2.2.0, GPL-3.0) "helps blue teams using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours", across Enterprise, ICS and Mobile; components are a Python CLI, YAML administration files, the web-based DeTT&CT Editor, and Excel scoring tables; output is "coloured visualisations … made by loading generated JSON layer files into the ATT&CK Navigator"; example CLI `python dettect.py generic -ds` lists data sources by technique count; Dettectinator is a companion library to read detections from a SIEM/EDR — [DeTT&CT README](https://github.com/rabobank-cdc/DeTTECT); [wiki](https://github.com/rabobank-cdc/DeTTECT/wiki); [editor](https://rabobank-cdc.github.io/dettect-editor)
- SOC-CMM Metrics 101 formalises the two axes as "% MITRE ATT&CK® coverage" (detection techniques vs the organisation's ATT&CK profile) and "% MITRE ATT&CK® visibility (data sources)", explicitly citing DETT&CT for the heat-map — [SOC-CMM Metrics 101 PDF](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
- Navigator layer v4.5 provides the `score` + `gradient` mechanism (default red→green over 0–100) used to render coverage percentages per technique — [Layer format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)
- Splunk Enterprise Security "Detection Studio" automatically maps the active detection library to ATT&CK "to visualize technical coverage in real-time" and keeps "a time-series view of the changes in MITRE ATT&CK coverage as detections are turned on, turned off, or updated" — [Splunk blog: Detection Studio](https://www.splunk.com/en_us/blog/security/mastering-the-detection-lifecycle-with-detection-studio.html); [Splunk docs](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security)
- Elastic's prebuilt rule repo `elastic/detection-rules` (≈2.9k stars) and the Sigma rule repo `SigmaHQ/sigma` (≈11.4k stars) both tag rules with ATT&CK technique IDs, which is what coverage scripts parse — [elastic/detection-rules](https://github.com/elastic/detection-rules); [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- Atomic Red Team (Red Canary; ≈12.7k stars, last push 2026-10-31): "Small and highly portable detection tests based on MITRE's ATT&CK", documented at atomicredteam.io — [atomic-red-team](https://github.com/redcanaryco/atomic-red-team); [atomicredteam.io](https://atomicredteam.io/) (verified live)
- CALDERA: GitHub `mitre/caldera` now redirects to `apache/caldera` (≈7.5k stars); "a cyber security platform designed to automate adversary emulation, assist manual red-teams, and automate incident response", built on ATT&CK; core = asynchronous C2 server with REST API and web UI; default agent Sandcat; plugins include Atomic, Stockpile, Emu; requires Python 3.10+; docs on Read the Docs — [apache/caldera](https://github.com/apache/caldera); [CALDERA docs](https://caldera.readthedocs.io/en/latest/) (verified live)
- Red Canary's reporting methodology demonstrates coverage-by-prevalence: analytics are ATT&CK-mapped so technique prevalence can be tracked over time, giving defenders a prioritisation list (top-10 above) — [Red Canary methodology](https://redcanary.com/threat-detection-report/methodology/)
- Practitioner guidance cautions against chasing 100% coverage: "Aiming for full coverage would mean tremendous efforts spent on building detection measures against threats that might never materialize" — [Wiz Academy: SOC metrics](https://www.wiz.io/api/md/academy/detection-and-response/soc-metrics)
- awesome-soc lists DeTT&CT and "SANS Continuous purple teaming" as coverage-assessment references and links the CTID Mappings Explorer and TIBER-EU purple-teaming best practices (ECB, 2025) — [awesome-soc](https://github.com/cyb3rxp/awesome-soc); [SANS continuous purple teaming](https://www.sans.org/blog/continuous-purple-teaming-practical-approach-strengthening-offensive-capabilities); [TIBER-EU purple best practices 2025](https://www.ecb.europa.eu/pub/pdf/annex/ecb.tiber_eu_purple_best_practices_2025.en.pdf); [CTID mappings explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/)

### Inferences
- A minimal Python coverage pipeline is: parse rule metadata (Sigma/Elastic YAML `tags: attack.tXXXX`) → set of covered technique IDs → compare with the technique universe from `mitreattack-python` (or filtered to the organisation's threat profile from DeTT&CT group YAML) → emit a Navigator v4.5 layer with `score` per technique → optionally run Atomic tests for the covered techniques and record whether an alert fired (true-positive validation).
- Visibility (data-source) coverage is a leading indicator; detection coverage is a lagging indicator; a weekly report should show both with the delta since the previous week (as Splunk's time-series view does).

### Gaps
- DeTT&CT's exact numeric scales (data-source quality 0–5, visibility 0–4, detection –1 to 5) were not re-verified from the wiki during this session; the README summary did not include them.
- The date and status of CALDERA's move to the Apache organisation was not stated in the README fetched; only the redirect to `apache/caldera` was observed.

---

## Key Question 5: Which community writings on SOC optimization are most cited?

### Takeaway
The most-referenced community hubs are `cyb3rxp/awesome-soc` (which itself canonises MITRE 11 Strategies, SOC-CMM, SOC-TOM, Microsoft's SOC/IR hierarchy of needs, DeTT&CT and the Gartner value benchmark), `infosecB/awesome-detection-engineering`, OTRF's Jupyter/ThreatHunter-Playbook work, Red Canary's and Expel's annual reports, Elastic Security Labs' DEBMM, and Splunk's Detection Studio posts; vendor metric blogs are plentiful but disagree on thresholds.

### Cited Findings
- `cyb3rxp/awesome-soc` (≈1.9k stars, last push 2026-10-20): sections "Fundamental concepts", "Mission-critical means", "SOC internals/core", "AI", "SOAR", "Detection engineering", "Threat intelligence", "Playbooks/SOP", "SOC metrics (KPI/SLA)", "SOC Management", "HR and training", "IT architecture of a SOC"; the metrics page cites MITRE Strategy 10 (pp. 301–318), SOC-CMM Metrics 101, the SANS 2025 and 2022 SOC surveys and Gartner's "Cybersecurity business value benchmark"; maturity references: MITRE 11 Strategies, SOC-CMM, SOC-TOM, Microsoft "SOC/IR hierarchy of needs", DeTT&CT, SANS continuous purple teaming — [awesome-soc](https://github.com/cyb3rxp/awesome-soc); [metrics-kpi.md](https://github.com/cyb3rxp/awesome-soc/blob/main/metrics-kpi.md); [detection_engineering.md](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md); [Microsoft hierarchy of needs PDF](https://download.microsoft.com/download/E/6/2/E62530BF-47CC-4527-88BA-F13DF5294A65/HierarchyofCybersecurityNeeds.pdf); [Gartner value benchmark PDF](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf); [Expel: reduce false positives](https://expel.com/cyberspeak/reduce-false-positives-in-soc-operations/)
- `infosecB/awesome-detection-engineering` (≈1.4k stars) — [GitHub](https://github.com/infosecB/awesome-detection-engineering)
- OTRF `ThreatHunter-Playbook` (≈4.7k stars) and `infosec-jupyter-book` (≈134 stars) by Roberto Rodriguez (creator of HELK and the Threat Hunter Playbook); msticpy integrates the OTRF Security Datasets as a data provider — [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook); [infosec-jupyter-book](https://github.com/OTRF/infosec-jupyter-book); [msticpy docs](https://msticpy.readthedocs.io/)
- Splunk's SOC metrics definitions: "MTTD measures the average time a SOC team takes to detect an incident or a security breach. A shorter Mean Time to Detect (MTTD) value indicates better performance" — [Splunk security monitoring](https://splunk.com/en_us/solutions/security-monitoring.html); Splunk Security Content (research.splunk.com) provides ATT&CK-tagged detections — [research.splunk.com](https://research.splunk.com)
- Elastic Security Labs DEBMM (Sep 2024) is the most detailed vendor-published detection-engineering maturity model — [Elastic DEBMM](https://www.elastic.co/security-labs/elastic-releases-debmm)
- Widely shared practitioner metric guidance (vendor blogs; thresholds are opinions, not standards): false-positive rate above 50% in a category "indicates significant tuning work needed" (one guide) vs. above 30% (another); 5–30 alerts/day per L1 analyst vs. under 50; "organizations typically cover 20 to 40 percent of relevant techniques; 60 percent or above is strong coverage"; MTTD should be tracked "separately by attack technique category (phishing, lateral movement, exfiltration)"; medians are preferred over means for response times — [Secure.com SOC metrics 2026](https://www.secure.com/blog/soc-metrics-and-kpis); [CyberDefenders SOC metrics](https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/); [Prophet Security](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more); [Decryption Digest](https://www.decryptiondigest.com/blog/soc-metrics-and-kpis); [Wiz](https://www.wiz.io/api/md/academy/detection-and-response/soc-metrics)
- A frequently repeated caution (attributed to the UK NCSC via ReliaQuest) is against "easily quantifiable metrics like 'number of tickets processed', 'time taken to close a ticket', 'number of detection rules written', and 'volume of logs'" in favour of effectiveness tested by red/purple teaming — [ReliaQuest: cybersecurity metrics](https://reliaquest.com/blog/cybersecurity-metrics/)
- Contrarian piece: "Why MTTD is the wrong metric to obsess over" (Techspective, Jun 2026) — [Techspective](https://techspective.net/2026/06/17/why-mttd-is-wrong-metric-to-obsess-over/)
- SANS white papers are now hosted under sans.org/white-papers (the old "Reading Room" URL scheme `sans.org/reading-room/...` still appears in awesome-soc for the 2022 survey) — [SANS white papers](https://www.sans.org/white-papers/); [SANS 2022 SOC survey (reading-room URL)](https://www.sans.org/reading-room/whitepapers/analyst/2022-sans-soc-survey/)
- Red Canary and Expel reports are built from confirmed detections / SOC case data rather than surveys, which is why they are cited as benchmarks for technique prevalence and response times — [Red Canary methodology](https://redcanary.com/threat-detection-report/methodology/); [Expel ATR 2025](https://expel.com/annual-threat-report-2025/)

### Inferences
- For a curriculum, awesome-soc is the best single "map" because it is actively maintained (pushed Oct 2026) and already cross-references the primary sources in this note; students can be asked to trace each metric back to MITRE Strategy 10 or SOC-CMM Metrics 101.
- Vendor threshold numbers (FP rate 30% vs 50%, alerts per analyst 5–50) should be taught as *examples of locally set targets*, consistent with SOC-CMM's statement that "Your own targets should be set by the organisation and derived from mission, ambition, and goals as defined in the SOC charter".

### Gaps
- I found no Elastic *blog* post specifically about SOC metrics/MTTD (only DEBMM and the SANS survey PDF hosted by Elastic).
- Star counts are point-in-time (2026-11-01) and approximate; `mitre/caldera` stars now accrue to `apache/caldera`.
- Specific Expel quarterly "alert-to-fix" medians in minutes were not located in the fetched pages.

---

## Key Question 6: Which runnable Python snippets illustrate automated reporting and SOC optimization?

### Takeaway
Ten snippets below (10–40 lines each) cover the module's project pipeline end-to-end; all are *illustrative, written from the documented APIs* linked in Key Question 1 unless a source URL is given, and use only widely available packages (`pandas`, `jinja2`, `weasyprint`, `matplotlib`, `python-docx`, `streamlit`, `requests`, `mitreattack-python`).

### Cited Findings

**Snippet 1 – Weekly incident report: pandas → Jinja2 → HTML → PDF (WeasyPrint)**
Illustrative; APIs per [Jinja2 docs](https://jinja.palletsprojects.com/en/stable/) and [WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/).
```python
import pandas as pd
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

inc = pd.read_csv("incidents.csv", parse_dates=["opened", "closed"])
week = inc[inc["opened"] >= pd.Timestamp.now() - pd.Timedelta(days=7)]
summary = {
    "total": len(week),
    "by_severity": week["severity"].value_counts().to_dict(),
    "open": int((week["closed"].isna()).sum()),
    "mttr_h": round((week["closed"] - week["opened"]).dt.total_seconds().div(3600).median(), 1),
}
env = Environment(loader=FileSystemLoader("templates"),
                  autoescape=select_autoescape(["html"]))
html = env.get_template("weekly.html").render(
    summary=summary,
    rows=week.sort_values("severity").to_dict("records"),
    generated=pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"),
)
open("weekly_report.html", "w").write(html)
HTML(string=html, base_url=".").write_pdf("weekly_report.pdf")
print("wrote weekly_report.pdf", summary)
```
Minimal `templates/weekly.html` (Jinja2 syntax per docs):
```html
<h1>SOC Weekly Report – {{ generated }}</h1>
<p>Incidents: {{ summary.total }} (open: {{ summary.open }}), median MTTR {{ summary.mttr_h }} h</p>
<table>{% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.severity }}</td><td>{{ r.title }}</td></tr>{% endfor %}</table>
```

**Snippet 2 – Bar chart of alerts by severity (matplotlib)**
Illustrative; API per [matplotlib docs](https://matplotlib.org/stable/).
```python
import pandas as pd
import matplotlib
matplotlib.use("Agg")                      # headless for cron/CI
import matplotlib.pyplot as plt

alerts = pd.read_csv("alerts.csv")         # columns: alert_id, severity, rule, fired_at
order = ["critical", "high", "medium", "low", "informational"]
counts = alerts["severity"].str.lower().value_counts().reindex(order, fill_value=0)

fig, ax = plt.subplots(figsize=(7, 4))
bars = ax.bar(counts.index, counts.values)
ax.bar_label(bars)
ax.set_title("Alerts by severity – last 7 days")
ax.set_ylabel("Alert count")
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
fig.savefig("alerts_by_severity.png", dpi=150)   # embed in HTML/DOCX report
```

**Snippet 3 – Generate a DOCX incident report (python-docx)**
Illustrative; API per [python-docx docs](https://python-docx.readthedocs.io/en/latest/).
```python
import pandas as pd
from docx import Document
from docx.shared import Inches

inc = pd.read_csv("incidents.csv")
doc = Document()
doc.add_heading("Monthly SOC Incident Report", level=0)
doc.add_paragraph(f"Period: {inc['opened'].min()} to {inc['opened'].max()}")
doc.add_heading("Executive summary", level=1)
doc.add_paragraph(
    f"{len(inc)} incidents handled; {int((inc['severity'] == 'critical').sum())} critical. "
    "Top compromise vector: " + inc["vector"].mode().iat[0] + "."
)
doc.add_picture("alerts_by_severity.png", width=Inches(5.5))
doc.add_heading("Incident register", level=1)
cols = ["id", "severity", "title", "status"]
table = doc.add_table(rows=1, cols=len(cols))
table.style = "Light Grid Accent 1"
for i, c in enumerate(cols):
    table.rows[0].cells[i].text = c.upper()
for _, r in inc[cols].iterrows():
    cells = table.add_row().cells
    for i, c in enumerate(cols):
        cells[i].text = str(r[c])
doc.save("soc_monthly_report.docx")
```

**Snippet 4 – ATT&CK Navigator layer JSON from covered techniques**
Illustrative; schema per [Layer format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md) (required `name`, `domain`; `versions.layer` "4.5", `versions.navigator` ≥ "4.9.0"; technique `score`, `comment`; `gradient` colours).
```python
import json

# e.g. parsed from Sigma/Elastic rule tags -> {technique_id: number_of_rules}
covered = {"T1059.001": 4, "T1059.003": 2, "T1078.004": 1, "T1105": 3, "T1047": 1}

layer = {
    "name": "Detection coverage – 2026-W44",
    "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Number of active detection rules per technique (0 = gap)",
    "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 4},
    "legendItems": [{"label": "no rules", "color": "#ff6666"},
                    {"label": "4+ rules", "color": "#8ec843"}],
    "techniques": [
        {"techniqueID": tid, "score": min(n, 4),
         "comment": f"{n} rule(s)", "enabled": True, "showSubtechniques": True}
        for tid, n in covered.items()
    ],
    "hideDisabled": False,
    "sorting": 3,
}
with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
# Upload at https://mitre-attack.github.io/attack-navigator/ -> Open Existing Layer
```

**Snippet 5 – Coverage percentage against the full technique list (mitreattack-python)**
Illustrative; API per [mitreattack-python docs](https://mitreattack-python.readthedocs.io/en/latest/) (`MitreAttackData`, `get_techniques`, `get_attack_id`); data from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
```python
# pip install mitreattack-python ; download enterprise-attack.json from attack-stix-data
from mitreattack.stix20 import MitreAttackData
import json

attack = MitreAttackData("enterprise-attack.json")
techs = attack.get_techniques(remove_revoked_deprecated=True)
universe = {attack.get_attack_id(t) for t in techs}

layer = json.load(open("coverage_layer.json"))
covered = {t["techniqueID"] for t in layer["techniques"] if t.get("score", 0) > 0}

coverage_pct = 100 * len(covered & universe) / len(universe)
print(f"{len(covered & universe)}/{len(universe)} techniques covered = {coverage_pct:.1f}%")
gaps = sorted(universe - covered)
print("first 10 gaps:", gaps[:10])
```

**Snippet 6 – MTTD and MTTR from a ticket export (pandas)**
Illustrative; pandas API per [pandas docs](https://pandas.pydata.org/docs/). Clock definitions follow the practitioner caution that MTTD may mean activity→alert, alert→acknowledge or alert→confirm ([Prophet Security](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more)); medians are reported alongside means.
```python
import pandas as pd

t = pd.read_csv("tickets.csv", parse_dates=["first_activity", "alerted", "acknowledged", "resolved"])
# Clock definitions (state them in the report!):
t["ttd_h"] = (t["alerted"] - t["first_activity"]).dt.total_seconds() / 3600   # detection
t["tta_m"] = (t["acknowledged"] - t["alerted"]).dt.total_seconds() / 60       # pickup
t["ttr_h"] = (t["resolved"] - t["alerted"]).dt.total_seconds() / 3600         # response/resolve

def summarise(g):
    return pd.Series({
        "n": len(g),
        "MTTD_mean_h": g["ttd_h"].mean(), "MTTD_median_h": g["ttd_h"].median(),
        "MTTA_median_min": g["tta_m"].median(),
        "MTTR_mean_h": g["ttr_h"].mean(), "MTTR_median_h": g["ttr_h"].median(),
        "p90_TTR_h": g["ttr_h"].quantile(0.9),
    })

by_sev = t.groupby("severity").apply(summarise).round(1)
overall = summarise(t).round(1)
print(by_sev, "\n\nOverall:\n", overall)
# Weekly trend for the executive chart
weekly = t.set_index("alerted").resample("W")[["ttd_h", "ttr_h"]].median()
weekly.to_csv("weekly_mttd_mttr.csv")
```

**Snippet 7 – False-positive rate per detection rule and tuning ranking**
Illustrative; metric definitions per SOC-CMM Metrics 101 ("% Percentage of false positives – alerts that fired incorrectly"; "% benign positives – fired correctly but not an incident") — [SOC-CMM Metrics 101](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf).
```python
import pandas as pd

a = pd.read_csv("alerts_triaged.csv")   # columns: rule, disposition in {true_positive, benign_positive, false_positive}
piv = pd.crosstab(a["rule"], a["disposition"]).reindex(
    columns=["true_positive", "benign_positive", "false_positive"], fill_value=0)
piv["total"] = piv.sum(axis=1)
piv["fp_rate"] = piv["false_positive"] / piv["total"]
piv["bp_rate"] = piv["benign_positive"] / piv["total"]
piv["precision"] = piv["true_positive"] / piv["total"]

# Tuning priority = analyst minutes wasted: FP volume weighted by FP rate (noisy AND wrong)
piv["tuning_score"] = piv["false_positive"] * piv["fp_rate"]
ranked = piv[piv["total"] >= 20].sort_values("tuning_score", ascending=False)

print(ranked.head(10).round(2))
ranked.head(10).to_csv("rules_to_tune.csv")
org_fp = piv["false_positive"].sum() / piv["total"].sum()
print(f"Org-wide FP rate: {org_fp:.1%}  (SOC-CMM target: trend decreasing)")
```

**Snippet 8 – Streamlit SOC dashboard skeleton**
Illustrative; API per [Streamlit docs](https://docs.streamlit.io/) (`st.metric`, `st.columns`, `st.bar_chart`, `st.dataframe`, `st.sidebar`). Run with `streamlit run soc_dashboard.py`.
```python
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC Dashboard", layout="wide")
st.title("SOC Operations Dashboard")

alerts = pd.read_csv("alerts.csv", parse_dates=["fired_at"])
tickets = pd.read_csv("tickets.csv", parse_dates=["alerted", "resolved"])
days = st.sidebar.slider("Window (days)", 1, 90, 7)
cutoff = pd.Timestamp.now() - pd.Timedelta(days=days)
a, t = alerts[alerts["fired_at"] >= cutoff], tickets[tickets["alerted"] >= cutoff]

mttr_h = (t["resolved"] - t["alerted"]).dt.total_seconds().div(3600).median()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts", len(a))
c2.metric("Incidents", len(t))
c3.metric("Median TTR (h)", f"{mttr_h:.1f}")
c4.metric("Open incidents", int(t["resolved"].isna().sum()))

st.subheader("Alerts by severity")
st.bar_chart(a["severity"].value_counts())
st.subheader("Noisiest rules")
st.bar_chart(a["rule"].value_counts().head(10))
st.subheader("Incident register")
st.dataframe(t.sort_values("alerted", ascending=False), use_container_width=True)
```

**Snippet 9 – Fetch EPSS scores from the FIRST API and prioritise vulnerabilities**
Illustrative; endpoint and parameters per [FIRST API docs: GET /epss](https://api.first.org/epss/) (`cve` comma-separated, ≤2000 chars; response `data[].cve/epss/percentile/date`). Verified live 2026-11-01 ([example call](https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2024-3400&pretty=true)). CVSS nomenclature per [CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document).
```python
import requests, pandas as pd

EPSS = "https://api.first.org/data/v1/epss"
vulns = pd.read_csv("scan_export.csv")          # columns: cve, cvss_base, asset, internet_facing

def epss_batch(cves, size=100):                 # keep the cve= parameter under 2000 chars
    rows = []
    for i in range(0, len(cves), size):
        r = requests.get(EPSS, params={"cve": ",".join(cves[i:i+size])}, timeout=30)
        r.raise_for_status()
        rows += r.json()["data"]
    return pd.DataFrame(rows).astype({"epss": float, "percentile": float})

scores = epss_batch(vulns["cve"].dropna().unique().tolist())
df = vulns.merge(scores, on="cve", how="left")
df["epss"] = df["epss"].fillna(0.0)
# Simple risk rank: likelihood (EPSS) x impact (CVSS-B / 10) x exposure multiplier
df["risk"] = df["epss"] * (df["cvss_base"] / 10) * df["internet_facing"].map({True: 2.0, False: 1.0})
top = df.sort_values("risk", ascending=False)
print(top[["cve", "asset", "cvss_base", "epss", "percentile", "risk"]].head(15).round(3))
top.to_csv("patch_priority.csv", index=False)
```

**Snippet 10 (short) – Markdown report to PDF via Pandoc**
Illustrative; CLI per [Pandoc manual](https://pandoc.org/MANUAL.html).
```python
import subprocess, pathlib
md = pathlib.Path("postmortem.md")
md.write_text("# Incident INC-2026-0412 post-mortem\n\n## Timeline\n\n- 09:12 alert fired\n- 09:20 acknowledged\n")
subprocess.run(["pandoc", str(md), "-o", "postmortem.pdf", "--pdf-engine=weasyprint"], check=True)
```

### Inferences
- Snippets 1–3 and 10 cover every deliverable format a SOC typically needs (HTML, PDF, DOCX); snippets 4–5 and 7 produce the detection-engineering evidence (coverage layer, coverage %, tuning backlog); snippets 6 and 8 produce the operational KPIs; snippet 9 produces the vulnerability-management section. Together they form a coherent "weekly SOC report generator" project.
- Each snippet depends only on CSV inputs, so students can run them against synthetic data before wiring in a SIEM API.

### Gaps
- No snippets were copied verbatim from an external source; I did not find a single authoritative public repository that implements exactly these report-generation tasks for SOCs, so all code is marked illustrative and should be unit-tested by the course author before distribution.
- `mitreattack-python` method names (`get_techniques`, `get_attack_id`) are from its documented `MitreAttackData` class; the ATT&CK version string in snippet 4 ("17") is a placeholder and should match the STIX bundle actually used.
