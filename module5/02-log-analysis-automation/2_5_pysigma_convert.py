"""ตัวอย่าง 2.5 — แปลง Sigma rule ด้วย pySigma (Splunk backend, Sysmon pipeline)

ที่มา: illustrative อิงจาก documented APIs: https://github.com/SigmaHQ/pySigma และ https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html ; CLI เทียบเท่า: sigma plugin install splunk; sigma convert -t splunk -p sysmon <rules>
คัดจาก docs/python-security-automation-research.md (ส่วนที่ 2) โดยไม่แก้ไขตรรกะ
การใช้: python 2_5_pysigma_convert.py
ต้องติดตั้ง: pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon
สถานะ: ดู README.md ของโฟลเดอร์นี้ (ผล smoke-test)
"""
# pip install pysigma pysigma-backend-splunk pysigma-pipeline-sysmon
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.sysmon import sysmon_pipeline

RULE = """
title: Suspicious whoami execution
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\whoami.exe'
  condition: sel
level: low
"""
rules = SigmaCollection.from_yaml(RULE)
backend = SplunkBackend(processing_pipeline=sysmon_pipeline())
for query in backend.convert(rules):
    print(query)
