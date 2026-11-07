# Compliance Mapping Reference

Maps security scan findings to framework controls so an audit report can carry a compliance evidence appendix. Read this mid-audit, after findings are collected and before the report is written.

## Contents

- [Read this first: evidence is not compliance](#read-this-first-evidence-is-not-compliance)
- [OWASP Top 10:2025](#owasp-top-102025)
- [OWASP LLM Top 10 (2025)](#owasp-llm-top-10-2025)
- [ISO/IEC 27001:2022 Annex A](#isoiec-270012022-annex-a)
- [ISO/IEC 42001:2023](#isoiec-420012023)
- [GDPR](#gdpr)
- [India DPDPA 2023 and DPDP Rules 2025](#india-dpdpa-2023-and-dpdp-rules-2025)
- [Writing the appendix](#writing-the-appendix)
- [When the user asks "are we compliant?"](#when-the-user-asks-are-we-compliant)
- [Rules for using this file](#rules-for-using-this-file)

## Read this first: evidence is not compliance

Scanner output is EVIDENCE supporting a control or article. It is never compliance itself. A clean scan proves that a test was run and that it passed. An auditor decides whether that test was sufficient, whether its scope was right, and whether the surrounding management system exists at all.

Constraints on every report produced with this file:

1. Never state or imply that a scan result makes a system compliant, certified, or certifiable.
2. Never use the words "certified", "attested", or "audited against" for scanner output. The correct verbs are "evidences", "supports", "is relevant to".
3. Always carry the caveat text into the report itself, not only into the conversation. The appendix template below includes it.
4. A control with no finding is not a passed control. It means this scan produced no evidence either way. Say so rather than marking it satisfied.
5. Compliance additionally requires the management system, policies, risk assessment, and organizational measures each framework mandates. None of those are visible to a scanner.

## OWASP Top 10:2025

Current edition is the 8th, released November 2025. Use the 2025 numbering in reports and state the year explicitly, because A03 and A10 changed meaning against 2021 and an unqualified "A03" is ambiguous.

| # | Category | Change vs 2021 |
|---|----------|----------------|
| A01:2025 | Broken Access Control | Held #1. Now absorbs SSRF, which was 2021 A10. Explicitly covers BOLA and BFLA API authorization. |
| A02:2025 | Security Misconfiguration | Up from #5. |
| A03:2025 | Software Supply Chain Failures | Expanded from 2021 A06 "Vulnerable and Outdated Components". Broader than dependency versions. |
| A04:2025 | Cryptographic Failures | Down from #2. |
| A05:2025 | Injection | Down from #3. |
| A06:2025 | Insecure Design | Down from #4. |
| A07:2025 | Authentication Failures | Renamed, was "Identification and Authentication Failures". |
| A08:2025 | Software or Data Integrity Failures | Held #8. |
| A09:2025 | Security Logging and Alerting Failures | Renamed, was "Security Logging and Monitoring Failures". |
| A10:2025 | Mishandling of Exceptional Conditions | NEW. Error handling, fail-open behaviour, logic errors. |

Three changes matter most when categorizing findings:

- SSRF findings map to A01:2025, not to a separate category.
- Dependency and build-pipeline findings map to A03:2025 as supply chain failures.
- Fail-open error paths, swallowed exceptions, and logic errors that leave a system in an insecure state now have a home in A10:2025 instead of being forced into A04 or A06.

Scan domain coverage:

| Scan domain | Categories typically evidenced |
|---|---|
| SAST | A01, A04, A05, A08, A10 |
| DAST | A01, A02, A05, A07 |
| SCA | A03 |
| Secret scanning | A02 and A04, plus A07 when the credential is auth material |
| Config review | A02 |

## OWASP LLM Top 10 (2025)

Apply this list only when the target integrates an LLM. Do not add it to a report for a system with no AI component.

| # | Category |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

Mappings a scan can support directly:

| Finding type | Category |
|---|---|
| Secrets in code, especially inside prompt templates | LLM07 |
| SCA over model, SDK, and package provenance | LLM03 |
| Output sanitization review on model responses reaching a sink | LLM05 |

## ISO/IEC 27001:2022 Annex A

Annex A controls are evidenced by the scan activity and its records, not by the absence of findings. Cite the control number and title together.

| Scan domain | Control(s) |
|---|---|
| SAST | A.8.28 Secure Coding; A.8.25 Secure Development Life Cycle; A.8.29 Security Testing in Development and Acceptance; A.8.26 Application Security Requirements |
| DAST | A.8.29; A.8.8 Management of Technical Vulnerabilities; A.8.27 Secure System Architecture and Engineering Principles |
| SCA | A.8.8; A.5.21 Managing Information Security in the ICT Supply Chain; A.5.19 and A.5.20 Supplier Relationships and Agreements; A.5.23 Cloud Services |
| Secret scanning | A.8.4 Access to Source Code; A.8.24 Use of Cryptography; A.8.12 Data Leakage Prevention; A.5.17 Authentication Information |
| PII in code or logs | A.8.12; A.8.15 Logging; A.5.34 Privacy and Protection of PII |
| IaC and config scanning | A.8.9 Configuration Management; A.8.31 Separation of Development, Test and Production Environments |
| Recurring CI scans plus triage records | A.8.8; A.8.16 Monitoring Activities; A.8.32 Change Management |
| Human code review records | A.8.25; A.8.28; A.8.29 |

Certification depends on the Statement of Applicability, the ISMS, and the audit itself. A scan contributes records to specific controls and nothing more.

## ISO/IEC 42001:2023

AI management system standard. 38 Annex A controls across A.2 to A.10, with applicability determined by the organization's Statement of Applicability. Cite it only for AI-integrated systems.

| Domain in an AI-integrated app | Control |
|---|---|
| SAST and DAST of AI-feature code, including prompt handling and output sanitization | A.6.1.3 Processes for Responsible Design and Development; A.6.2.4 AI System Verification and Validation |
| Security requirements specified for LLM features | A.6.2.2 AI System Requirements and Specification |
| SCA over model, SDK, and vector database dependencies | A.4.4 Tooling Resources; A.10.3 Suppliers |
| Scan reports archived per release | A.6.2.3 Documentation of Design and Development; A.6.2.7 AI System Technical Documentation |
| Pre-deploy scan gate | A.6.2.5 AI System Deployment |
| Continuous scanning and monitoring in production | A.6.2.6 AI System Operation and Monitoring; A.6.2.8 Recording of Event Logs |
| PII and secret scanning of training or RAG data pipelines | A.7.2 Data for Development and Enhancement; A.7.5 Data Provenance; A.7.6 Data Preparation |
| Security risk findings feeding an impact assessment | A.5.2 AI System Impact Assessment Process |

## GDPR

The strongest direct mapping for any scanning programme is Article 32(1)(d), which requires "a process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures". Note the word "regularly": a single run evidences a test, a schedule evidences the process.

| Scan domain | Article |
|---|---|
| SAST, DAST, SCA run regularly on a schedule or in CI | Art. 32(1)(d), regular testing of effectiveness |
| Crypto misuse such as weak TLS, hardcoded keys, plaintext storage | Art. 32(1)(a), pseudonymisation and encryption |
| Vulnerabilities affecting availability or integrity, plus remediation | Art. 32(1)(b), confidentiality, integrity, availability and resilience |
| Security gates in the SDLC from design onward | Art. 25(1) data protection by design; Art. 25(2) by default |
| Secret scanning, since exposed credentials are a breach vector | Art. 32(1). Actual exposure may itself be notifiable, so Art. 33 to the authority within 72 hours and Art. 34 to data subjects where risk is high |
| PII in code or logs | Art. 5(1)(f) integrity and confidentiality, with Art. 32. Unminimized PII in logs also implicates Art. 5(1)(c) minimisation. Exposure triggers Arts. 33 and 34 |
| Logging and alerting findings | Art. 32(1)(b) and (d). Detection capability underpins the 72 hour Art. 33 clock, which starts on becoming "aware of" the breach |

PII found in source code or logs is not merely a finding. It is potential evidence of an Art. 32 failure, and if it has been exposed it is a personal data breach under Art. 4(12). Escalate such findings rather than listing them at their raw scanner severity.

## India DPDPA 2023 and DPDP Rules 2025

Timing, which the report should state because obligations are not yet fully in force:

- DPDP Rules 2025 were notified by MeitY on 14 November 2025. These are final rules, not a draft.
- Commencement is phased. Rules 3, 5 to 16, 22 and 23, which include the security safeguards at Rule 6 and breach intimation at Rule 7, take effect 18 months after publication, so approximately May 2027.
- Preparation should happen now, because the safeguards are architectural and cannot be retrofitted in the weeks before commencement.

Obligations:

- Act s.8(5) requires reasonable security safeguards. Act s.8(6) requires breach intimation.
- Rule 6 sets minimum safeguards: encryption, obfuscation, masking or virtual tokens; access control; visibility through logs, monitoring and review; retention of logs and related personal data for one year; backups; and processor contracts that mandate these safeguards.
- Rule 7 requires intimation to affected Data Principals without delay, plus a detailed report to the Data Protection Board within 72 hours.

Penalties: up to Rs 250 crore for failure of security safeguards under s.8(5), and up to Rs 200 crore for failure to notify a breach.

| Scan domain | Provision |
|---|---|
| SAST and DAST with a remediation trail | s.8(5) with Rule 6(1), reasonable security safeguards |
| Crypto findings | Rule 6(1)(a), encryption, obfuscation, masking, virtual tokens |
| SCA plus processor and vendor SDK scanning | Rule 6(1)(f), processor contract safeguards; s.8(2) |
| Secret scanning | Rule 6(1)(b), access control. A lapse falls in the s.8(5) Rs 250 crore tier |
| PII in code or logs | s.8(5) risk. Rule 6(1)(c) log visibility holds only if the logs themselves are protected. Over-retention conflicts with s.8(7) and Rule 8 erasure |
| Logging and monitoring findings | Rule 6(1)(c), logs, monitoring and review with one year retention. Underpins the 72 hour Rule 7 report to the Board |
| Timestamped scan reports and fix history | Demonstrates the "reasonable" standard if the Board investigates after a breach. This is the primary mitigation evidence against the Rs 250 crore tier |

## Writing the appendix

Append the following to the audit report, after the findings section. Fill only the cells the scan actually supports. Leave a cell as `n/a` rather than reaching for a control that does not fit, and never widen a mapping to fill a column.

```markdown
## Appendix: Compliance Evidence Mapping

This appendix maps findings from this scan to control frameworks. Scanner
output is evidence supporting a control, not compliance with it. A clean
result proves that a test ran and passed. Sufficiency of scope, method and
frequency is an auditor's determination, not this report's. Nothing here
constitutes certification or an attestation of conformity.

Scan run: <date> | Scope: <repos, branches, environments> | Tools: <tool list>

### Finding to control mapping

| # | Finding | Severity | OWASP 2025 | ISO 27001:2022 | GDPR | DPDPA 2023 / Rules 2025 |
|---|---------|----------|------------|----------------|------|-------------------------|
| 1 | Hardcoded API key in `src/config.ts` | High | A02:2025 Security Misconfiguration | A.8.4 Access to Source Code; A.5.17 Authentication Information | Art. 32(1) | Rule 6(1)(b) access control; s.8(5) |
| 2 | Dependency `<pkg>@<ver>` with known CVE | High | A03:2025 Software Supply Chain Failures | A.8.8 Management of Technical Vulnerabilities; A.5.21 ICT Supply Chain | Art. 32(1)(b) | Rule 6(1)(f); s.8(2) |
| 3 | User email written to application log | Medium | A09:2025 Security Logging and Alerting Failures | A.8.12 Data Leakage Prevention; A.8.15 Logging; A.5.34 Privacy and Protection of PII | Art. 5(1)(f); Art. 5(1)(c); Art. 32 | s.8(5); Rule 6(1)(c) |

### Controls exercised by this scan run

Independent of findings, running and recording this scan produces evidence for
the following controls. Each entry requires the run to be recorded and retained.

| Control | What evidences it | Standing requirement |
|---------|-------------------|----------------------|
| GDPR Art. 32(1)(d), regular testing of effectiveness | This scan, its date, scope and tool versions | Recurrence. One run evidences a test, a schedule evidences the process |
| ISO 27001 A.8.29 Security Testing in Development and Acceptance | Scan executed before release and result recorded | Retained report per release |
| ISO 27001 A.8.8 Management of Technical Vulnerabilities | Findings identified, severity assigned, remediation tracked | Closed-loop triage records |
| ISO 27001 A.8.25 Secure Development Life Cycle | Scan integrated into the development pipeline | Documented pipeline gate |
| ISO 27001 A.8.32 Change Management | Findings raised and resolved through change records | Linked tickets or commits |
| DPDPA s.8(5) reasonable security safeguards | Timestamped report plus fix history | Continuous record, retained for Board scrutiny |

### Not evidenced by this scan

<List controls the audience may expect but which this run does not support.
Absence of a finding is not evidence a control is satisfied.>
```

Rules when filling the template:

1. One row per finding, not one row per control. A finding with several control mappings gets several cells in its own row.
2. Cite the framework version in the column header exactly as shown, because control numbers are version specific.
3. Add the OWASP LLM and ISO 42001 columns only for AI-integrated targets. Do not carry empty columns.
4. The "Not evidenced" block is mandatory. Deleting it turns a scoped report into an implied clean bill of health.

## When the user asks "are we compliant?"

The honest answer is that this scan evidences technical measures only, and technical measures are one input to a compliance determination that no scanner can make.

State plainly what a scan does not cover, naming the missing pieces:

- Policies and procedures, including an information security policy, an acceptable use policy, and access control procedures.
- A documented risk assessment and risk treatment plan, with an ISO 27001 Statement of Applicability where certification is the goal.
- Records of processing activities under GDPR Art. 30, plus a lawful basis for each processing operation.
- Data Protection Impact Assessments where processing is high risk, under GDPR Art. 35.
- A Data Protection Officer where one is required, consent notices, and data subject rights handling. Under DPDPA the equivalents are the Consent Manager arrangements, notice requirements, and Data Principal rights handling.
- Processor and sub-processor contracts carrying the required security terms, under GDPR Art. 28 and DPDPA Rule 6(1)(f).
- A management system with defined scope, leadership commitment, internal audit and management review. For ISO certification an accredited certification body audit is also required, and for ISO 42001 an AI management system with its own impact assessment process.
- Breach response procedures capable of meeting the GDPR Art. 33 and DPDPA Rule 7 72 hour clocks.
- Training, awareness, supplier management, physical security, and business continuity.

Recommended phrasing: "This scan supports the technical measures element of <framework>. It does not determine compliance. Compliance depends on the organizational measures listed above and on an auditor's assessment."

## Rules for using this file

1. Use only the control numbers listed here. Never invent, infer, or extrapolate a control number, article number, or rule number.
2. If a needed control is not in this file, verify it against the published standard or regulation before citing it. An unverified citation is worse than an omission.
3. Cite framework versions explicitly: OWASP Top 10:2025, ISO/IEC 27001:2022, ISO/IEC 42001:2023, DPDP Rules 2025.
4. Map conservatively. One well supported control beats five speculative ones, and a reviewer who finds one bad mapping will distrust the whole appendix.
