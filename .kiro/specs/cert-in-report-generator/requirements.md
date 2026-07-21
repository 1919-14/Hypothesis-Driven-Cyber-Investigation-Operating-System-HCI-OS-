# Requirements Document: CERT-In Report Generator

## Introduction

The CERT-In Report Generator is an automated reporting system for HCI-OS that generates comprehensive, professional-grade cybersecurity reports in the style of CERT-In annual and quarterly publications. The system aggregates security incident data from HCI-OS's 13-agent architecture, applies AI-powered analysis and narrative generation, and produces multi-format reports with actionable intelligence for stakeholders including government agencies, security operations centers, and executive leadership.

The generator integrates with existing HCI-OS data stores (audit logs, cognitive memory, federation intelligence, CERT-In advisories, asset graphs) to provide statistical analysis, trend identification, threat attribution, and evidence-based recommendations.

## Glossary

- **Report_Generator**: The CERT-In Report Generator system that orchestrates data aggregation, analysis, and report production
- **Data_Aggregator**: Component that collects and consolidates data from HCI-OS agents and data stores
- **AI_Analyzer**: Component that applies machine learning and LLM-based analysis to generate insights, summaries, and recommendations
- **Template_Engine**: Component that applies CERT-In-style formatting and structure to report content
- **Export_Service**: Component that renders reports in multiple output formats (PDF, Markdown, JSON, HTML)
- **Redaction_Service**: Component that identifies and removes sensitive information (PII, credentials, internal IPs) from reports
- **Audit_Trail**: Immutable log of all report generation events maintained by A12
- **HCI_OS**: The parent multi-agent cybersecurity operations system containing 13 specialized agents (A1-A13)
- **A12**: Audit & Memory Agent that maintains audit_log.jsonl and cognitive_memory.jsonl
- **A13**: Federation Agent that manages federation_store.json with STIX 2.1 IOC sharing
- **A6**: Attribution & RAG Agent that maps incidents to MITRE ATT&CK and threat actor campaigns
- **CERT_In**: Computer Emergency Response Team India, the authoritative source for cybersecurity advisories
- **STIX**: Structured Threat Information eXpression (STIX 2.1) format for threat intelligence
- **MITRE_ATT&CK**: Knowledge base of adversary tactics and techniques
- **RAG**: Retrieval Augmented Generation system using FAISS vector database (rag_index.faiss)
- **Hypothesis**: Competing explanation for observed security behavior tracked by HCI-OS
- **Decision**: Cryptographically signed containment action proposed by A7 SOAR
- **Evidence**: Canonical telemetry object with 256-dimensional semantic embedding

## Requirements

### Requirement 1: Data Integration and Aggregation

**User Story:** As a security analyst, I want the Report Generator to automatically collect incident data from all HCI-OS components, so that reports reflect complete system state without manual data gathering.

#### Acceptance Criteria

1. THE Data_Aggregator SHALL read audit_log.jsonl entries from A12 to extract Decision and correction records
2. THE Data_Aggregator SHALL read cognitive_memory.jsonl entries from A12 to extract Hypothesis objects
3. THE Data_Aggregator SHALL read federation_store.json from A13 to extract STIX 2.1 indicators and peer intelligence
4. THE Data_Aggregator SHALL read cert_in_advisories.json to extract advisory metadata, TTP chains, and attribution data
5. THE Data_Aggregator SHALL query asset_inventory.json and asset_graph.json to extract affected asset counts and topology
6. WHEN aggregating data for a time period, THE Data_Aggregator SHALL filter records by stored_at timestamp fields
7. WHEN multiple data sources are unavailable, THE Data_Aggregator SHALL log missing sources and generate partial reports with data coverage warnings
8. THE Data_Aggregator SHALL compute aggregate statistics (total incidents, incidents by type, incidents by sector, resolution times) across the specified time period

### Requirement 2: Incident Classification and Statistics

**User Story:** As a CERT-In liaison, I want incidents categorized using CERT-In taxonomy (phishing, malware, ransomware, DDoS, data breach, vulnerability exploitation), so that reports align with national reporting standards.

#### Acceptance Criteria

1. THE Report_Generator SHALL classify Hypothesis objects into CERT-In incident categories based on MITRE ATT&CK TTP chains
2. WHEN a Hypothesis contains TTP T1566, THE Report_Generator SHALL categorize it as "Phishing"
3. WHEN a Hypothesis contains TTP T1486, THE Report_Generator SHALL categorize it as "Ransomware"
4. WHEN a Hypothesis contains TTP T1499, THE Report_Generator SHALL categorize it as "DDoS"
5. WHEN a Hypothesis contains TTPs T1003 OR T1078 OR T1021, THE Report_Generator SHALL categorize it as "Unauthorized Access"
6. WHEN a Hypothesis contains TTP T1190, THE Report_Generator SHALL categorize it as "Vulnerability Exploitation"
7. THE Report_Generator SHALL compute incident counts, percentages, and month-over-month trends for each category
8. THE Report_Generator SHALL identify the top 5 incident categories by volume for inclusion in executive summaries

### Requirement 3: Sector-Based Analysis

**User Story:** As a critical infrastructure coordinator, I want reports segmented by sector (Power, Finance, Healthcare, Government, Education, Transport), so that sector-specific stakeholders receive relevant intelligence.

#### Acceptance Criteria

1. THE Report_Generator SHALL extract sector labels from Evidence asset_id fields using asset_inventory.json mappings
2. THE Report_Generator SHALL aggregate incident counts per sector for the reporting period
3. THE Report_Generator SHALL compute sector risk scores based on incident severity, affected asset criticality, and hypothesis confidence levels
4. WHEN generating sector breakdowns, THE Report_Generator SHALL include incident type distribution per sector
5. THE Report_Generator SHALL identify the top 3 most-targeted sectors by incident volume
6. WHERE a sector filter is specified, THE Report_Generator SHALL generate sector-specific reports containing only incidents affecting that sector
7. THE Report_Generator SHALL compare current period sector statistics to previous period for trend identification

### Requirement 4: Threat Attribution and Campaign Tracking

**User Story:** As a threat intelligence analyst, I want reports to include threat actor attribution and campaign tracking, so that I can understand adversary patterns and prioritize defenses.

#### Acceptance Criteria

1. THE Report_Generator SHALL extract attribution data from Hypothesis objects populated by A6 Attribution Agent
2. THE Report_Generator SHALL correlate incidents to known campaigns using cert_in_advisories.json advisory_id and attribution fields
3. THE Report_Generator SHALL compute activity levels per attributed threat actor (APT41, SideWinder, Volt Typhoon, etc.) for the reporting period
4. THE Report_Generator SHALL identify newly observed threat actors not present in previous reporting periods
5. WHEN multiple incidents map to the same campaign, THE Report_Generator SHALL group them under a campaign summary section
6. THE Report_Generator SHALL extract TTP chains from Hypothesis mitre_chain fields and display them in MITRE ATT&CK matrix format
7. THE Report_Generator SHALL rank threat actors by total incidents attributed, average incident severity, and sectors targeted

### Requirement 5: AI-Generated Executive Summaries

**User Story:** As an executive stakeholder, I want AI-generated executive summaries that highlight key findings and trends, so that I can understand security posture without reading technical details.

#### Acceptance Criteria

1. THE AI_Analyzer SHALL generate a 200-300 word executive summary using LLM-based natural language generation
2. THE AI_Analyzer SHALL include the following elements in executive summaries: total incident count, period-over-period change percentage, top incident category, most-targeted sector, and highest-risk threat actor
3. WHEN incident volume increases by more than 20% compared to previous period, THE AI_Analyzer SHALL explicitly highlight this as a "significant increase" in the summary
4. WHEN a critical infrastructure sector (Power, Defense) is in the top 3 targets, THE AI_Analyzer SHALL flag this as "critical infrastructure targeting" in the summary
5. THE AI_Analyzer SHALL generate summaries in a formal, objective tone matching CERT-In publication style
6. THE AI_Analyzer SHALL avoid speculation and unsupported claims, limiting summary content to facts derivable from aggregated data
7. THE AI_Analyzer SHALL ensure executive summaries contain no PII, internal IP addresses, or sensitive technical details

### Requirement 6: AI-Generated Incident Trend Analysis

**User Story:** As a SOC manager, I want AI-powered trend analysis that identifies emerging threats and pattern changes, so that I can proactively adjust security controls.

#### Acceptance Criteria

1. THE AI_Analyzer SHALL compare current reporting period statistics to previous period across incident types, sectors, and threat actors
2. THE AI_Analyzer SHALL identify statistically significant trends using threshold: absolute change ≥ 10 incidents OR relative change ≥ 30%
3. WHEN an incident type shows increasing trend, THE AI_Analyzer SHALL generate a natural language explanation of the trend magnitude and potential causes
4. THE AI_Analyzer SHALL identify correlations between threat actor activity and specific TTP patterns using MITRE ATT&CK mappings
5. THE AI_Analyzer SHALL detect anomalous patterns such as: unusual time-of-day activity, rapid lateral movement sequences (TGN temporal analysis), or novel TTP combinations
6. THE AI_Analyzer SHALL use RAG system (rag_index.faiss) to retrieve similar historical incidents and compare current patterns to past campaigns
7. THE AI_Analyzer SHALL generate trend visualizations showing incident volume over time (monthly breakdown for annual reports, weekly for quarterly reports)

### Requirement 7: AI-Generated Recommendations

**User Story:** As a security architect, I want AI-generated actionable recommendations based on observed incidents, so that I can prioritize remediation efforts and security investments.

#### Acceptance Criteria

1. THE AI_Analyzer SHALL generate 5-10 prioritized recommendations based on incident frequency, severity, and sector criticality
2. WHEN a specific vulnerability (CVE) appears in 3 or more incidents, THE AI_Analyzer SHALL recommend patching that CVE as a high-priority action
3. WHEN phishing incidents exceed 30% of total incidents, THE AI_Analyzer SHALL recommend user awareness training programs
4. WHEN ransomware incidents target critical infrastructure, THE AI_Analyzer SHALL recommend network segmentation and backup validation
5. WHEN incidents show credential abuse patterns (T1078, T1003), THE AI_Analyzer SHALL recommend MFA enforcement and privileged access management
6. THE AI_Analyzer SHALL map recommendations to MITRE ATT&CK mitigations using the ATT&CK mitigation framework
7. THE AI_Analyzer SHALL rank recommendations by estimated impact (number of incidents potentially prevented) and implementation feasibility

### Requirement 8: Report Template Structure

**User Story:** As a CERT-In coordinator, I want reports structured identically to official CERT-In publications, so that reports integrate seamlessly into national reporting workflows.

#### Acceptance Criteria

1. THE Template_Engine SHALL structure reports with the following sections in order: Cover Page, Executive Summary, Incident Statistics, Sector Analysis, Threat Actor Attribution, Activities & Operations, Training and Awareness (if applicable), International Collaboration (federation data), Recommendations, Appendices
2. THE Template_Engine SHALL include a Cover Page containing: report title, reporting period, generation date, HCI-OS version, and organizational logo placeholder
3. THE Template_Engine SHALL format the Incident Statistics section with: total incident count, incident breakdown by category (table and chart), month-over-month comparison, resolution time statistics (mean, median, 95th percentile)
4. THE Template_Engine SHALL format the Sector Analysis section with: incidents per sector (table), sector risk scores, top 3 targeted sectors, sector-specific incident type distributions
5. THE Template_Engine SHALL format the Threat Actor Attribution section with: active threat actors, incidents per actor, TTP matrices, campaign summaries, attribution confidence levels
6. THE Template_Engine SHALL format the Activities & Operations section with: significant incident case studies (3-5 incidents), containment actions taken (from Decision records), human correction statistics (from A12 feedback data)
7. THE Template_Engine SHALL include page numbers, section numbers, and a table of contents

### Requirement 9: PDF Export with Professional Styling

**User Story:** As a report recipient, I want PDF reports with professional styling matching CERT-In visual standards, so that reports are suitable for formal distribution to government agencies.

#### Acceptance Criteria

1. THE Export_Service SHALL render reports to PDF format using a PDF generation library (ReportLab or WeasyPrint)
2. THE Export_Service SHALL apply the following styling: A4 page size, 1-inch margins, 11pt serif font for body text, 14-16pt bold sans-serif for headings
3. THE Export_Service SHALL render tables with alternating row colors for readability
4. THE Export_Service SHALL render charts (bar, line, pie) for incident statistics, sector distributions, and trend timelines
5. THE Export_Service SHALL embed a configurable logo image on the cover page and page headers
6. THE Export_Service SHALL apply page breaks to ensure sections start on new pages
7. THE Export_Service SHALL generate PDF files within 90 seconds for annual reports containing up to 10,000 incidents

### Requirement 10: Markdown Export for Review and Editing

**User Story:** As a security analyst, I want reports exported as Markdown, so that I can review, edit, and collaborate on report content before final publication.

#### Acceptance Criteria

1. THE Export_Service SHALL render reports to Markdown format with standard CommonMark syntax
2. THE Export_Service SHALL structure Markdown output with: # for report title, ## for major sections, ### for subsections, #### for sub-subsections
3. THE Export_Service SHALL render tables using Markdown table syntax with proper column alignment
4. THE Export_Service SHALL render statistics as unordered lists with bold labels
5. THE Export_Service SHALL include metadata frontmatter (YAML) at the beginning of Markdown files containing: report_type, reporting_period, generated_at, hci_os_version
6. THE Export_Service SHALL save Markdown files with UTF-8 encoding and .md extension
7. THE Export_Service SHALL generate Markdown files within 5 seconds for reports of any size

### Requirement 11: JSON Export for Programmatic Access

**User Story:** As a systems integrator, I want reports exported as structured JSON, so that I can programmatically consume report data for dashboards, APIs, and data lakes.

#### Acceptance Criteria

1. THE Export_Service SHALL render reports to JSON format following a documented schema
2. THE Export_Service SHALL structure JSON output with top-level keys: metadata, executive_summary, statistics, sector_analysis, threat_attribution, recommendations, incidents
3. THE Export_Service SHALL include full Hypothesis and Decision objects in the incidents array
4. THE Export_Service SHALL ensure JSON is valid according to JSON Schema specification
5. THE Export_Service SHALL pretty-print JSON output with 2-space indentation
6. THE Export_Service SHALL save JSON files with UTF-8 encoding and .json extension
7. THE Export_Service SHALL generate JSON files within 10 seconds for reports of any size

### Requirement 12: HTML Export for Web Viewing

**User Story:** As a web portal administrator, I want reports exported as self-contained HTML, so that I can publish reports to internal web portals without additional formatting.

#### Acceptance Criteria

1. THE Export_Service SHALL render reports to HTML5 format with embedded CSS styling
2. THE Export_Service SHALL ensure HTML output is self-contained (no external stylesheet or script dependencies)
3. THE Export_Service SHALL apply responsive CSS that adapts to viewport widths from 768px to 1920px
4. THE Export_Service SHALL render tables using HTML <table> elements with sortable column headers (JavaScript-based)
5. THE Export_Service SHALL render charts as inline SVG elements or embedded Chart.js visualizations
6. THE Export_Service SHALL include a navigation menu with anchor links to major report sections
7. THE Export_Service SHALL generate HTML files within 15 seconds for reports of any size

### Requirement 13: Sensitive Information Redaction

**User Story:** As a data protection officer, I want sensitive information automatically redacted from reports, so that reports comply with data protection regulations and operational security requirements.

#### Acceptance Criteria

1. THE Redaction_Service SHALL identify and redact the following PII fields: user, email, username, user_id, hostname, asset_id, internal_domain
2. THE Redaction_Service SHALL replace internal IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) with placeholders "REDACTED_INTERNAL_IP_xxx"
3. THE Redaction_Service SHALL replace asset_id values with anonymized identifiers "ASSET_xxx" while maintaining consistency within a single report
4. THE Redaction_Service SHALL preserve public IP addresses, file hashes, and domains for threat intelligence value
5. THE Redaction_Service SHALL redact credential values, API keys, and authentication tokens using pattern matching (regex for common secret formats)
6. THE Redaction_Service SHALL generate a redaction summary showing: total fields redacted, redaction types applied, and whether any redaction failures occurred
7. WHEN Redaction_Service encounters ambiguous data (e.g., a number that might be a user ID or an incident count), THE Redaction_Service SHALL preserve the value and log a warning for manual review

### Requirement 14: Report Customization and Configuration

**User Story:** As a report administrator, I want configurable report templates and parameters, so that I can tailor reports for different audiences and organizational requirements.

#### Acceptance Criteria

1. THE Report_Generator SHALL accept the following parameters: reporting_period (date range), report_type (annual, quarterly, monthly), sector_filter (optional), output_formats (list of PDF, Markdown, JSON, HTML), include_appendices (boolean)
2. THE Report_Generator SHALL load template configurations from a JSON file at hci_os/reports/templates/config.json
3. THE Template_Engine SHALL support customization of: report title, organizational name, logo image path, color scheme (hex codes), font family
4. WHERE a sector_filter is specified, THE Report_Generator SHALL exclude incidents from other sectors and update statistics accordingly
5. WHERE include_appendices is false, THE Report_Generator SHALL omit detailed incident listings and include only summary statistics
6. THE Report_Generator SHALL validate all configuration parameters and return descriptive error messages for invalid inputs
7. THE Report_Generator SHALL save configuration parameters used for each report in the report metadata

### Requirement 15: Audit Trail and Report Provenance

**User Story:** As a compliance officer, I want an immutable audit trail of all report generation events, so that I can demonstrate report integrity and trace report lineage.

#### Acceptance Criteria

1. THE Report_Generator SHALL log report generation events to A12 audit_log.jsonl with entry_type "REPORT_GENERATED"
2. THE Report_Generator SHALL include the following fields in audit entries: report_id, report_type, reporting_period, generated_by (user or system), generated_at (ISO 8601 timestamp), data_sources_used (list), output_formats, redaction_summary, generation_duration_seconds
3. THE Report_Generator SHALL compute a SHA-256 hash over the final report content (before format conversion) and store it in the audit entry as report_content_hash
4. THE Report_Generator SHALL chain report audit entries using the same SHA-256 chaining mechanism as A12 Decision logs
5. WHEN a report is regenerated for the same period, THE Report_Generator SHALL create a new audit entry with a version field incremented from the previous entry
6. THE Report_Generator SHALL support audit trail verification via A12 verify_chain() function
7. THE Report_Generator SHALL store generated reports in hci_os/reports/output/ with filenames: {report_type}_{period_start}_{period_end}_{report_id}.{format}

### Requirement 16: Performance and Scalability

**User Story:** As a system administrator, I want report generation to complete within reasonable timeframes even for large datasets, so that analysts can generate reports on-demand without blocking other operations.

#### Acceptance Criteria

1. THE Report_Generator SHALL generate annual reports covering up to 10,000 incidents within 5 minutes
2. THE Report_Generator SHALL generate quarterly reports covering up to 2,500 incidents within 90 seconds
3. THE Report_Generator SHALL support concurrent report generation requests with a maximum of 3 simultaneous report jobs
4. WHEN a fourth report generation request arrives while 3 jobs are running, THE Report_Generator SHALL queue the request and process it when a job slot becomes available
5. THE Data_Aggregator SHALL use efficient JSONL streaming for reading audit_log.jsonl and cognitive_memory.jsonl to avoid loading entire files into memory
6. THE AI_Analyzer SHALL batch LLM generation requests to process multiple sections (executive summary, recommendations, trend analysis) in a single LLM call where possible
7. THE Export_Service SHALL write output files directly to disk in streaming mode rather than buffering complete reports in memory

### Requirement 17: RAG Integration for Historical Context

**User Story:** As a threat intelligence analyst, I want the AI analyzer to leverage historical incident data via RAG, so that reports include comparisons to similar past incidents and campaigns.

#### Acceptance Criteria

1. THE AI_Analyzer SHALL query the RAG system (rag_index.faiss) using incident semantic embeddings to retrieve similar historical incidents
2. WHEN generating campaign summaries, THE AI_Analyzer SHALL retrieve top 5 most similar past incidents per current incident and identify recurring patterns
3. THE AI_Analyzer SHALL use CERT-In advisories (cert_in_advisories.json) as reference documents in the RAG corpus
4. THE AI_Analyzer SHALL generate comparison statements such as "Similar to the SideWinder campaign observed in Q2 2022 (CIAD-2022-0089), targeting military establishments"
5. THE AI_Analyzer SHALL measure similarity using cosine similarity with threshold ≥ 0.85 for inclusion as "similar incident"
6. THE AI_Analyzer SHALL limit RAG retrieval to 50 queries per report to maintain performance targets
7. WHEN RAG retrieval fails or returns no similar incidents, THE AI_Analyzer SHALL proceed with analysis using only current period data

### Requirement 18: Federation Intelligence Integration

**User Story:** As a multi-stakeholder coordinator, I want reports to include anonymized threat intelligence shared via federation, so that reports reflect collective defense insights.

#### Acceptance Criteria

1. THE Report_Generator SHALL extract federated indicators from federation_store.json maintained by A13
2. THE Report_Generator SHALL compute federation statistics: total indicators received, indicators by type (IP, hash, domain), contributing organizations, indicators incorporated into local detections
3. THE Report_Generator SHALL include a "Cross-Organization Intelligence" section showing: total indicators shared by this organization, total indicators received, match rate (% of local incidents with federated indicator matches)
4. THE Report_Generator SHALL anonymize organization identifiers in federation data, replacing org_id values with generic labels "Partner_Org_A", "Partner_Org_B"
5. THE Report_Generator SHALL identify the top 5 most-shared IOC values (by number of contributing organizations) without revealing which organizations shared them
6. WHEN federation_store.json is empty or unavailable, THE Report_Generator SHALL omit the federation section and log a data availability warning
7. THE Report_Generator SHALL compute federation confidence boosts applied to local hypotheses per A13 boost calculations

### Requirement 19: MITRE ATT&CK Mapping and Visualization

**User Story:** As a threat researcher, I want visual MITRE ATT&CK heat maps showing TTP frequency, so that I can identify commonly observed adversary techniques and prioritize detection coverage.

#### Acceptance Criteria

1. THE Report_Generator SHALL extract MITRE ATT&CK TTP identifiers from Hypothesis mitre_chain fields
2. THE Report_Generator SHALL aggregate TTP frequency counts across all incidents in the reporting period
3. THE Report_Generator SHALL map TTPs to MITRE ATT&CK tactics (Reconnaissance, Initial Access, Execution, Persistence, etc.)
4. THE Report_Generator SHALL generate a heat map visualization showing TTP frequency per tactic using color intensity (white = 0 incidents, red = highest frequency)
5. THE Report_Generator SHALL include a TTP frequency table listing: TTP ID, TTP name, tactic, incident count, percentage of total incidents
6. THE Report_Generator SHALL identify the top 10 most frequently observed TTPs and highlight them in the report
7. THE Export_Service SHALL render MITRE ATT&CK heat maps as embedded images in PDF reports and interactive SVG in HTML reports

### Requirement 20: Human Feedback and Correction Statistics

**User Story:** As a quality assurance manager, I want reports to include human feedback statistics, so that stakeholders understand the level of analyst review and decision quality.

#### Acceptance Criteria

1. THE Report_Generator SHALL extract human correction records from audit_log.jsonl entries with entry_type "HUMAN_CORRECTION"
2. THE Report_Generator SHALL compute correction statistics: total decisions made, total decisions reviewed (human_reviewed=true), review rate percentage
3. THE Report_Generator SHALL compute correction type distribution: CONFIRM count, REVOKE count, MODIFY count, ESCALATE count
4. THE Report_Generator SHALL compute correction rate: (REVOKE + MODIFY + ESCALATE) / total decisions reviewed, expressed as percentage
5. THE Report_Generator SHALL compute trust-weighted consensus statistics: average consensus score for applied corrections, distribution of analyst roles (SENIOR, JUNIOR, EXTERNAL)
6. THE Report_Generator SHALL include a "Decision Quality Metrics" section showing: autonomous decision accuracy (CONFIRM rate), false positive rate (REVOKE rate), decision modification rate (MODIFY rate)
7. WHEN correction rate exceeds 15%, THE AI_Analyzer SHALL flag this as "elevated correction rate requiring model retraining" in the recommendations section

### Requirement 21: Report Versioning and Historical Comparison

**User Story:** As a security director, I want to compare current reports to previous reporting periods, so that I can track security posture improvements and identify long-term trends.

#### Acceptance Criteria

1. THE Report_Generator SHALL assign a unique report_id to each generated report using UUID4 format
2. THE Report_Generator SHALL store report metadata (not full content) in a reports_metadata.json file containing: report_id, report_type, reporting_period, generated_at, incident_count, top_sector, top_threat_actor
3. THE Report_Generator SHALL support a comparison mode that accepts two report_ids and generates a delta report
4. WHEN generating delta reports, THE Report_Generator SHALL compute and display: incident volume change (absolute and percentage), sector targeting changes, threat actor activity changes, new vs recurring TTPs
5. THE Report_Generator SHALL display trend lines showing incident volume over the last 4 reporting periods (e.g., last 4 quarters for quarterly reports)
6. THE Report_Generator SHALL identify "new this period" elements: new threat actors, new TTPs, new targeted sectors
7. THE Report_Generator SHALL maintain report file history in hci_os/reports/output/ with timestamped filenames to prevent overwriting

### Requirement 22: Error Handling and Data Quality Validation

**User Story:** As a system operator, I want the report generator to validate data quality and handle errors gracefully, so that partial data or system failures do not block report generation.

#### Acceptance Criteria

1. WHEN audit_log.jsonl is missing or empty, THE Report_Generator SHALL log a critical error and terminate with error message "Insufficient data: audit log unavailable"
2. WHEN cognitive_memory.jsonl is missing, THE Report_Generator SHALL log a warning and proceed with audit log data only
3. WHEN federation_store.json is missing, THE Report_Generator SHALL log a warning and omit federation sections
4. WHEN cert_in_advisories.json is missing, THE Report_Generator SHALL log a warning and proceed without advisory correlation
5. THE Data_Aggregator SHALL validate data integrity by checking for required fields in each record type (Decision must have decision_id, action_taken, risk_score; Hypothesis must have hypothesis_id, goal, confidence)
6. WHEN invalid records are encountered, THE Data_Aggregator SHALL skip the invalid record, log a validation error with record identifier, and continue processing
7. THE Report_Generator SHALL include a "Data Quality Summary" section in report metadata showing: total records processed, invalid records skipped, data sources unavailable, coverage percentage

### Requirement 23: LLM Integration and Prompt Engineering

**User Story:** As a content quality reviewer, I want AI-generated content to follow consistent prompt templates and quality standards, so that reports maintain professional tone and factual accuracy.

#### Acceptance Criteria

1. THE AI_Analyzer SHALL use LangChain framework for LLM integration with support for model switching (OpenAI GPT-4, Anthropic Claude, local models)
2. THE AI_Analyzer SHALL use structured prompts with the following components: role definition, task description, input data summary, output format specification, constraints (no speculation, factual only)
3. THE AI_Analyzer SHALL enforce maximum token limits per LLM call: 4000 tokens for executive summaries, 6000 tokens for trend analysis, 3000 tokens for recommendations
4. WHEN LLM responses exceed specified word counts, THE AI_Analyzer SHALL truncate responses at the nearest sentence boundary
5. THE AI_Analyzer SHALL validate LLM outputs for: no hallucinated statistics (all numbers must exist in input data), no unsubstantiated attribution claims, no speculative language ("possibly", "might", "could indicate")
6. WHEN LLM output validation fails, THE AI_Analyzer SHALL retry generation up to 2 additional times with refined prompts before falling back to template-based generation
7. THE AI_Analyzer SHALL log all LLM interactions (prompt, response, tokens used, generation time) to a separate llm_generation_log.jsonl file for quality auditing

### Requirement 24: Report Parser and Round-Trip Validation

**User Story:** As a data engineer, I want a report parser that can read generated reports back into structured format, so that I can validate report integrity and enable programmatic report analysis.

#### Acceptance Criteria

1. THE Report_Generator SHALL provide a Parser component that reads JSON-format reports and reconstructs report data structures
2. THE Parser SHALL validate JSON reports against a JSON Schema specification file at hci_os/reports/schema/report_schema.json
3. THE Parser SHALL extract all statistics, incident records, and metadata from JSON reports into Python objects
4. THE Report_Generator SHALL provide a Pretty_Printer component that formats report data structures back into JSON reports
5. FOR ALL valid report data objects, parsing a JSON report then pretty-printing then parsing again SHALL produce an equivalent report data object (round-trip property)
6. THE Parser SHALL return descriptive error messages for malformed reports including: line number of first error, error type (missing field, type mismatch, schema violation), suggested fix
7. THE Report_Generator SHALL include unit tests validating round-trip property for 10 representative report configurations (annual, quarterly, different sectors, with/without appendices)

### Requirement 25: CLI and API Interface

**User Story:** As a DevOps engineer, I want both CLI and Python API interfaces for report generation, so that I can integrate report generation into automated workflows and manual operations.

#### Acceptance Criteria

1. THE Report_Generator SHALL provide a CLI entry point at hci_os/reports/cli.py accepting arguments: --period-start, --period-end, --type {annual,quarterly,monthly}, --sector, --formats, --output-dir
2. THE CLI SHALL display progress indicators showing: data collection progress, AI analysis progress, export progress
3. THE CLI SHALL return exit code 0 on success, non-zero on failure
4. THE CLI SHALL support a --dry-run flag that validates inputs and displays report configuration without generating files
5. THE Report_Generator SHALL provide a Python API class ReportGenerator with methods: generate(), configure(), validate_config()
6. THE Python API SHALL support both synchronous and asynchronous report generation modes
7. THE Python API SHALL raise descriptive exceptions for error conditions: InsufficientDataError, InvalidConfigurationError, ExportFailedError

