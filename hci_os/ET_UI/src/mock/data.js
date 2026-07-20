// Mock data for HCI-OS UI. All timestamps are relative to incident T-0.
// Hypothesis: HYP-2026-014 (CBSE-like exfiltration attempt).

export const INCIDENT = {
  hypothesis_id: "HYP-2026-014",
  title: "Suspected Lateral Movement → Crown Jewel Exfiltration",
  target: "CBSE Grade-12 Result DB",
  detection_ts: "2026-01-14T09:12:04Z",
  status: "CONTAINED",
  confidence: 0.94,
  mitre_chain: ["T1190", "T1078", "T1021.002", "T1041"],
  cert_in_deadline_hours: 6,
  affected_assets: [
    { id: "web-01", name: "web-01.cbse.gov.in", criticality: "HIGH" },
    { id: "app-03", name: "app-03.internal", criticality: "HIGH" },
    { id: "db-crown-01", name: "db-crown-01 (Result DB)", criticality: "CROWN_JEWEL" },
  ],
  iocs: [
    { type: "ip", value: "185.203.116.44", note: "Known TOR exit" },
    { type: "hash", value: "9f2c3b4e2a71d6...c93b", note: "Cobalt Strike beacon" },
    { type: "domain", value: "cdn-updates[.]xyz", note: "C2 beacon" },
  ],
};

// Timeline events T-0 .. T+43s
export const TIMELINE_EVENTS = [
  { t: 0, type: "EVIDENCE", severity: "warning", title: "Anomalous HTTP POST", asset: "web-01", confidence: 0.61, description: "Outbound POST /api/exec.php with base64 payload > 8KB.", evidence_ref: "EV-91021" },
  { t: 3, type: "EVIDENCE", severity: "suspicious", title: "Auth bypass signature match", asset: "web-01", confidence: 0.78, description: "Signature CVE-2025-33421 matched on Apache Struts endpoint.", evidence_ref: "EV-91022" },
  { t: 6, type: "HYPOTHESIS", severity: "suspicious", title: "Hypothesis generated: WebSvr → AppSrv pivot", asset: "web-01", confidence: 0.82, description: "A3-Reasoner links EV-91021 & EV-91022. Predicts lateral to app-03.", evidence_ref: "HYP-2026-014" },
  { t: 9, type: "EVIDENCE", severity: "suspicious", title: "SMB session opened app-03", asset: "app-03", confidence: 0.86, description: "app-03 accepted SMB session from web-01 svc-account.", evidence_ref: "EV-91027" },
  { t: 12, type: "CRITIC", severity: "info", title: "A4-Critic challenge issued", asset: "—", confidence: 0.9, description: "Adversarial critic ruled out benign patch-management explanation (score 0.11).", evidence_ref: "CR-4401" },
  { t: 17, type: "EVIDENCE", severity: "critical", title: "Crown-jewel DB read spike", asset: "db-crown-01", confidence: 0.92, description: "Result DB reads jumped 640× baseline in 4s. Row count ≈ 1.2M.", evidence_ref: "EV-91039" },
  { t: 21, type: "DECISION", severity: "critical", title: "Decision proposed: isolate app-03", asset: "app-03", confidence: 0.93, description: "A7-SOAR proposes network isolation of app-03 (blast_radius=LOW).", evidence_ref: "DEC-77014" },
  { t: 23, type: "HUMAN_GATE", severity: "warning", title: "Human Gate: awaiting confirm", asset: "app-03", confidence: 0.93, description: "SOC analyst review required (SLA 15m). Confirmed at T+27s.", evidence_ref: "DEC-77014" },
  { t: 27, type: "ACTION", severity: "clean", title: "app-03 isolated (VLAN quarantine)", asset: "app-03", confidence: 0.99, description: "SOAR playbook PB-ISO-02 executed. Reversible in 60s.", evidence_ref: "ACT-33012" },
  { t: 31, type: "DECISION", severity: "critical", title: "Decision: block egress to 185.203.116.44", asset: "edge-fw-01", confidence: 0.95, description: "Firewall rule pushed. Global block list updated.", evidence_ref: "DEC-77015" },
  { t: 36, type: "ACTION", severity: "clean", title: "Egress blocked at edge firewall", asset: "edge-fw-01", confidence: 1.0, description: "Rule ACL-EG-9931 active. Exfil channel severed.", evidence_ref: "ACT-33013" },
  { t: 43, type: "CONTAIN", severity: "clean", title: "Incident CONTAINED", asset: "—", confidence: 1.0, description: "No further beaconing. Crown Jewel integrity verified via A8-hash-chain.", evidence_ref: "ACT-33014" },
];

// Graph for Cytoscape
export const GRAPH = {
  nodes: [
    { data: { id: "internet", label: "Internet", severity: "suspicious", kind: "cloud" } },
    { data: { id: "edge-fw-01", label: "edge-fw-01", severity: "clean", kind: "firewall" } },
    { data: { id: "web-01", label: "web-01", severity: "critical", kind: "server" } },
    { data: { id: "app-03", label: "app-03", severity: "critical", kind: "server" } },
    { data: { id: "app-02", label: "app-02", severity: "clean", kind: "server" } },
    { data: { id: "auth-svc", label: "auth-svc", severity: "suspicious", kind: "service" } },
    { data: { id: "db-crown-01", label: "db-crown-01", severity: "critical", kind: "crown" } },
    { data: { id: "db-audit", label: "db-audit", severity: "clean", kind: "db" } },
  ],
  edges: [
    { data: { id: "e1", source: "internet", target: "edge-fw-01", weight: 0.9, kind: "attack" } },
    { data: { id: "e2", source: "edge-fw-01", target: "web-01", weight: 0.85, kind: "attack" } },
    { data: { id: "e3", source: "web-01", target: "app-03", weight: 0.78, kind: "attack" } },
    { data: { id: "e4", source: "app-03", target: "db-crown-01", weight: 0.92, kind: "attack" } },
    { data: { id: "e5", source: "app-03", target: "auth-svc", weight: 0.4, kind: "predicted" } },
    { data: { id: "e6", source: "auth-svc", target: "db-audit", weight: 0.3, kind: "predicted" } },
    { data: { id: "e7", source: "web-01", target: "app-02", weight: 0.2, kind: "blocked" } },
    { data: { id: "e8", source: "app-03", target: "db-crown-01", weight: 0.0, kind: "blocked_extra", parallel: true } },
  ],
};

// Pending decisions for Human Gate
export const PENDING_DECISIONS = [
  {
    decision_id: "DEC-77016",
    hypothesis_id: "HYP-2026-014",
    action_taken: "Force-rotate svc-cbse-app credentials",
    risk_score: 0.72,
    blast_radius_score: 0.18,
    blast_radius_label: "LOW",
    proposed_by: "A7-SOAR",
    ts_iso: "2026-01-14T09:13:07Z",
    sla_seconds_left: 812,
  },
  {
    decision_id: "DEC-77017",
    hypothesis_id: "HYP-2026-014",
    action_taken: "Quarantine host app-04 (predicted next hop)",
    risk_score: 0.65,
    blast_radius_score: 0.34,
    blast_radius_label: "MEDIUM",
    proposed_by: "A5-GNN",
    ts_iso: "2026-01-14T09:13:11Z",
    sla_seconds_left: 598,
  },
  {
    decision_id: "DEC-77018",
    hypothesis_id: "HYP-2026-014",
    action_taken: "Push YARA rule y_cobalt_v3 to all endpoints",
    risk_score: 0.41,
    blast_radius_score: 0.12,
    blast_radius_label: "LOW",
    proposed_by: "A9-Response",
    ts_iso: "2026-01-14T09:13:18Z",
    sla_seconds_left: 244,
  },
];

// Digital twin simulated attack path
export const TWIN_PATH = [
  { t: 0, node: "internet", label: "External recon" },
  { t: 2, node: "web-01", label: "Struts exploit" },
  { t: 9, node: "app-03", label: "SMB pivot" },
  { t: 14, node: "auth-svc", label: "Kerberoast" },
  { t: 21, node: "db-crown-01", label: "Bulk read" },
];

// Chatbot canned responses
export const CHATBOT_RESPONSES = {
  default:
    "I can explain hypotheses, decisions, and predicted next moves. Try: 'why was app-03 isolated?' or 'what's the next predicted hop?'",
  "why was this flagged":
    "This incident was flagged because A3-Reasoner correlated Evidence EV-91021 (base64 POST) and EV-91022 (CVE-2025-33421 signature) with a confidence of 0.82 — see Hypothesis HYP-2026-014.",
  "why was app-03 isolated":
    "app-03 was quarantined at T+27s after Decision DEC-77014 (blast_radius=LOW) was confirmed by SOC analyst 'a.sharma'. The trigger was a 640× read spike on db-crown-01 from an app-03 session.",
  "what's the next predicted move":
    "A5-GNN predicts lateral movement app-03 → auth-svc (attention weight 0.40), followed by auth-svc → db-audit (0.30). A quarantine on app-04 is pending your approval as DEC-77017.",
  "next predicted hop":
    "auth-svc — GAT attention weight 0.40. Consider pre-emptively rotating svc-account credentials (see DEC-77016).",
  "isolate the host":
    "Isolating app-03 severs the SMB pivot path used by the actor. Reversible in <60s via SOAR playbook PB-ISO-02. Estimated business impact: 12 non-critical batch jobs delayed.",
};

export const ROLES = [
  { id: "sysadmin", label: "SysAdmin", short: "SYS", email: "root@hci-os" },
  { id: "soc", label: "SOC Analyst", short: "SOC", email: "a.sharma@cbse.gov.in" },
  { id: "reviewer", label: "Reviewer", short: "REV", email: "r.gupta@cbse.gov.in" },
  { id: "ciso", label: "CISO", short: "CISO", email: "s.iyer@cbse.gov.in" },
];

export const AUDIT_LOG = [
  { ts: "T+21.001s", actor: "A7-SOAR", event: "propose_action", target: "DEC-77014", hash: "0x8f3a...c19b" },
  { ts: "T+23.402s", actor: "A2-HumanGate", event: "gate_open", target: "DEC-77014", hash: "0x91cd...44a2" },
  { ts: "T+27.118s", actor: "a.sharma", event: "confirm", target: "DEC-77014", hash: "0x77aa...2ee1" },
  { ts: "T+27.203s", actor: "A7-SOAR", event: "exec_playbook", target: "PB-ISO-02", hash: "0x0bcd...9013" },
  { ts: "T+31.559s", actor: "A9-Response", event: "propose_action", target: "DEC-77015", hash: "0x22ea...aa10" },
  { ts: "T+36.010s", actor: "edge-fw-01", event: "apply_acl", target: "ACL-EG-9931", hash: "0xc0ff...ee42" },
];
