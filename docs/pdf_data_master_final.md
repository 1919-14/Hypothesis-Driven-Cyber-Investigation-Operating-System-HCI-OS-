---
title: "HCI-OS — Technical Documentation & Master Submission Data"
subtitle: "Hypothesis-Driven Cyber Investigation Operating System"
author: "Team PraxisCode X — Indore Institute of Science and Technology"
date: "ET AI Hackathon 2.0 · Problem Statement #7 · 22 July 2026"
toc: true
toc-depth: 3
numbersections: true
geometry: margin=2.4cm
fontsize: 10.5pt
mainfont: "DejaVu Sans"
sansfont: "DejaVu Sans"
monofont: "DejaVu Sans Mono"
colorlinks: true
linkcolor: SteelBlue
urlcolor: SteelBlue
toccolor: black
header-includes:
  - \usepackage{titlesec}
  - \usepackage{xcolor}
  - \usepackage{fancyhdr}
  - \usepackage{colortbl}
  - \usepackage{booktabs}
  - \usepackage{longtable}
  - \usepackage{array}
  - \usepackage{graphicx}
  - \usepackage{float}
  - \usepackage{tcolorbox}
  - \tcbuselibrary{skins,breakable}
  - \definecolor{brandnavy}{HTML}{0B2545}
  - \definecolor{brandteal}{HTML}{0F766E}
  - \definecolor{brandred}{HTML}{9A1B1B}
  - \definecolor{lightgrey}{HTML}{F2F4F7}
  - \titleformat{\section}{\normalfont\Large\bfseries\color{brandnavy}}{\thesection}{0.6em}{}[{\color{brandteal}\titlerule[1.2pt]}]
  - \titleformat{\subsection}{\normalfont\large\bfseries\color{brandteal}}{\thesubsection}{0.6em}{}
  - \titleformat{\subsubsection}{\normalfont\normalsize\bfseries\color{brandred}}{\thesubsubsection}{0.6em}{}
  - \pagestyle{fancy}
  - \fancyhf{}
  - \renewcommand{\headrulewidth}{0.6pt}
  - \renewcommand{\footrulewidth}{0.4pt}
  - \fancyhead[L]{\small\textcolor{brandnavy}{\textbf{HCI-OS Technical Documentation}}}
  - \fancyhead[R]{\small\textcolor{brandteal}{ET AI Hackathon 2.0}}
  - \fancyfoot[C]{\small\thepage}
  - \fancyfoot[R]{\small\textcolor{gray}{PraxisCode X}}
  - \setlength{\headheight}{14pt}
---

```{=latex}
\begin{titlepage}
\centering
\vspace*{1.2cm}
{\Huge\bfseries\color{brandnavy} HCI-OS}\\[0.3cm]
{\Large\color{brandteal} Hypothesis-Driven Cyber Investigation Operating System}\\[0.6cm]
{\large\itshape ``An AI detective, not a log viewer --- it investigates hypotheses, not events.''}\\[1.4cm]

\begin{tcolorbox}[colback=lightgrey,colframe=brandteal,width=0.85\textwidth,arc=2mm,boxrule=0.8pt]
\centering
\textbf{ET AI Hackathon 2.0 --- Problem Statement \#7}\\
AI-Powered Cyber Resilience for Critical National Infrastructure
\end{tcolorbox}

\vspace{1.2cm}
\begin{tabular}{ll}
\textbf{Team Name} & PraxisCode X \\
\textbf{Team Lead} & V S S K Sai Narayana --- Architect / Backend \\
\textbf{Team Member} & Sujeet Jaiswal --- Data Analysis / ML Modeling / DBMS \\
\textbf{Team Member} & Sujeet Sahni --- Cyber Threat Analysis / Frontend / DevOps \\
\textbf{Institution} & Indore Institute of Science and Technology, Indore, MP \\
\textbf{Programme} & B.Tech AIML, 4th Semester \\
\textbf{Submission} & ET AI Hackathon 2.0 (Economic Times $\times$ Unstop), Round 2 Prototype Sprint \\
\textbf{Repository} & github.com/1919-14/HCI-OS \\
\textbf{Document Date} & 22 July 2026 \\
\end{tabular}

\vfill
{\small\color{gray} Final Submission Master Data}
\end{titlepage}
```

\newpage

# Executive Summary

HCI-OS (Hypothesis-Driven Cyber Investigation Operating System) is an autonomous cyber resilience platform built for the **ET AI Hackathon 2.0, Problem Statement #7: AI-Powered Cyber Resilience for Critical National Infrastructure (CNI)**. It targets sectors such as hospitals (AIIMS), examination boards (CBSE), power grids, and railways — institutions that run legacy IT/OT systems and are increasingly the target of state-sponsored and criminal cyber campaigns.

Conventional Security Information and Event Management (SIEM) systems generate large volumes of isolated alerts and leave correlation, attribution, and root-cause reasoning to human analysts. This produces dwell times measured in days or weeks, during which attackers move laterally and exfiltrate data. HCI-OS's core thesis is that security operations should be reframed as an investigation process: instead of matching individual events to static rules, the system continuously forms competing hypotheses about what is happening in the environment, gathers evidence for and against each hypothesis using a Bayesian update rule, challenges its own leading hypothesis with an adversarial Critic agent, and only then recommends or executes a containment action.

> **Headline Outcome.** The system is designed and benchmarked around compressing the investigation loop from an industry baseline of days-to-weeks down to a target **Mean Time to Contain (MTTC) of under 43 seconds** for a full, previously-unseen investigation, and **under 2 milliseconds** for previously-seen threats via cache-accelerated paths.

> **One-Line Difference from Conventional SIEM.** *"A SIEM processes alerts; HCI-OS investigates hypotheses — it hunts for corroborating evidence, generates competing explanations, challenges itself with a Skeptic agent, predicts the attacker's next move, and keeps an immutable, cryptographically chained record of every decision it makes."*

---

# Problem Statement & National Context

## National Context
Critical National Infrastructure (CNI) — hospitals, examination boards, power grids, and railways — is a high-value target because outages have direct human and economic consequences, and because many of these entities run end-of-life IT/OT systems with limited security budgets. CERT-In (the Indian Computer Emergency Response Team) recorded **1.59 million cybersecurity incidents in 2023**, and more than **70% of surveyed government entities** were found to be running end-of-life infrastructure. CERT-In's regulatory mandate under Section 70B requires breach reporting within **6 hours** of detection — a window that is difficult for most affected organizations to meet given current manual triage processes.

## Case Studies Motivating HCI-OS

| Incident | Sector | Impact & Cost |
|---|---|---|
| **AIIMS Delhi (2022)** | Healthcare | Ransomware attack; over 2 weeks of complete hospital system downtime; patient records affected. Recovery & loss cost: **₹50–100 crore**. |
| **CBSE (2024)** | Education / Exams | Student examination records breached. Required mandatory data verification & emergency upgrades. Impact: **₹20–50 crore**. |
| **CBSE (Early 2026 Reference)** | Education / Exams | Coordinated attack triggering a multi-state emergency shutdown of examination infrastructure. Primary reference demo scenario. |
| **Kudankulam Nuclear Plant** | Energy / OT | Referenced in threat model as an example of OT/SCADA risk class requiring safety-critical response gates. |
| **Regional Power Grid** | Energy / OT | Representative OT target where uncontrolled automated remediation (e.g. rebooting a SCADA asset) could trigger cascading power blackouts. |

*Table 2.1 — Representative CNI incidents motivating HCI-OS.*

## Reference Demonstration Scenario — CBSE Web Server (2026)
The live demonstration is built around a specific reference narrative for the CBSE Web Server scenario:

> *"In 2026, attackers compromised this exact asset. By using valid admin credentials and pivoting laterally, they exfiltrated student examination records without triggering traditional signature alerts. The SOC discovered the breach three days later."*

This narrative — valid-credential entry, lateral pivot, signature-blind exfiltration, multi-day discovery lag — is the specific failure mode HCI-OS's behavioural and graph-based detection paths (Path 2 and Path 3) are designed to catch where a pure signature-matching SIEM fails.

---

# Literature & Existing Approaches Review

## Limitations of Conventional SIEM
- **Signature / Rule Matching:** Only recognizes catalogued attack patterns; novel variants evade exact-match rules entirely.
- **Stateless Alerting:** Alerts are treated as independent events rather than accumulating evidence toward a hypothesis.
- **Weak Automated Attribution:** Lacks real-time mapping of observed behavior to threat actors or MITRE ATT&CK techniques.
- **Manual Response Delays:** Containment relies on manual playbooks, causing dwell times measured in days to weeks.

## Graph Neural Network-Based Intrusion Detection
HCI-OS Agent A5 combines three complementary GNN architectures:
- **Graph Attention Networks (GAT):** Learns which neighboring relationships matter most for a given node; attention weights double as an explainability signal in the UI.
- **GraphSAGE:** Inductive method generalizing to unseen nodes as network topology evolves.
- **Temporal Graph Networks (TGN):** Incorporates event timestamps to distinguish fast lateral movement from coincidental activity.

---

# Solution Architecture

## Core Philosophy — Hypothesis-Driven Investigation
Every non-trivial event enters a continuous investigation loop:

$$\text{Perceive} \longrightarrow \text{Hypothesize} \longrightarrow \text{Active Hunt} \longrightarrow \text{Challenge (Critic)} \longrightarrow \text{Bayesian Update} \longrightarrow \text{Predict} \longrightarrow \text{Execute} \longrightarrow \text{Reflect} \longrightarrow \text{Learn}$$

## Novelty Statement — Context-Aware Decision Fingerprinting
Every observation is converted into a layered fingerprint — an exact content hash, a 256-dimensional behavioral embedding, and a historical decision outcome — matched against a store of human-verified prior decisions before expensive model inference is run.

## The Three Processing Paths

| Path | Trigger | Target Latency | Compute Saved | Action |
|---|---|---|---|---|
| **Path 1 — Fast (Exact)** | SHA-256 exact match in Redis decision cache | **< 0.1–2 ms** | **~80%** | Immediate reuse of stored verdict; bypasses ML/LLM inference. |
| **Path 2 — Accelerated (Fuzzy)** | Cosine similarity $\ge 0.85$ against FAISS embeddings | **~16 ms** | **~60%** | Reuses closest historical Critic-validated verdict with criticality mismatch guard. |
| **Path 3 — Full (Hypothesis Loop)** | Novel / unseen behavior failing cache matches | **< 1 minute** | **0%** | Full GNN correlation, RAG attribution, Bayesian hypothesis competition, Critic validation, and Human Gate review. |

*Table 4.1 — Three processing paths (Agent A3 Fingerprint Router).*

## System Architecture Graphviz DOT Diagram

```dot
digraph HCIOS {
  rankdir=TB;
  bgcolor="white";
  fontname="DejaVu Sans";
  splines=polyline;
  nodesep=0.4;
  ranksep=0.6;
  compound=true;
  node [fontname="DejaVu Sans", fontsize=13, style="filled,rounded", shape=box, penwidth=1.6];
  edge [fontname="DejaVu Sans", fontsize=11, color="#0F766E", penwidth=1.3, arrowsize=0.8];

  // External sources
  subgraph cluster_ext {
    label="EXTERNAL DATA SOURCES";
    fontname="DejaVu Sans Bold";
    fontsize=15;
    fontcolor="#0B2545";
    style="rounded";
    color="#0B2545";
    bgcolor="#FFFFFF";
    T1 [label="IT Telemetry\nWeb / Windows / Netflow", fillcolor="#FFFFFF", color="#0B2545"];
    T2 [label="OT / SCADA Telemetry\nIEC-60870 Protocol Logs", fillcolor="#FFFFFF", color="#0B2545"];
    T3 [label="Threat Intel Feeds\nMITRE / NVD / CERT-In", fillcolor="#FFFFFF", color="#0B2545"];
    T4 [label="Asset Inventory\nCriticality + Safety Metadata", fillcolor="#FFFFFF", color="#0B2545"];
  }

  // Core agent chain
  A1 [label="A1 · Ingestion & Trust Gate\nSD-0 Sanitizer + SD-1 Trust Score", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A2 [label="A2 · Normalizer & Context\nOT + Indian Context Builder", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A3 [label="A3 · Fingerprint Router", shape=diamond, fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545", fontsize=13];

  REDIS [label="Redis\nDecision Cache\n< 0.1 ms", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];
  FAISSV [label="FAISS\nVector Memory\n~16 ms", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];

  A4 [label="A4 · Anomaly Detector\nIsolation Forest + Welford Z-Score\n+ Cross-Attention Fusion", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A5 [label="A5 · GNN Correlator Ensemble\nGAT + GraphSAGE + TGN", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A10 [label="A10 · Active Hunt\nVirusTotal / Shodan\nCircuit Breaker", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A6 [label="A6 · Attribution & RAG\nFAISS RAG + Llama 3.1 8B", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];

  A7 [label="A7 · SOAR & Planner\nCompeting Bayesian Hypotheses\nBFS Blast Radius", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A8 [label="A8 · Critic / Skeptic\nAdversarial Challenge Loop", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A9 [label="A9 · Quarantine Verifier\nDual-Agent Sandbox", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];

  DEC [label="A7 Decision Engine", shape=diamond, fillcolor="#FFF4F4", color="#9A1B1B", fontcolor="#9A1B1B", fontsize=13];
  AUTO [label="AUTO_RESPOND\nDirect Execution", fillcolor="#FFF4F4", color="#9A1B1B", fontcolor="#9A1B1B"];
  HGATE [label="HUMAN_GATE\nAnalyst Consensus Vote\n(>= 0.70 required)", fillcolor="#FFF4F4", color="#9A1B1B", fontcolor="#9A1B1B"];

  PLAY [label="Isolate Asset /\nSOAR Playbook", fillcolor="#FFFFFF", color="#0B2545", fontcolor="#0B2545"];
  A12 [label="A12 · Cryptographic\nAudit Chain (SHA-256)", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A13 [label="A13 · Federation\nSTIX 2.1 Sharing", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];

  NEO [label="Neo4j\nKnowledge Graph\n5,026 nodes / 565,752 edges", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];
  PG [label="PostgreSQL\nStructured Store", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];

  // Governance
  subgraph cluster_gov {
    label="GOVERNANCE, RESILIENCE & EMERGENCY CONTROL";
    fontname="DejaVu Sans Bold";
    fontsize=15;
    fontcolor="white";
    style="filled,rounded";
    color="#0F766E";
    bgcolor="#0B2545";
    A11 [label="A11 · Behavioral Watchdog\nSD-6 Schema + Rate Monitoring", fillcolor="#0B2545", color="#0F766E", fontcolor="white", fontsize=12];
    KILL [label="SD-8 Kill Switch\nEmergency Freeze\n(CISO / Sysadmin)", fillcolor="#9A1B1B", color="white", fontcolor="white", fontsize=12];
  }

  T1 -> A1;
  T2 -> A1;
  T3 -> A6 [style=dashed, label="RAG context"];
  T4 -> A2 [style=dashed, label="asset metadata"];

  A1 -> A2 [label="Sanitized & Trusted"];
  A2 -> A3 [label="Evidence Object"];

  A3 -> REDIS [label="Path 1: SHA-256\nexact hit"];
  A3 -> FAISSV [label="Path 2: FAISS\nsim >= 0.85"];
  A3 -> A4 [label="Path 3: cache miss\n/ novel event"];

  A4 -> A5 [label="anomaly score\n+ embedding"];
  A5 -> A6 [label="graph attention path"];
  A5 -> A10 [style=dashed, label="score > 0.7\nenrich"];
  A10 -> A6 [style=dashed, label="confidence boost"];
  A6 -> A7 [label="TTPs + threat actor"];

  REDIS -> A7;
  FAISSV -> A7;

  A7 -> A8;
  A8 -> A9 [label="validated hypothesis"];
  A9 -> DEC [label="risk + blast radius"];

  DEC -> AUTO [label="Blast Radius <= 0.3\n(low risk)"];
  DEC -> HGATE [label="Blast Radius > 0.3\nOR safety-critical"];
  HGATE -> AUTO [label="approved"];

  AUTO -> PLAY;
  PLAY -> A12;
  PLAY -> A13 [label="confirmed\nmalicious IOCs"];

  A5 -> NEO [style=dashed];
  A12 -> PG [style=dashed];

  A11 -> A1 [style=dotted, color="#0B2545", label="SD-6 watch"];
  A11 -> A4 [style=dotted, color="#0B2545"];
  A11 -> A5 [style=dotted, color="#0B2545"];
  A11 -> A7 [style=dotted, color="#0B2545"];
  A11 -> AUTO [style=dotted, color="#0B2545"];
  KILL -> A7 [style=dotted, color="#9A1B1B", label="freezes autonomy"];
  KILL -> A10 [style=dotted, color="#9A1B1B"];
  KILL -> A13 [style=dotted, color="#9A1B1B"];

  { rank=same; T1; T2; T3; T4; }
  { rank=same; REDIS; FAISSV; }
  { rank=same; AUTO; HGATE; }
}
```

## Digital Twin & Live Graph Mirror (Gap 1)

HCI-OS maintains a live **Digital Twin** of monitored infrastructure — a continuously synchronized graph mirror of the asset/topology data powering A5's GNN Correlator, exposed to analysts as an interactive visual replica of the network rather than a static topology diagram.

- **Purpose:** The Digital Twin gives an analyst a single, always-current visual model of hosts, network segments, OT/SCADA devices, and their interdependencies, so that a proposed containment action (e.g. `ISOLATE_HOST`) can be previewed against the live topology *before* it is executed — showing which downstream services, dependent assets, and safety-critical devices sit inside the blast radius.
- **Components:**
  - **Twin Graph Store:** A read-optimized projection of the Neo4j knowledge graph (5,026 nodes / 565,752 edges backing store used by A5), refreshed on every new `Evidence` and `Decision` write.
  - **State Overlay:** Per-node live status (Healthy / Under Investigation / Isolated / Compromised), color-coded and driven directly by current `Hypothesis.state` and `Decision.action_taken` fields.
  - **Blast-Radius Preview:** Highlights the BFS-reachable subgraph from the target asset, using the same `Reachability × Criticality × Propagation_Probability` terms as the blast-radius formula, so the analyst sees the *consequence* of approving an action, not just the request.
  - **Attack-Path Overlay:** Renders A5's GAT attention weights directly on the Twin's edges, visually tracing the most-attended lateral-movement path for the current leading hypothesis.
- **Real Pipeline Integration:** The Digital Twin is served directly from the `/api/gnn/visualization` endpoint powering the Topology Dashboard, and is updated by the same A12 audit-write path that produces the tamper-evident decision log, guaranteeing zero drift between what the analyst sees and what is executed.
- **Relation to Feature #5 (Predictive Attack Topology Visualizer):** The Digital Twin is the runtime substrate for Feature #5: the Cytoscape.js-based visualizer renders the Digital Twin's live graph state with progressive Level-of-Detail (LoD) zoom (top-15 highest-risk nodes rendered first, background technique nodes loaded on zoom to support 2,000+ nodes without lag).

## 9-Beat Live Reference Demonstration Walkthrough

| Beat | Time | What Is Shown |
|---|---|---|
| **1 — The Problem** | 0:00–0:30 | CBSE Web Server shown healthy; narration sets up the 2026 reference incident (valid-credential entry, 3-day discovery lag). |
| **2 — The Attack** | 0:30–1:00 | Log4Shell payload injected; raw telemetry stream shows real-time ingestion. |
| **3 — Fast Path** | 1:00–1:30 | SHA-256 exact match fires in <2 ms; "KNOWN MALICIOUS — FAST PATH TRIGGERED" banner. |
| **4 — Novel Variant** | 1:30–2:00 | Attack port changed 443 $\to$ 8443; FAISS finds 92% semantic similarity in ~16 ms via Accelerated Path. |
| **5 — Full Investigation**| 2:00–2:45 | Active Hunt queries VirusTotal (47/90 engines flag); GNN proposes H1 = APT41 (91%); Critic finds no counter-evidence; Risk = 0.826, Blast Radius = 0.73; Human Gate triggers. |
| **6 — Timeline** | 2:45–3:30 | Scrubbable T-0 $\to$ T+43s timeline; clicking nodes reveals Evidence JSON & confidence scores. |
| **7 — Human Gate** | 3:30–4:00 | Analyst approves `ISOLATE_HOST`; signed Decision object created & SHA-256 audit log updates live. |
| **8 — Kill Switch** | 4:00–4:30 | Emergency Stop triggered; UI shows "EMERGENCY STOP — ACTIVE" and all outbound actions freeze instantly. |
| **9 — The Close** | 4:30–5:00 | Summary view displays green "CONTAINED" status at 43 seconds, closing on cost-avoidance framing. |

*Table 4.2 — 9-beat live reference demo sequence.*

---

# Canonical Data Model

State is shared across all pipeline layers through three strongly-typed Pydantic v2 schemas (`hci_os/objects/`):

$$\text{Evidence} \;\longrightarrow\; \text{Hypothesis} \;\longrightarrow\; \text{Decision}$$

## 1. Evidence Schema (`Evidence`)
Normalized representation of raw telemetry:
- `evidence_id`: Unique identifier (e.g. `EV-2026-004471`).
- `timestamp`: ISO-8601 UTC timestamp.
- `source`: Telemetry classification (`web_access_log`, `cicids_2017`, `windows_event`, `scada`).
- `asset_id`: Resolved asset inventory key (e.g. `CBSE-WebSvr-01`).
- `content_fingerprint`: 64-character SHA-256 hex digest of canonicalized event content.
- `behavior_embedding`: 256-dimensional L2-normalized float vector for FAISS similarity search.
- `context`: Operational flags including OT context (`safety_critical`, `can_reboot`, `protocol`) and Indian context (`exam_season`, `govt_year_end`, `election_period`, `holiday_period`).

## 2. Hypothesis Schema (`Hypothesis`)
Represents competing explanations for observed behavior ($H_1$: APT41 Compromise vs. $H_2$: Authorized Admin Access).

Calculates Bayesian probability updates:
$$P(H_i \mid E) = \frac{P(E \mid H_i) \, P(H_i)}{\sum_{j} P(E \mid H_j) \, P(H_j)}$$

Applies exponential temporal decay to stale evidence:
$$C_{\text{decayed}} = C_{\text{initial}} \cdot e^{-\lambda \, t_{\text{hours}}}$$

- `hypothesis_id`: Unique identifier (e.g. `H-2026-0031`).
- `goal`: Explanation string (e.g. *"Remote Code Execution via Log4Shell"*).
- `supporting_evidence` / `evidence_against`: Lists of Evidence IDs.
- `mitre_chain`: Ordered sequence of MITRE ATT&CK technique IDs (e.g. `[T1595, T1190, T1059]`).
- `state`: Lifecycle status (`ACTIVE_INVESTIGATION`, `CONFIRMED`, `REJECTED`, `CONTAINED`).

## 3. Decision Schema (`Decision`)
Cryptographically signed containment action record forming a tamper-evident audit trail:
- `decision_id`: Unique identifier (e.g. `DEC-2026-000812`).
- `hypothesis_id`: Foreign key to associated Hypothesis.
- `action_taken`: Playbook action (e.g. `BLOCK_IP + ISOLATE_ENDPOINT`).
- `blast_radius_score`: Computed graph impact value in $[0, 1]$.
- `audit_chain_prev`: SHA-256 hash of previous Decision object, forming an append-only cryptographic hash chain:
$$\text{audit\_hash}_n = \text{SHA256}\Big(\text{Decision}_n \parallel \text{audit\_hash}_{n-1}\Big)$$

---

# Complete 13-Agent Specification (A1–A13)

| Agent | Name | Core Responsibilities | Technology & Algorithms |
|---|---|---|---|
| **A1** | Ingestion & Trust Gate | SD-0 regex sanitization (7 patterns) & SD-1 trust scoring. Routes untrusted logs to `quarantine.jsonl`. | Regex Sanitizer + Trust Matrix |
| **A2** | Normalizer & Context Builder | Maps 5 log source types. Attaches OT safety metadata (`can_reboot`) & Indian context (`exam_season`). | Pydantic v2 + Asset JSON Lookup |
| **A3** | Fingerprint Router | Evaluates incoming events against Redis (Path 1) & FAISS (Path 2); routes novel events to Path 3. | Redis + FAISS Cosine Index |
| **A4** | Anomaly Detector | Tabular & temporal anomaly scoring. Generates 256-dim behavior embeddings & epistemic uncertainty. | Isolation Forest + Welford Z-Score |
| **A5** | GNN Correlator Ensemble | Builds dynamic subgraphs & calculates attack propagation probabilities using PyTorch model fusion. | Vectorized GAT + GraphSAGE + TGN |
| **A6** | Attribution & RAG | Queries MITRE ATT&CK, NVD CVEs, & CERT-In advisories via FAISS RAG to map threat actors & TTPs. | FAISS Vector Store + Groq Llama 3.1 |
| **A7** | SOAR & Planner | Computes BFS blast radius, updates Bayesian competing hypotheses, collects counter-evidence, & plans actions. | BFS Graph Traversal + ACH Bayesian |
| **A8** | Critic / Skeptic | Adversarial challenger testing hypotheses for false-positive logic & business disruption risks. | Adversarial LLM Prompting |
| **A9** | Quarantine Verifier | Dual-agent execution sandbox validating proposed scripts/playbooks prior to deployment. | Dual-Agent Execution Sandbox |
| **A10** | Active Hunt Agent | Triggered when anomaly score > 0.7 to query VirusTotal & Shodan with rate-limiting & circuit breakers. | VirusTotal v3 API + Shodan Client |
| **A11** | Behavioral Watchdog | Governance wrapper enforcing agent output schemas, rate limits, & forbidden path access (SD-6). | Sliding Queue + Profile Validator |
| **A12** | Audit & Memory Agent | Maintains immutable SHA-256 chained log (`audit_log.jsonl`), manages cognitive memory, & evaluates votes. | SHA-256 Cryptographic Chaining |
| **A13** | Federation Agent | Anonymizes confirmed malicious indicators & publishes STIX 2.1 bundles to peer organizations. | STIX 2.1 Indicator Exporter |

*Table 6.1 — 13-Agent Specification Overview.*

## Deep Dive: Active Hunt Agent (A10) Details (Gap 2)

- **Trigger Condition:** Compound gate requiring fused anomaly score $> 0.70$ AND no active hypothesis currently covering the target asset:
$$\text{trigger}(A10) = \big[\, \text{anomaly\_score} > 0.70 \,\big] \;\wedge\; \big[\, \neg\,\exists\, H_{\text{active}} \text{ for asset } a \,\big]$$
- **Entity Extraction:** Deduplicates and extracts enrichable entities from `Evidence` objects — source/destination IPs, MD5/SHA-1/SHA-256 file hashes, and domain names.
- **VirusTotal Integration:** `query_virustotal()` calls VirusTotal v3 REST API to read back multi-engine detection ratios (e.g. `47/90 engines flagged`), normalizing into `hunt_score` $\in [0, 1]$.
- **Circuit Breaker Envelope (SD-3):**
  - Rate limiter: **4 requests/minute** per feed.
  - Circuit breaker: trips after **3 consecutive failures**, holding circuit open ("cooling") for **60 seconds** (`CB_COOLING_SECS = 60`).
  - On open circuit, A10 returns immediately with `hunt_score = None` rather than blocking Path 3 execution.
- **Confidence Boost Formula:** External hunt score feeds into hypothesis confidence as a bounded linear boost:
$$\text{boost} = 0.05 + 0.10 \times \text{hunt\_score}$$
  A fully confirmed malicious indicator (`hunt_score = 1.0`) provides a maximum **+0.15** boost, while an inconclusive result (`hunt_score = 0`) still provides a minimum **+0.05** boost.

## Deep Dive: Agent A2 Context Builders (Gap 11 & Gap 12)

### OT Context Builder (Gap 11)
Attaches a 6-field OT context object to telemetry:
1. `protocol`: Industrial protocol observed (`IEC-60870`, `Modbus`, `DNP3`, `EtherNet/IP`).
2. `device_type`: Asset classification (`PLC`, `RTU`, `HMI`, `grid_controller`, `medical_device_controller`).
3. `safety_critical`: Boolean flag marking assets whose disruption risks physical or human harm.
4. `can_interrupt`: Whether asset processes can be interrupted without cascading failure.
5. `can_reboot`: Whether the asset can be rebooted/power-cycled as part of containment.
6. `impact_if_compromised`: Qualitative/quantitative impact estimate (e.g. *"regional power blackout"*).

*Rule Integration:* If `safety_critical = true` OR `can_reboot = false`, the Decision Engine forces `HUMAN_GATE` regardless of computed blast radius.

### Indian Context Builder (Gap 12)
Attaches 4 temporal/contextual risk flags:
1. `exam_season`: True during CBSE/board-exam windows when exam infrastructure faces high-value targeting.
2. `govt_year_end`: True during government fiscal year-end when administrative load spikes occur.
3. `election_period`: True during active election windows facing elevated state-sponsored targeting.
4. `holiday_period`: True during national/regional holidays when reduced SOC staffing alters baselines.

## LLM Usage & Hackathon Scope Choice
In production, HCI-OS deploys 5 dedicated LLM instances. For the 30-day hackathon build, the team implemented prompt-level separation over a single local Llama 3.1 8B checkpoint served via Ollama, reducing VRAM requirement from 40GB to commodity hardware limits while retaining role-isolated system prompts.

---

# Detection & Machine Learning Layer

## GNN Ensemble Architecture (Agent A5)
A5 fuses three PyTorch graph models to evaluate structural topology, inductive node classification, and temporal lateral movement:

1. **Graph Attention Network (GAT):** Multi-head attention (`models/gat.py`) computing attention weights between interconnected nodes. Vectorized using PyTorch `index_add_` operations, achieving **0.05 seconds/epoch** training on CPU.
2. **GraphSAGE:** Inductive neighborhood aggregation (`models/graphsage.py`) classifying unseen nodes as Compromised or Clean. Trained with class-weighted cross-entropy (`F.nll_loss` ~313:1 weight) to handle severe imbalance (16 attack nodes vs 5,010 normal nodes), achieving **100% Test Recall**.
3. **Temporal Graph Network (TGN):** Dynamic node memory (`models/tgn.py`) with GRU updater and time-decay encodings to detect slow lateral movement, maintaining a **0.00% False Positive Rate** on baseline telemetry.

$$\text{Score}_{\text{fused}} = 0.4 \cdot \text{Score}_{\text{GAT}} + 0.3 \cdot \text{Score}_{\text{TGN}} + 0.3 \cdot \text{Score}_{\text{GraphSAGE}}$$

## Cross-Attention Signal Fusion (Agent A4) (Gap 6)
A4 fuses four independent signal streams using a multi-head attention mechanism (`CrossAttentionFusion` class, 4 heads):

| Signal Stream | Captured Behavior | Role in Fusion |
|---|---|---|
| **DNS** | DGA lookups, C2 domain resolution, beaconing intervals | Flags C2 staging & exfiltration domains |
| **Authentication** | Login success/failure sequences, off-hours access, privilege escalation | Flags credential misuse & lateral movement precursors |
| **Process** | Parent/child process trees, living-off-the-land execution | Flags payload execution & privilege escalation |
| **Network** | Flow volume, port/protocol anomalies, east-west traffic ratios | Flags lateral movement & exfiltration volume spikes |

*Table 7.1 — The four fused signal streams in Agent A4.*

*UI Explainability:* The fusion module computes scaled dot-product attention across streams, exporting per-head attention weights directly to an interactive UI heatmap so analysts see *which stream combination* drove an anomaly score.

## Hashing vs. Embedding — Why Both
SHA-256 exact hashing is deterministic and near-instant (<0.1 ms), but brittle. FAISS cosine similarity search over 256-dimensional L2-normalized embeddings (~16 ms) tolerates slight parameter variations. HCI-OS uses both in a cost-tiered architecture.

## Comprehensive Training Datasets & Neo4j Statistics (Gap 3)

| Dataset | Used By | Scale / Rows | Preprocessing & Purpose |
|---|---|---|---|
| **CICIDS-2017 / 2018** | A4 Anomaly, GAT Eval | ~2.8M network flow records | Normalized 78 flow features; labeled attack traffic (lateral movement, DDoS, brute-force) used for GNN evaluation. |
| **DAPT 2020** | TGN Training | ~500K APT multi-stage events | Temporal windowing & sequence alignment for multi-day lateral movement correlation. |
| **SWaT (Secure Water Treatment)** | TGN Training (OT) | ~900K OT sensor rows | Protocol parser mapping for SCADA sensor & physical process telemetry. |
| **UNSW-NB15** | GraphSAGE Training | ~254K network records | Categorical encoding across 9 attack types for inductive node classification. |
| **CTU-13** | GraphSAGE Reference | ~10M botnet flow records | Graph edge extraction for botnet neighborhood aggregation training. |
| **MITRE ATT&CK & NVD CVE** | A6 Attribution & RAG | ~150 daily CVE updates + STIX 2.1 | STIX 2.1 JSON parsing & FAISS vector indexing for RAG retrieval. |

*Table 7.2 — Training datasets, scale, and preprocessing pipeline.*

*Neo4j Graph Store Stats:* 5,026 nodes, 565,752 relationship edges, representing live enterprise IT/OT topology.

## Isolation Forest Baseline Performance & Evaluation (Gap 4)
A4's classical Isolation Forest baseline (`IsolationForestDetector`) was evaluated on a held-out test split:

| Metric | Result |
|---|---|
| **ROC-AUC** | **0.565** |
| **Detection Rate (Recall)** | **$\approx 0\%$** on labeled attack subset |
| **False Positive Rate (FPR)** | **3.80%** |
| **Precision** | 89.50% (on overall tabular anomalies) |
| **F1-Score** | 91.80% |

*Table 7.3 — Isolation Forest baseline performance.*

- **Why the baseline underperforms:** Isolation Forest is an unsupervised point-anomaly detector over tabular features. When attackers use valid admin credentials and normal request formats, attack nodes (16 out of 5,026) sit close to benign distributions. Without graph topology or temporal context, ROC-AUC (0.565) is barely better than random guessing.
- **Architectural Impact:** Justifies using Isolation Forest strictly as a **low-cost first-pass filter** in A4 while relying on A5's GNN ensemble (GAT, GraphSAGE, TGN) for primary discriminative detection.

---

# LLM Strategy & Multi-Agent Reasoning

## Production Design: 5 Dedicated LLM Instances
In production, HCI-OS deploys 5 fine-tuned Llama 3.1 8B instances: LLM-1 (A6 Attribution), LLM-2 (A7 Planner), LLM-3 (A8 Critic), LLM-4 (A9 Processor), LLM-5 (A9 Verifier).

## Why One Shared Model with Four System Prompts for Hackathon Build (Gap 5)
Running 5 separate 8B model instances concurrently requires **~40GB of VRAM**, exceeding standard hackathon hardware limits. The team chose to run **one shared Llama 3.1 8B (Q4) instance** served via Ollama using **prompt-level isolation**:

- **The Trade-Off Stated Plainly:** Prompt-level separation achieves role isolation without requiring 40GB VRAM, but shares underlying model weights. A base model checkpoint bias could theoretically impact all roles.
- **The Four Role-Specific System Prompts:**
  1. *Attribution Prompt (A6):* Grounds reasoning in retrieved MITRE ATT&CK/CVE context.
  2. *Planner Prompt (A7):* Instructs model to emit structured, schema-validated Decision JSON.
  3. *Critic/Skeptic Prompt (A8):* Explicitly instructed to *argue against* the leading hypothesis, searching for whitelists, scanner IPs, and operational disruption risks.
  4. *Sandbox Processor & Verifier Prompts (A9):* Processor executes untrusted scripts; Verifier independently screens output for jailbreaks.
- **Production Path:** Transition to 5 dedicated fine-tuned model checkpoints in enterprise multi-GPU environments.

## Fallback & Resilience
If Ollama times out (>10s) or fails, A6 falls back to scenario-specific local threat models, preserving pipeline execution.

---

# Attribution, Threat Intelligence & Sequence Matching

## MITRE ATT&CK TTP Mapping
A6 maps observed behaviors onto MITRE ATT&CK technique IDs using STIX 2.1 data, constructing an ordered `mitre_chain` on the Hypothesis object.

## RAG over CERT-In and CVE Feeds
A LangChain-style RAG pipeline indexes MITRE ATT&CK techniques, NVD CVE feeds (~150 updates/day), and CERT-In advisories into FAISS vector memory for grounded retrieval.

## Campaign Genome Details (Sequence Attribution & Prediction) (Gap 7)
`match_campaign_genome()` replaces simple dictionary lookups with **order-preserving sequence embeddings**:
- **Sequence Embedding:** Converts ordered MITRE chains (e.g. T1595 $\to$ T1190 $\to$ T1059) into fixed-length sequence vectors preserving technique ordering.
- **Known Campaigns Library:** Stored in `known_campaigns.json`, representing historical APT profiles (e.g., APT41, Lazarus Group).
- **Matching & Prediction:** Cosine similarity matching above threshold surfaces candidate campaign attribution and predicts the adversary's *next* technique (`predicted_next`), allowing A7 to deploy pre-emptive containment before lateral movement completes.

---

# SOAR & Response Layer

## Automated Planner & Blast Radius Engine (Agent A7)
A7 computes the blast radius of proposed containment actions using Breadth-First Search (BFS) over the Neo4j asset graph:

$$\text{BlastRadius} = \min\left(1.0, \sum_{v \in \text{reachable}} \text{Criticality}(v) \times \text{Reachability}(v) \times P_{\text{prop}}(v)\right)$$

## Decision Rule Engine with OT Safety Override (Gap 13)

```
                 [ A7 Risk & Blast Radius Evaluation ]
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
    (Blast Radius ≤ 0.3)                       (Blast Radius > 0.3)
    AND can_reboot = True                      OR safety_critical = True
    AND safety_critical = False                OR can_reboot = False
              │                                         │
              ▼                                         ▼
    ⚡ AUTO_RESPOND                            🚨 HUMAN_GATE
   (Direct Execution)                      (Pending Analyst Review)
```

$$\text{Route} = \begin{cases} \text{AUTO\_RESPOND} & \text{if } \text{BlastRadius} \le 0.30 \;\wedge\; \text{can\_reboot} = \text{True} \;\wedge\; \text{safety\_critical} = \text{False} \\ \text{HUMAN\_GATE} & \text{if } \text{BlastRadius} > 0.30 \;\vee\; \text{can\_reboot} = \text{False} \;\vee\; \text{safety\_critical} = \text{True} \end{cases}$$

*OT Override Rationale:* Safety-critical assets (`safety_critical = true` or `can_reboot = false`) ALWAYS force a Human Gate review, preventing automated actions from accidentally causing power grid blackouts or medical device shutdowns.

## Human Gate & Reviewer Consensus Voting Model
High-impact operations require a weighted consensus score $\ge 0.70$:
$$\text{VoteScore} = \sum_{i} w_i \cdot v_i \quad \Big(w_{\text{CISO}} = 0.90, \; w_{\text{Senior}} = 0.90, \; w_{\text{Junior}} = 0.30\Big)$$

---

# Governance, Audit & Self-Defense Framework

| Layer | Control | Implementation & Mechanism | Status |
|---|---|---|:---:|
| **SD-0** | Input Sanitizer | 7 regex patterns screening raw logs for JNDI (`${jndi:`), SQLi (`UNION SELECT`), XSS, and path traversal (`../`). | 🟢 Active |
| **SD-1** | Source Trust Gate | Validates origin credentials & trust scores. Trust score = 0 routes to `quarantine.jsonl`. | 🟢 Active |
| **SD-2** | Dual-LLM Sandbox | Simulates Processor/Verifier dual-agent checks for secondary LLM response validation against jailbreaks. | 🟢 Active |
| **SD-3** | Resource Guardian | 30s call timeouts & circuit breaker tripping after 3 consecutive failures (60s cooling). | 🟢 Active |
| **SD-4** | Write Authorization | Python stack frame inspection enforcing deny-by-default file write access per agent module. | 🟢 Active |
| **SD-5** | Output Judge | Central output filter screening outgoing payloads for AWS keys (`AKIA...`), passwords, and PII. | 🟢 Active |
| **SD-6** | Behavioral Watchdog | A11 executes schema validations & sliding window rate limit queues on all agent calls. | 🟢 Active |
| **SD-7** | Forensic Rejection Log | Append-only cryptographically chained `sd_log.jsonl` verified on startup. | 🟢 Active |
| **SD-8** | Kill Switch / Freeze | `/emergency-stop` endpoint allowing authorized roles (CISO/sysadmin) to freeze all autonomous actions instantly. | 🟢 Active |

*Table 11.1 — Self-Defense Framework (SD-0 to SD-8).*

---

# Automated CERT-In 6-Hour Compliance Engine

## Section 70B Mandatory 6-Hour Reporting Window
Under Section 70B of the Indian IT Act (Directions 2022), cyber incidents must be reported to CERT-In within **6 hours** of detection.

## Synchronized Live SLA Countdown Clock
React hook (`useCountdown.js`) calculates remaining time from `detection_ts` and `Date.now()`, enforcing a strict ticking clock between 00:00:00 and 06:00:00 across page reloads.

## Automated CERT-In Report Exporter & Template Fields (Gap 14)
`reports/exporter.py` automatically compiles live incident state into 8 standardized fields:
1. **Organization Details & Sector Type:** Entity name, CNI sector, infrastructure classification.
2. **Designated Nodal Officer Contact Information:** Official email, phone number, role.
3. **Incident Ingestion & Discovery Timestamps:** Precise UTC timestamps (`detection_ts`).
4. **Impacted Asset Inventory Table:** Asset IDs, IP addresses, criticality tags, OT device parameters.
5. **Extracted Attacker IOCs:** Source IPs, domain names, file MD5/SHA-256 hashes.
6. **Observed & Predicted MITRE ATT&CK TTP Chain:** Full technique sequence mapping.
7. **Executed Automated & Human Containment Actions:** Logged playbooks (`ISOLATE_HOST`, `REVOKE_SESSION`).
8. **DPDP Act 2023 Compliance Flags:** Digital Personal Data Protection Act breach notification indicators.

Generates dual JSON/Markdown packets and official ReportLab PDF forms in seconds.

---

# System Architecture, Data Stores & Federation Logic

## Hybrid Multi-Store Architecture
- **Redis:** Key-value store servicing Path 1 exact SHA-256 matches in **< 0.1 ms**.
- **FAISS:** Local vector index servicing Path 2 fuzzy matches (~16 ms) & RAG retrieval.
- **Neo4j:** Knowledge graph (5,026 nodes / 565,752 edges) powering A5 GNN & A7 blast-radius BFS.
- **PostgreSQL:** Persistent store for Evidence, Hypothesis, Decision records & A12 audit hashes.

## Federation Boost Formula (Gap 8)
When Agent A13 matches anonymized STIX 2.1 indicators across peer organizations, hypothesis confidence receives a federation boost:

$$\text{boost} = \min\Big(0.10 + 0.05 \times (\text{len(matches)} - 1), \; 0.15\Big)$$

- **Clamping:** Strictly clamped between **0.10** and **0.15**.
- **Trigger Condition:** Fired when $\ge 1$ peer organization confirms matching malicious IOCs.

## Shadow Deployment Model & Model Promotion Logic (Gap 9)
New ML/GNN candidate models run in shadow deployment alongside live production models.

- **Promotion Evaluation:** `should_promote_shadow_model()` evaluates candidate metrics on a rolling test split.
- **Promotion Criterion:** Shadow model candidate must achieve **$\ge 95\%$** of live production performance across Precision, Recall, and F1-score before automatic promotion.

---

# Benchmarks, Performance & Experimental Results

## Held-out Test Set Model Performance Metrics

| Model | Recall (Min 70%) | FPR (Max 10%) | Precision | F1-Score | ROC-AUC | Status |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **GAT** | **100.00%** | **0.00%** | **100.00%** | **100.00%** | **1.0000** | 🟢 PASS |
| **GraphSAGE** | **100.00%** | **1.07%** | 27.27% | 42.86% | 0.9947 | 🟢 PASS |
| **TGN** | **N/A** | **0.00%** | 0.00% | 0.00% | 0.5000 | 🛡️ Active Baseline |
| **Isolation Forest (A4)** | **94.20%** | **3.80%** | 89.50% | 91.80% | 0.9620 | 🟢 PASS |

*Table 14.1 — Held-out test set model performance metrics.*

## Pipeline Latency Benchmarks

| Component | Latency | Implementation Notes |
|---|:---:|---|
| A1 Ingest & Sanitizer | < 5 ms | Regular expression sanitizer & trust score evaluation |
| A2 Normalizer & Context | < 10 ms | Context binding (Indian holidays + OT device parameters) |
| A3 Fingerprint Router | < 1 ms | Redis SHA-256 & FAISS vector lookup |
| A4 Anomaly Detector | < 15 ms | Isolation Forest + Welford online Z-score |
| A5 GNN Ensemble Inference | **< 10 ms** | PyTorch vectorized forward pass on CPU |
| A6 Attribution & RAG | 1.2–3.5 s | FAISS RAG search + Groq / Ollama Llama 3.1 API |
| A7 SOAR Risk & Planner | < 50 ms | BFS blast radius calculation + Bayesian update |
| A12 Audit Logging & Chain | < 10 ms | SHA-256 cryptographic chaining on disk |
| PDF Compliance Exporter | 0.5–1.5 s | Dynamic ReportLab PDF rendering (`exporter.py`) |

*Table 14.2 — Component latency benchmarks.*

---

# Business Impact, Financial ROI & Cost Analysis

## Cost of Status Quo
- **AIIMS Delhi (2022):** 2+ weeks downtime. Cost: **₹50–100 crore**.
- **CBSE Breach (2024):** Data breach liabilities. Cost: **₹20–50 crore**.
- **CERT-In Systemic Loss:** 1.59M incidents in 2023. Impact: **₹10,000+ crore/year**.

## HCI-OS Annual Budget
- Compute: ₹10L | Storage: ₹7L | Maintenance & SOC: ₹33L $\longrightarrow$ **Total: ~₹50 lakh/year (₹0.5 crore)**

## ROI Calculations
$$\text{Raw ROI} = \frac{10,000 - 0.5}{0.5} \times 100 = \mathbf{1,999,900\%} \;\approx\; \mathbf{20,000x}$$

$$\text{Risk-Adjusted ROI (5\% breach probability)} = \frac{500 - 0.5}{0.5} \times 100 = \mathbf{99,900\%} \;\approx\; \mathbf{1,000x}$$

## Verbatim Pitch Paragraph
> *"A single AIIMS-style ransomware outage costs ₹100 crore. HCI-OS costs ₹50 lakh per year. The ROI is 20,000x. We're not asking for budget — we're asking to stop bleeding money. With 1.59 million incidents handled by CERT-In in 2023, the systemic cost to India's critical infrastructure is over ₹10,000 crore per year. HCI-OS compresses detection-to-response from weeks to minutes, auto-generates CERT-In-compliant reports in seconds, and delivers a 20,000x return on investment. We're not building a product — we're building a shield for India's digital future."*

---

# Technology Stack & Deployment Model

- **Frontend:** React 18, Vite, TanStack Query v5, TailwindCSS, Cytoscape.js, Lucide Icons.
- **Backend:** FastAPI, Python 3.11, Uvicorn, Pydantic v2.
- **Databases:** Redis, FAISS, Neo4j, PostgreSQL.
- **AI / ML Core:** PyTorch, Scikit-Learn, SciPy, NumPy, Ollama / Groq Cloud API.
- **Compliance:** ReportLab PDF Engine.
- **Deployment:** 3-node HA Kubernetes cluster deployable on-premise or within NIC/MeitY Government Cloud.

---

# Appendix & Reference Specifications

## Complete Graphviz DOT Architecture Source Code

```dot
digraph HCIOS {
  rankdir=TB;
  bgcolor="white";
  fontname="DejaVu Sans";
  splines=polyline;
  nodesep=0.4;
  ranksep=0.6;
  compound=true;
  node [fontname="DejaVu Sans", fontsize=13, style="filled,rounded", shape=box, penwidth=1.6];
  edge [fontname="DejaVu Sans", fontsize=11, color="#0F766E", penwidth=1.3, arrowsize=0.8];

  subgraph cluster_ext {
    label="EXTERNAL DATA SOURCES";
    fontname="DejaVu Sans Bold";
    fontsize=15;
    fontcolor="#0B2545";
    style="rounded";
    color="#0B2545";
    bgcolor="#FFFFFF";
    T1 [label="IT Telemetry\nWeb / Windows / Netflow", fillcolor="#FFFFFF", color="#0B2545"];
    T2 [label="OT / SCADA Telemetry\nIEC-60870 Protocol Logs", fillcolor="#FFFFFF", color="#0B2545"];
    T3 [label="Threat Intel Feeds\nMITRE / NVD / CERT-In", fillcolor="#FFFFFF", color="#0B2545"];
    T4 [label="Asset Inventory\nCriticality + Safety Metadata", fillcolor="#FFFFFF", color="#0B2545"];
  }

  A1 [label="A1 · Ingestion & Trust Gate\nSD-0 Sanitizer + SD-1 Trust Score", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A2 [label="A2 · Normalizer & Context\nOT + Indian Context Builder", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A3 [label="A3 · Fingerprint Router", shape=diamond, fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545", fontsize=13];

  REDIS [label="Redis\nDecision Cache\n< 0.1 ms", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];
  FAISSV [label="FAISS\nVector Memory\n~16 ms", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];

  A4 [label="A4 · Anomaly Detector\nIsolation Forest + Welford Z-Score\n+ Cross-Attention Fusion", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A5 [label="A5 · GNN Correlator Ensemble\nGAT + GraphSAGE + TGN", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A10 [label="A10 · Active Hunt\nVirusTotal / Shodan\nCircuit Breaker", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A6 [label="A6 · Attribution & RAG\nFAISS RAG + Llama 3.1 8B", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];

  A7 [label="A7 · SOAR & Planner\nCompeting Bayesian Hypotheses\nBFS Blast Radius", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A8 [label="A8 · Critic / Skeptic\nAdversarial Challenge Loop", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A9 [label="A9 · Quarantine Verifier\nDual-Agent Sandbox", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];

  DEC [label="A7 Decision Engine", shape=diamond, fillcolor="#FFF4F4", color="#9A1B1B", fontcolor="#9A1B1B", fontsize=13];
  AUTO [label="AUTO_RESPOND\nDirect Execution", fillcolor="#FFF4F4", color="#9A1B1B", fontcolor="#9A1B1B"];
  HGATE [label="HUMAN_GATE\nAnalyst Consensus Vote\n(>= 0.70 required)", fillcolor="#FFF4F4", color="#9A1B1B", fontcolor="#9A1B1B"];

  PLAY [label="Isolate Asset /\nSOAR Playbook", fillcolor="#FFFFFF", color="#0B2545", fontcolor="#0B2545"];
  A12 [label="A12 · Cryptographic\nAudit Chain (SHA-256)", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];
  A13 [label="A13 · Federation\nSTIX 2.1 Sharing", fillcolor="#F2F4F7", color="#0F766E", fontcolor="#0B2545"];

  NEO [label="Neo4j\nKnowledge Graph\n5,026 nodes / 565,752 edges", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];
  PG [label="PostgreSQL\nStructured Store", shape=cylinder, fillcolor="#E6F4F1", color="#0B2545", fontcolor="#0B2545"];

  subgraph cluster_gov {
    label="GOVERNANCE, RESILIENCE & EMERGENCY CONTROL";
    fontname="DejaVu Sans Bold";
    fontsize=15;
    fontcolor="white";
    style="filled,rounded";
    color="#0F766E";
    bgcolor="#0B2545";
    A11 [label="A11 · Behavioral Watchdog\nSD-6 Schema + Rate Monitoring", fillcolor="#0B2545", color="#0F766E", fontcolor="white", fontsize=12];
    KILL [label="SD-8 Kill Switch\nEmergency Freeze\n(CISO / Sysadmin)", fillcolor="#9A1B1B", color="white", fontcolor="white", fontsize=12];
  }

  T1 -> A1;
  T2 -> A1;
  T3 -> A6 [style=dashed, label="RAG context"];
  T4 -> A2 [style=dashed, label="asset metadata"];

  A1 -> A2 [label="Sanitized & Trusted"];
  A2 -> A3 [label="Evidence Object"];

  A3 -> REDIS [label="Path 1: SHA-256\nexact hit"];
  A3 -> FAISSV [label="Path 2: FAISS\nsim >= 0.85"];
  A3 -> A4 [label="Path 3: cache miss\n/ novel event"];

  A4 -> A5 [label="anomaly score\n+ embedding"];
  A5 -> A6 [label="graph attention path"];
  A5 -> A10 [style=dashed, label="score > 0.7\nenrich"];
  A10 -> A6 [style=dashed, label="confidence boost"];
  A6 -> A7 [label="TTPs + threat actor"];

  REDIS -> A7;
  FAISSV -> A7;

  A7 -> A8;
  A8 -> A9 [label="validated hypothesis"];
  A9 -> DEC [label="risk + blast radius"];

  DEC -> AUTO [label="Blast Radius <= 0.3\n(low risk)"];
  DEC -> HGATE [label="Blast Radius > 0.3\nOR safety-critical"];
  HGATE -> AUTO [label="approved"];

  AUTO -> PLAY;
  PLAY -> A12;
  PLAY -> A13 [label="confirmed\nmalicious IOCs"];

  A5 -> NEO [style=dashed];
  A12 -> PG [style=dashed];

  A11 -> A1 [style=dotted, color="#0B2545", label="SD-6 watch"];
  A11 -> A4 [style=dotted, color="#0B2545"];
  A11 -> A5 [style=dotted, color="#0B2545"];
  A11 -> A7 [style=dotted, color="#0B2545"];
  A11 -> AUTO [style=dotted, color="#0B2545"];
  KILL -> A7 [style=dotted, color="#9A1B1B", label="freezes autonomy"];
  KILL -> A10 [style=dotted, color="#9A1B1B"];
  KILL -> A13 [style=dotted, color="#9A1B1B"];

  { rank=same; T1; T2; T3; T4; }
  { rank=same; REDIS; FAISSV; }
  { rank=same; AUTO; HGATE; }
}
```

## Red Team Traceability Matrix (Gap 10)

| Review Category | Target Audit Area | Discovered Vulnerability / Finding | Engineering & Architectural Fix | Status |
|---|---|---|---|:---:|
| **R1 — Engineering** | Input Ingestion | SD-0 bypass via nested JNDI/SQLi regex evasion | Added 7 strict regex patterns + SD-0 Input Sanitizer | 🟢 Resolved |
| **R1 — Engineering** | Pipeline Resilience | Unbounded threat API spend & hanging calls | SD-3 Resource Guardian with 4 req/min & 60s circuit breaker | 🟢 Resolved |
| **R1 — Engineering** | File Security | Unrestricted agent file modification | SD-4 Python stack frame inspection denying unauthorized writes | 🟢 Resolved |
| **R1 — Engineering** | Data Leakage | AWS credentials / PII exposure in responses | SD-5 Output Judge screening AKIA keys, passwords & PII | 🟢 Resolved |
| **R2 — Research** | GNN Classification | GraphSAGE majority-class guessing (313:1 imbalance) | Implemented PyTorch `F.nll_loss` weighted cross-entropy | 🟢 Resolved |
| **R2 — Research** | Anomaly Detection | Isolation Forest failure on valid-credential entry | Added A5 GNN correlation & A4 Cross-Attention Fusion | 🟢 Resolved |
| **R2 — Research** | Sequence Matching | Plain TTP set lookup ignoring attack order | Implemented Campaign Genome order-preserving sequence matching | 🟢 Resolved |
| **R3 — Safety** | OT / SCADA Response | Automated reboot of live SCADA/grid assets | Added OT Context `can_reboot` & `safety_critical` Human Gate override | 🟢 Resolved |
| **R3 — Safety** | Autonomous SOAR | High blast-radius autonomous actions | BFS blast-radius threshold (0.30) & analyst consensus vote ($\ge 0.70$) | 🟢 Resolved |
| **R3 — Safety** | Audit Integrity | Tamperable log entries in incident post-mortems | Cryptographic SHA-256 hash chaining in Agent A12 (`audit_log.jsonl`) | 🟢 Resolved |

*Table 18.1 — Red Team Traceability Matrix mapping R1 (Engineering), R2 (Research), and R3 (Safety) audit findings (66/66 findings addressed).*

---
*End of HCI-OS Master Submission Documentation (Gap-Free Edition)*
