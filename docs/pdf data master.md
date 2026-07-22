---
title: "HCI-OS — Technical Documentation"
subtitle: "Hypothesis-Driven Cyber Investigation Operating System v3.3"
author: "Team PraxisCode X — Indore Institute of Science and Technology"
date: "ET AI Hackathon 2.0 · Problem Statement #7 · 22 July 2026"
toc: true
toc-depth: 2
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
{\small\color{gray} Version 3.3 --- Final Submission Build}
\end{titlepage}
```

\newpage

# Executive Summary

HCI-OS (Hypothesis-Driven Cyber Investigation Operating System) is a cyber resilience platform built for the ET AI Hackathon 2.0, Problem Statement #7: AI-Powered Cyber Resilience for Critical National Infrastructure (CNI). It targets sectors such as hospitals (AIIMS), examination boards (CBSE), power grids, and railways — institutions that run legacy IT/OT systems and are increasingly the target of state-sponsored and criminal cyber campaigns.

Conventional Security Information and Event Management (SIEM) systems generate large volumes of isolated alerts and leave correlation, attribution, and root-cause reasoning to human analysts. This produces dwell times measured in days or weeks, during which attackers move laterally and exfiltrate data. HCI-OS's core thesis is that security operations should be reframed as an investigation process: instead of matching individual events to static rules, the system continuously forms competing hypotheses about what is happening in the environment, gathers evidence for and against each hypothesis using a Bayesian update rule, challenges its own leading hypothesis with an adversarial Critic agent, and only then recommends or executes a containment action.

> **Headline Outcome.** The system is designed and benchmarked around compressing the investigation loop from an industry baseline of days-to-weeks down to a target Mean Time to Contain (MTTC) of under 43 seconds for a full, previously-unseen investigation, and under 2 milliseconds for previously-seen threats via cache-accelerated paths.

> **One-Line Difference from Conventional SIEM.** "A SIEM processes alerts; HCI-OS investigates hypotheses — it hunts for corroborating evidence, generates competing explanations, challenges itself with a Skeptic agent, predicts the attacker's next move, and keeps an immutable, cryptographically chained record of every decision it makes."

**What this document covers:** the national-infrastructure problem context and why detection speed — not detection accuracy alone — is the primary bottleneck; the 12-layer, 13-agent architecture and the three-path processing design (Fast / Accelerated / Full); the canonical Evidence → Hypothesis → Decision data model shared by all agents; the GNN ensemble, LLM strategy, SOAR/response layer, and the nine-part self-defense stack; verified build progress, test results, and honest limitations as recorded in the team's engineering log; business impact, technology stack, deployment model, and roadmap.

# Problem Statement

## National Context

Critical National Infrastructure (CNI) — hospitals, examination boards, power grids, and railways — is a high-value target because outages have direct human and economic consequences, and because many of these entities run end-of-life IT/OT systems with limited security budgets. CERT-In (the Indian Computer Emergency Response Team) recorded 1.59 million cybersecurity incidents in 2023, and more than 70% of surveyed government entities were found to be running end-of-life infrastructure. CERT-In's regulatory mandate requires breach reporting within **6 hours** of detection — a window that is difficult for most affected organizations to meet given current manual triage processes.

## Case Studies Motivating HCI-OS

| Incident | Sector | Impact |
|---|---|---|
| AIIMS Delhi (2022) | Healthcare | Ransomware attack; over two weeks of system downtime; patient records affected. |
| CBSE (2024) | Education / Examinations | Student examination records breached. |
| CBSE (early 2026) | Education / Examinations | Coordinated attack triggering a multi-state emergency shutdown of examination infrastructure. |
| Kudankulam Nuclear Power Plant | Energy / OT | Referenced in the project's threat model as an example of the OT/SCADA risk class the system is designed to address. |
| Power Grid (regional) | Energy | Referenced as a representative OT target where uncontrolled automated remediation (e.g. rebooting a live SCADA asset) could itself cause an outage. |

*Table 2.1 — Representative incidents referenced in the HCI-OS problem framing. Kudankulam and regional power-grid entries are used as illustrative OT risk scenarios in the project's design documents rather than as detailed case studies.*

The team's live demonstration is built around a specific reference narrative for the CBSE Web Server scenario, used to make the abstract dwell-time problem concrete for judges: *"In 2026, attackers compromised this exact asset. By using valid admin credentials and pivoting laterally, they exfiltrated student examination records without triggering traditional signature alerts. The SOC discovered the breach three days later."* This narrative — valid-credential entry, lateral pivot, signature-blind exfiltration, multi-day discovery lag — is the specific failure mode HCI-OS's behavioural/graph-based detection paths (Path 2 and Path 3, §6.3) are designed to catch where a pure signature-matching SIEM would not.

## Why Detection Speed Is the True Bottleneck

Most breaches are not undetectable — they are detected too late, after lateral movement has already occurred. The project's design documents identify three structural reasons for this delay in conventional SOC operations:

- **Alert fatigue:** signature/rule-based SIEMs generate a high volume of low-context alerts, and analysts triage manually rather than investigate systematically.
- **No persistent hypothesis:** each alert is evaluated close to independently, so slow, low-and-slow campaigns that span many small events rarely get flagged by any single rule.
- **No safe automation path:** without a principled way to bound the blast radius of an automated response, most organizations default to fully manual containment, which is slow by construction.

HCI-OS addresses each of these directly: cache-accelerated paths reduce alert fatigue on repeat/near-repeat threats, the Hypothesis object persists and accumulates evidence across events, and the SOAR layer's blast-radius and confidence thresholds provide a principled boundary for when automation is safe versus when a human must be in the loop.

# Literature / Existing Approaches Review

## Limitations of Conventional SIEM

- Signature/rule matching only recognizes previously catalogued attack patterns; novel or slightly-modified attacks (e.g. a changed port number) evade exact-match rules entirely.
- Alerts are treated as independent events rather than as evidence accumulating toward a hypothesis, so multi-stage campaigns are hard to see as a single narrative.
- Most SIEM deployments provide weak or no automated attribution (mapping observed behaviour to a known threat actor or MITRE ATT&CK technique), leaving this reasoning step to a human analyst under time pressure.
- Response is largely manual, which is safe but slow — the industry-cited dwell times of days-to-weeks are a direct consequence of this.

## Signature-Based Detection Failures

Exact-match / signature detection (e.g. hash blocklists) is fast and precise for known-bad indicators, but any adversary who changes even one byte of a payload, or one parameter of a request, bypasses it. HCI-OS treats exact-match as the fastest of three tiers rather than the only tier, adding a semantic/behavioural similarity layer and a full graph-based investigation layer behind it.

## Graph Neural Network-Based Intrusion Detection

Representing network and system entities (hosts, users, processes, IPs) as a graph, and using Graph Neural Networks (GNNs) to reason over that graph, allows a detector to use topological and temporal context rather than only per-event features. HCI-OS's Agent A5 draws on three complementary GNN architectures for this purpose:

- **Graph Attention Networks (GAT)** — learn which neighbouring relationships matter most for a given node, producing attention weights that can be surfaced to a human analyst for explainability.
- **GraphSAGE** — an inductive method that can generalize to nodes not seen during training, useful for classifying newly-appeared assets as the network topology changes.
- **Temporal Graph Networks (TGN)** — incorporate event timestamps so that fast, sequential lateral movement or brute-force patterns are distinguishable from coincidental, unrelated activity.

> *Note: A formal literature survey with academic citations (e.g. specific GAT/GraphSAGE/TGN papers, published SIEM-limitation studies) is not reproduced verbatim here; the summary above is derived from the project's own architecture rationale rather than an independent literature review, and citation-level references should be added before external publication.*

# Solution Architecture

## Core Philosophy — Hypothesis-Driven Investigation

Rather than asking "does this event match a known-bad rule?", HCI-OS asks "what is the most probable explanation for the evidence I have observed, and how confident am I?". Every non-trivial event enters an investigation loop:

$$\text{Perceive} \rightarrow \text{Hypothesize} \rightarrow \text{Active Hunt} \rightarrow \text{Challenge (Critic)} \rightarrow \text{Bayesian Update} \rightarrow \text{Predict} \rightarrow \text{Execute} \rightarrow \text{Reflect} \rightarrow \text{Learn}$$

which then repeats as new evidence arrives.

## Novelty Statement — Context-Aware Decision Fingerprinting

The project's stated novel contribution is **Context-Aware Decision Fingerprinting**: every observation is converted into a layered fingerprint — an exact content hash, a behavioural/semantic embedding, and (when a full investigation is required) a decision outcome — and matched against a store of human-verified prior decisions before any expensive model inference is run. This lets previously-adjudicated threats and previously-adjudicated benign behaviour be resolved almost instantly, while reserving the costly GNN/LLM investigation loop for genuinely novel behaviour.

## Three-Path Design

| Path | Trigger | Target Latency | Compute Saved | Action |
|---|---|---|---|---|
| **Path 1 — Fast (Exact)** | SHA-256 exact match in Redis threat cache | < 0.1–2 ms | ~80% | Immediate reuse of the stored verdict; bypasses all ML/LLM inference. |
| **Path 2 — Accelerated (Fuzzy)** | Cosine similarity $\ge 0.85$ against FAISS behavioural embeddings | ~16 ms | ~60% | Reuses the closest historical Critic-validated verdict, with a criticality mismatch guard that falls back to Path 3 if the asset context differs. |
| **Path 3 — Full (Hypothesis Loop)** | Novel / unseen behaviour with no cache or fuzzy match | < 1 minute | 0% (full pipeline) | Full GNN correlation, RAG-based attribution, Bayesian hypothesis competition, Critic validation, and (where required) Human Gate review. |

*Table 6.1 — Three processing paths (Agent A3, Fingerprint / Hash Router).*

## High-Level Architecture Diagram

The end-to-end HCI-OS pipeline spans four functional zones: (1) universal telemetry ingestion, (2) the three-path fingerprint router, (3) the full hypothesis-driven investigation loop (A4–A9), and (4) the governance, audit, and federation layer (A11–A13), wrapped by the SD-0..SD-8 self-defense stack and the SD-8 Kill Switch.

![Figure 6.1 — End-to-end HCI-OS pipeline: 13-agent architecture, three processing paths (Fast / Accelerated / Full), data stores, Human Gate, and Kill Switch.](architecture_diagram.png){width=98%}

**Reading the diagram:** Raw telemetry (IT logs, OT/SCADA protocols, threat intel feeds, and the asset inventory) enters through **A1 (Ingestion & Trust Gate)** and **A2 (Normalizer & Context)**, which produces a canonical `Evidence` object. **A3 (Fingerprint Router)** then attempts, in order, an exact SHA-256 match against **Redis** (Path 1), a fuzzy cosine-similarity match against the **FAISS** vector store (Path 2), and — only on a miss — forwards the event into the full investigation loop (Path 3): **A4 (Anomaly Detector)** → **A5 (GNN Correlator Ensemble)** → **A6 (Attribution & RAG)**, enriched on demand by **A10 (Active Hunt)**. All three paths converge at **A7 (SOAR & Competing Hypotheses)**, which is challenged by **A8 (Critic/Skeptic)** and verified by **A9 (Quarantine Sandbox)** before a bounded **risk / blast-radius decision** routes the event to either **AUTO_RESPOND** or **HUMAN_GATE** (analyst consensus vote). Every executed decision is written to **A12's** SHA-256 audit chain and, for confirmed malicious IOCs, anonymized and shared via **A13 (Federation)**. **A11 (Behavioral Watchdog)** and the **SD-8 Kill Switch** wrap the entire pipeline as a governance and emergency-freeze layer.

### ASCII Overview of the Three-Path Router

```
                     [ Ingested Log ]
                            |
        +-------------------+-------------------+
        v                   v                   v
   [ Fast Path ]      [ Accelerated ]      [ Full Loop ]
     SHA-256              FAISS             GNN + LLM
     < 2 ms               ~16 ms              < 1 min
```

## Design Principles

- **Fail-safe by construction:** the SD-8 kill switch has no auto-release on timeout — once autonomy is frozen, it stays frozen until an explicit, logged human release.
- **Safety before speed for OT/SCADA:** if an asset's context marks `can_reboot = false`, the SOAR layer forces a Human Gate regardless of hypothesis confidence.
- **Cache before compute:** the fingerprint router always attempts Path 1 and Path 2 before invoking the GNN/LLM stack, saving an estimated 60–80% of compute on repeat and near-repeat threats.
- **Every decision is falsifiable:** the Critic (A8) agent is structurally required to look for counter-evidence — whitelist membership, known-scanner IPs, active red-team windows — before a hypothesis can drive an autonomous action.
- **Everything is audited:** every decision, correction, and self-defense rejection is written to a SHA-256 hash-chained, append-only log (A12), regardless of outcome.

## Digital Twin {#sec-digital-twin}

HCI-OS maintains a live **Digital Twin** of the monitored infrastructure — a continuously-synchronized graph mirror of the same asset/topology data that powers A5's GNN Correlator, exposed to analysts as an interactive visual replica of the network rather than a static topology diagram.

**Purpose.** The Digital Twin gives an analyst a single, always-current visual model of hosts, network segments, OT/SCADA devices, and their interdependencies, so that a proposed containment action (e.g. `ISOLATE_HOST`) can be previewed against the live topology *before* it is executed — showing which downstream services, dependent assets, and safety-critical devices sit inside the blast radius.

**Components.**

| Component | Role |
|---|---|
| **Twin Graph Store** | A read-optimized projection of the Neo4j knowledge graph (same 5,026-node / 565,752-edge backing store used by A5), refreshed on every new `Evidence` and `Decision` write. |
| **State Overlay** | Per-node live status (Healthy / Under Investigation / Isolated / Compromised), color-coded and driven directly by the current `Hypothesis.state` and `Decision.action_taken` fields. |
| **Blast-Radius Preview** | Before a Human Gate approval, the Twin highlights the BFS-reachable subgraph from the target asset, using the same `Reachability × Criticality × Propagation_Probability` terms as the §12.1 blast-radius formula, so the analyst sees the *consequence* of approving an action, not just the request. |
| **Attack-Path Overlay** | Renders A5's GAT attention weights directly on the Twin's edges, visually tracing the most-attended lateral-movement path for the current leading hypothesis. |

**Real pipeline integration.** The Digital Twin is not a separate simulation running on synthetic data — it is served from the same `/api/gnn/visualization` endpoint (§24.2) that powers the Topology Dashboard, and is updated by the same A12 audit-write path that produces the tamper-evident decision log, so what the analyst sees in the Twin is guaranteed to be consistent with what is actually logged and actioned by the live pipeline.

**Relation to Feature #5 (Predictive Attack Topology Visualizer).** The Digital Twin is the runtime substrate for Feature #5 in the project's feature matrix (§8, Part A): the Cytoscape.js-based Predictive Attack Topology Visualizer is the front-end rendering of the Digital Twin's live graph state, including the progressive Level-of-Detail zoom behaviour described in §17.2 (top-15 highest-risk nodes rendered first, background technique/mitigation nodes loaded on zoom to support 2,000+ nodes without lag).

## Reference Demonstration Walkthrough

The architecture above is validated end-to-end through a rehearsed, 9-beat, 5-minute live demonstration built around the CBSE Web Server reference scenario (§2.2). The walkthrough exercises all three processing paths and the Human Gate / Kill Switch controls in a single continuous narrative, and is the operational basis for the 43-second MTTC headline figure.

| Beat | Time | What Is Shown |
|---|---|---|
| 1 — The Problem | 0:00–0:30 | CBSE Web Server shown healthy; narration sets up the 2026 reference incident (valid-credential entry, 3-day discovery lag). |
| 2 — The Attack | 0:30–1:00 | A Log4Shell payload is injected; the raw telemetry feed shows the event arriving in real time. |
| 3 — Fast Path | 1:00–1:30 | SHA-256 exact match fires in under 2ms; "KNOWN MALICIOUS — FAST PATH TRIGGERED" banner. |
| 4 — Novel Variant | 1:30–2:00 | Attack port changed 443→8443 to evade the hash match; FAISS finds 92% semantic similarity in ~16ms via the Accelerated Path. |
| 5 — Full Investigation | 2:00–2:45 | Active Hunt queries VirusTotal (47/90 engines flag it); GNN ensemble proposes H1 = APT41 (91%); Critic finds no contradicting evidence; Risk = 0.826, Blast Radius = 0.73; Human Gate triggers. |
| 6 — Explainable Timeline | 2:45–3:30 | Scrubbable T-0 → T+43s timeline; clicking any node reveals the underlying Evidence JSON and confidence scores. |
| 7 — Human-in-the-Loop | 3:30–4:00 | Analyst approves "ISOLATE_HOST"; a signed Decision object is created and the SHA-256-chained audit log updates live. |
| 8 — Kill Switch | 4:00–4:30 | Emergency Stop is triggered; the dashboard shows "EMERGENCY STOP — ACTIVE" and all outbound autonomous actions freeze. |
| 9 — The Close | 4:30–5:00 | Summary view shows a green "CONTAINED" status at the 43-second mark, closing on the cost-avoidance framing (§16). |

*Table 6.2 — 9-beat reference demonstration flow (demo_script.md). A pre-recorded 1080p/30fps backup video is maintained as a fallback if the live environment or connectivity fails during presentation.*

The team's rehearsal log records three timed run-throughs, converging from an over-time 5:45 first attempt to a 4:32 final pass, with fixes to the GNN-explanation beat length and a UI pre-fetch cache added after the second rehearsal — evidence that the 43-second MTTC and full 9-beat flow have been exercised as a live system rather than only described.

# Core Data Objects

The system shares state across all layers using three strongly-typed Pydantic schemas, forming a strict pipeline of typed transformations:

$$\text{Evidence} \;\longrightarrow\; \text{Hypothesis} \;\longrightarrow\; \text{Decision}$$

1. **Evidence (`Evidence`).** Normalized representation of raw logs (web access logs, CICIDS network flows, Windows events, OT SCADA protocols). Features a SHA-256 `content_fingerprint`, standardized entity extraction (IPs, users, process IDs, hashes), and a 256-dimensional semantic behavior embedding vector.
2. **Hypothesis (`Hypothesis`).** Represents competing explanations for observed behavior ($H_1$: APT41 Compromise vs. $H_2$: Authorized Admin Access). Calculates Bayesian probability updates:
   $$P(H_i \mid E) = \frac{P(E \mid H_i)\, P(H_i)}{\sum_{j} P(E \mid H_j)\, P(H_j)}$$
   and applies temporal decay to stale evidence over time:
   $$C_{\text{decayed}} = C_{\text{initial}} \cdot e^{-\lambda \, t_{\text{hours}}}$$
3. **Decision (`Decision`).** Versioned, cryptographically chained containment playbooks (e.g. `ISOLATE_HOST`, `BLOCK_IP`, `REVOKE_SESSION`). Each decision calculates an `audit_hash` derived from the previous entry's `audit_chain_prev`, creating a tamper-evident audit log.

# The 13-Agent Specification (A1–A13)

| Agent | Name | Core Responsibilities | Technology / Algorithms |
|---|---|---|---|
| **A1** | Ingestion & Trust | SD-0 input sanitization (7 regex patterns) & SD-1 trust scoring. Routes unknown sources to `quarantine.jsonl`. | Regex Sanitizer + Trust Matrix |
| **A2** | Normalizer & Context | Field mapping across 5 source types. Binds Indian context (holidays/elections) and OT device safety metadata (`can_reboot`). | Pydantic v2 + Asset JSON Lookup |
| **A3** | Fingerprint Router | Evaluates incoming events against Redis (Path 1) and FAISS (Path 2); routes novel events to Path 3. | Redis + FAISS Cosine Index |
| **A4** | Anomaly Detector | Tabular & temporal anomaly scoring. Generates 256-dim behavior embeddings and calculates epistemic uncertainty. | Isolation Forest + Welford Z-Score |
| **A5** | GNN Correlator | Builds dynamic subgraphs and calculates attack propagation probabilities using PyTorch model fusion. | Vectorized GAT + GraphSAGE + TGN |
| **A6** | Attribution & RAG | Queries MITRE ATT&CK, NVD CVEs, and CERT-In advisories via FAISS RAG to map threat actors and next moves. | FAISS Vector Store + Groq Llama 3.1 |
| **A7** | SOAR & Planner | Computes BFS blast radius, updates Bayesian competing hypotheses, collects counter-evidence, and triggers decisions. | BFS Graph Traversal + ACH Bayesian |
| **A8** | Critic / Skeptic | Adversarial challenger agent testing hypotheses for false-positive logic and business disruption risks. | Adversarial LLM Prompting |
| **A9** | Quarantine Verifier | Dual-agent execution sandbox validating proposed scripts/actions prior to deployment. | Dual-Agent Execution Sandbox |
| **A10** | Active Hunt | Triggered when anomaly score > 0.7 to query VirusTotal and Shodan feeds with rate-limiting and circuit breakers. | VirusTotal v3 API + Shodan Client |
| **A11** | Behavioral Watchdog | Governance wrapper enforcing agent output schemas, rate limits, and forbidden path access (SD-6). | Sliding Queue + Profile Validator |
| **A12** | Audit & Memory | Maintains immutable SHA-256 chained log (`audit_log.jsonl`), manages cognitive memory, and evaluates reviewer consensus. | SHA-256 Cryptographic Chaining |
| **A13** | Federation | Anonymizes confirmed malicious indicators and publishes STIX 2.1 bundles to peer organizations. | STIX 2.1 Indicator Exporter |

*Table 8.1 — Complete 13-agent specification.*

## A10 — Active Hunt Agent (Deep Dive)

**Trigger condition.** A10 fires when a compound gate is satisfied: the fused anomaly score from A4/A5 exceeds a hard threshold of **0.70**, *and* no active hypothesis already covers the target asset (preventing duplicate hunts on an asset already under investigation).

$$\text{trigger}(A10) = \big[\, \text{anomaly\_score} > 0.70 \,\big] \;\wedge\; \big[\, \neg\,\exists\, H_{\text{active}} \text{ for asset } a \,\big]$$

**Entity extraction.** Before querying external feeds, A10 extracts the enrichable entity set from the `Evidence` object — source/destination IPs, file hashes (MD5/SHA-1/SHA-256), and domains — deduplicating against entities already resolved in the current investigation window to avoid redundant API spend.

**VirusTotal integration.** `query_virustotal()` calls the VirusTotal v3 REST API, submitting extracted hashes/IPs and reading back the multi-engine detection ratio (e.g. `47/90 engines flagged`). This ratio is normalized into a `hunt_score` $\in [0, 1]$ used downstream in the confidence boost formula.

**Circuit breaker.** External threat-feed calls are wrapped in a resilience envelope shared with SD-3 (Resource Guardian):
- Rate limiter: **4 requests/minute** per feed.
- Circuit breaker: trips after **3 consecutive failures**, holding the circuit open ("cooling") for **60 seconds** (`CB_COOLING_SECS = 60`) before allowing a retry probe.
- On an open circuit, A10 returns immediately with `hunt_score = None` rather than blocking the pipeline, so a VirusTotal/Shodan outage never stalls Path 3 investigations.

**Confidence boost formula.** The hunt result feeds back into the current leading hypothesis's confidence as a bounded linear boost:

$$\text{boost} = 0.05 + 0.10 \times \text{hunt\_score}$$

so a fully-confirmed malicious indicator (`hunt_score = 1.0`) contributes a maximum boost of **+0.15** to hypothesis confidence, while an inconclusive result (`hunt_score = 0`) still contributes a minimum **+0.05** — reflecting that even a "clean" external lookup is weak evidence, not proof of benignity.

## A2 — Context Builders (Deep Dive)

A2 (Normalizer & Context) enriches every canonical `Evidence` object with two India- and OT-specific context blocks before it reaches the fingerprint router. These context flags are read downstream by A7 (risk scoring) and the CERT-In report generator, and are what let HCI-OS reason about *consequence*, not just *anomaly*.

### OT Context Builder

For events originating from OT/SCADA assets, A2 attaches a six-field OT context object:

| Field | Purpose |
|---|---|
| `protocol` | The industrial protocol observed (e.g. IEC-60870, Modbus, DNP3), used to select protocol-aware parsers and risk weighting. |
| `device_type` | Classifies the asset (PLC, RTU, HMI, grid controller, medical device controller, etc.). |
| `safety_critical` | Boolean flag marking assets whose disruption risks physical/human harm (e.g. life-support systems, grid breakers). |
| `can_interrupt` | Whether the asset's current process can be safely interrupted without a cascading failure. |
| `can_reboot` | Whether the asset can be power-cycled/rebooted as part of a containment action without causing an outage. |
| `impact_if_compromised` | A qualitative/quantitative estimate of downstream impact (e.g. "regional power outage", "exam-day service disruption"). |

*Table 8.2 — OT Context Builder fields (A2).* These fields feed directly into the §12.2 decision rule: `safety_critical = true` or `can_reboot = false` forces a Human Gate regardless of computed blast radius.

### Indian Context Builder

Alongside OT metadata, A2 attaches four India-specific temporal/contextual risk flags:

| Flag | Purpose |
|---|---|
| `exam_season` | True during CBSE/board-exam windows, when examination-board infrastructure is a higher-value target and false positives are more operationally costly. |
| `govt_year_end` | True during the government fiscal year-end window, when administrative systems see atypical (but legitimate) load spikes that could otherwise resemble anomalies. |
| `election_period` | True during active election windows, when state and central infrastructure face elevated, politically-motivated targeting. |
| `holiday_period` | True during national/regional holidays, when reduced staffing changes the expected baseline of "normal" administrative activity and legitimate access patterns. |

*Table 8.3 — Indian Context Builder flags (A2).* These flags act as risk multipliers rather than hard gates — e.g. an anomalous access pattern against CBSE infrastructure during `exam_season = true` is up-weighted in the A7 risk score, reflecting real-world targeting patterns rather than triggering an automatic block.

# Problem Statement

## National Context

Critical National Infrastructure (CNI) — hospitals, examination boards, power grids, and railways — is a high-value target because outages have direct human and economic consequences, and because many of these entities run end-of-life IT/OT systems with limited security budgets. CERT-In (the Indian Computer Emergency Response Team) recorded 1.59 million cybersecurity incidents in 2023, and more than 70% of surveyed government entities were found to be running end-of-life infrastructure. CERT-In's regulatory mandate requires breach reporting within **6 hours** of detection — a window that is difficult for most affected organizations to meet given current manual triage processes.

## Case Studies Motivating HCI-OS

| Incident | Sector | Impact |
|---|---|---|
| AIIMS Delhi (2022) | Healthcare | Ransomware attack; over two weeks of system downtime; patient records affected. |
| CBSE (2024) | Education / Examinations | Student examination records breached. |
| CBSE (early 2026) | Education / Examinations | Coordinated attack triggering a multi-state emergency shutdown of examination infrastructure. |
| Kudankulam Nuclear Power Plant | Energy / OT | Referenced in the project's threat model as an example of the OT/SCADA risk class the system is designed to address. |
| Power Grid (regional) | Energy | Referenced as a representative OT target where uncontrolled automated remediation (e.g. rebooting a live SCADA asset) could itself cause an outage. |

*Table 2.1 — Representative incidents referenced in the HCI-OS problem framing. Kudankulam and regional power-grid entries are used as illustrative OT risk scenarios in the project's design documents rather than as detailed case studies.*

The team's live demonstration is built around a specific reference narrative for the CBSE Web Server scenario, used to make the abstract dwell-time problem concrete for judges: *"In 2026, attackers compromised this exact asset. By using valid admin credentials and pivoting laterally, they exfiltrated student examination records without triggering traditional signature alerts. The SOC discovered the breach three days later."* This narrative — valid-credential entry, lateral pivot, signature-blind exfiltration, multi-day discovery lag — is the specific failure mode HCI-OS's behavioural/graph-based detection paths (Path 2 and Path 3, §6.3) are designed to catch where a pure signature-matching SIEM would not.

## Why Detection Speed Is the True Bottleneck

Most breaches are not undetectable — they are detected too late, after lateral movement has already occurred. The project's design documents identify three structural reasons for this delay in conventional SOC operations:

- **Alert fatigue:** signature/rule-based SIEMs generate a high volume of low-context alerts, and analysts triage manually rather than investigate systematically.
- **No persistent hypothesis:** each alert is evaluated close to independently, so slow, low-and-slow campaigns that span many small events rarely get flagged by any single rule.
- **No safe automation path:** without a principled way to bound the blast radius of an automated response, most organizations default to fully manual containment, which is slow by construction.

HCI-OS addresses each of these directly: cache-accelerated paths reduce alert fatigue on repeat/near-repeat threats, the Hypothesis object persists and accumulates evidence across events, and the SOAR layer's blast-radius and confidence thresholds provide a principled boundary for when automation is safe versus when a human must be in the loop.

# Literature / Existing Approaches Review

## Limitations of Conventional SIEM

- Signature/rule matching only recognizes previously catalogued attack patterns; novel or slightly-modified attacks (e.g. a changed port number) evade exact-match rules entirely.
- Alerts are treated as independent events rather than as evidence accumulating toward a hypothesis, so multi-stage campaigns are hard to see as a single narrative.
- Most SIEM deployments provide weak or no automated attribution (mapping observed behaviour to a known threat actor or MITRE ATT&CK technique), leaving this reasoning step to a human analyst under time pressure.
- Response is largely manual, which is safe but slow — the industry-cited dwell times of days-to-weeks are a direct consequence of this.

## Signature-Based Detection Failures

Exact-match / signature detection (e.g. hash blocklists) is fast and precise for known-bad indicators, but any adversary who changes even one byte of a payload, or one parameter of a request, bypasses it. HCI-OS treats exact-match as the fastest of three tiers rather than the only tier, adding a semantic/behavioural similarity layer and a full graph-based investigation layer behind it.

## Graph Neural Network-Based Intrusion Detection

Representing network and system entities (hosts, users, processes, IPs) as a graph, and using Graph Neural Networks (GNNs) to reason over that graph, allows a detector to use topological and temporal context rather than only per-event features. HCI-OS's Agent A5 draws on three complementary GNN architectures for this purpose:

- **Graph Attention Networks (GAT)** — learn which neighbouring relationships matter most for a given node, producing attention weights that can be surfaced to a human analyst for explainability.
- **GraphSAGE** — an inductive method that can generalize to nodes not seen during training, useful for classifying newly-appeared assets as the network topology changes.
- **Temporal Graph Networks (TGN)** — incorporate event timestamps so that fast, sequential lateral movement or brute-force patterns are distinguishable from coincidental, unrelated activity.

> *Note: A formal literature survey with academic citations (e.g. specific GAT/GraphSAGE/TGN papers, published SIEM-limitation studies) is not reproduced verbatim here; the summary above is derived from the project's own architecture rationale rather than an independent literature review, and citation-level references should be added before external publication.*

\newpage

# Solution Architecture

## Core Philosophy — Hypothesis-Driven Investigation

Rather than asking "does this event match a known-bad rule?", HCI-OS asks "what is the most probable explanation for the evidence I have observed, and how confident am I?". Every non-trivial event enters an investigation loop:

$$\text{Perceive} \rightarrow \text{Hypothesize} \rightarrow \text{Active Hunt} \rightarrow \text{Challenge (Critic)} \rightarrow \text{Bayesian Update} \rightarrow \text{Predict} \rightarrow \text{Execute} \rightarrow \text{Reflect} \rightarrow \text{Learn}$$

which then repeats as new evidence arrives.

## Novelty Statement — Context-Aware Decision Fingerprinting

The project's stated novel contribution is **Context-Aware Decision Fingerprinting**: every observation is converted into a layered fingerprint — an exact content hash, a behavioural/semantic embedding, and (when a full investigation is required) a decision outcome — and matched against a store of human-verified prior decisions before any expensive model inference is run. This lets previously-adjudicated threats and previously-adjudicated benign behaviour be resolved almost instantly, while reserving the costly GNN/LLM investigation loop for genuinely novel behaviour.

## Three-Path Design

| Path | Trigger | Target Latency | Compute Saved | Action |
|---|---|---|---|---|
| **Path 1 — Fast (Exact)** | SHA-256 exact match in Redis threat cache | < 0.1–2 ms | ~80% | Immediate reuse of the stored verdict; bypasses all ML/LLM inference. |
| **Path 2 — Accelerated (Fuzzy)** | Cosine similarity $\ge 0.85$ against FAISS behavioural embeddings | ~16 ms | ~60% | Reuses the closest historical Critic-validated verdict, with a criticality mismatch guard that falls back to Path 3 if the asset context differs. |
| **Path 3 — Full (Hypothesis Loop)** | Novel / unseen behaviour with no cache or fuzzy match | < 1 minute | 0% (full pipeline) | Full GNN correlation, RAG-based attribution, Bayesian hypothesis competition, Critic validation, and (where required) Human Gate review. |

*Table 6.1 — Three processing paths (Agent A3, Fingerprint / Hash Router).*

## High-Level Architecture Diagram

The end-to-end HCI-OS pipeline spans four functional zones: (1) universal telemetry ingestion, (2) the three-path fingerprint router, (3) the full hypothesis-driven investigation loop (A4–A9), and (4) the governance, audit, and federation layer (A11–A13), wrapped by the SD-0..SD-8 self-defense stack and the SD-8 Kill Switch.

```{=latex}
\begin{figure}[H]
\centering
\includegraphics[width=0.98\textwidth]{images/architecture_diagram.png}
\caption{End-to-end HCI-OS pipeline: 13-agent architecture, three processing paths (Fast / Accelerated / Full), data stores, Human Gate, and Kill Switch.}
\end{figure}
```

**Reading the diagram:** Raw telemetry (IT logs, OT/SCADA protocols, threat intel feeds, and the asset inventory) enters through **A1 (Ingestion & Trust Gate)** and **A2 (Normalizer & Context)**, which produces a canonical `Evidence` object. **A3 (Fingerprint Router)** then attempts, in order, an exact SHA-256 match against **Redis** (Path 1), a fuzzy cosine-similarity match against the **FAISS** vector store (Path 2), and — only on a miss — forwards the event into the full investigation loop (Path 3): **A4 (Anomaly Detector)** $\rightarrow$ **A5 (GNN Correlator Ensemble)** $\rightarrow$ **A6 (Attribution & RAG)**, enriched on demand by **A10 (Active Hunt)**. All three paths converge at **A7 (SOAR & Competing Hypotheses)**, which is challenged by **A8 (Critic/Skeptic)** and verified by **A9 (Quarantine Sandbox)** before a bounded **risk / blast-radius decision** routes the event to either **AUTO\_RESPOND** or **HUMAN\_GATE** (analyst consensus vote). Every executed decision is written to **A12's** SHA-256 audit chain and, for confirmed malicious IOCs, anonymized and shared via **A13 (Federation)**. **A11 (Behavioral Watchdog)** and the **SD-8 Kill Switch** wrap the entire pipeline as a governance and emergency-freeze layer.

### ASCII Overview of the Three-Path Router

```
                     [ Ingested Log ]
                            |
        +-------------------+-------------------+
        v                   v                   v
   [ Fast Path ]      [ Accelerated ]      [ Full Loop ]
     SHA-256              FAISS             GNN + LLM
     < 2 ms               ~16 ms              < 1 min
```

## Design Principles

- **Fail-safe by construction:** the SD-8 kill switch has no auto-release on timeout — once autonomy is frozen, it stays frozen until an explicit, logged human release.
- **Safety before speed for OT/SCADA:** if an asset's context marks `can_reboot = false`, the SOAR layer forces a Human Gate regardless of hypothesis confidence.
- **Cache before compute:** the fingerprint router always attempts Path 1 and Path 2 before invoking the GNN/LLM stack, saving an estimated 60–80% of compute on repeat and near-repeat threats.
- **Every decision is falsifiable:** the Critic (A8) agent is structurally required to look for counter-evidence — whitelist membership, known-scanner IPs, active red-team windows — before a hypothesis can drive an autonomous action.
- **Everything is audited:** every decision, correction, and self-defense rejection is written to a SHA-256 hash-chained, append-only log (A12), regardless of outcome.

## Digital Twin {#sec-digital-twin}

HCI-OS maintains a live **Digital Twin** of the monitored infrastructure — a continuously-synchronized graph mirror of the same asset/topology data that powers A5's GNN Correlator, exposed to analysts as an interactive visual replica of the network rather than a static topology diagram.

**Purpose.** The Digital Twin gives an analyst a single, always-current visual model of hosts, network segments, OT/SCADA devices, and their interdependencies, so that a proposed containment action (e.g. `ISOLATE_HOST`) can be previewed against the live topology *before* it is executed — showing which downstream services, dependent assets, and safety-critical devices sit inside the blast radius.

**Components.**

| Component | Role |
|---|---|
| **Twin Graph Store** | A read-optimized projection of the Neo4j knowledge graph (same 5,026-node / 565,752-edge backing store used by A5), refreshed on every new `Evidence` and `Decision` write. |
| **State Overlay** | Per-node live status (Healthy / Under Investigation / Isolated / Compromised), color-coded and driven directly by the current `Hypothesis.state` and `Decision.action_taken` fields. |
| **Blast-Radius Preview** | Before a Human Gate approval, the Twin highlights the BFS-reachable subgraph from the target asset, using the same `Reachability` $\times$ `Criticality` $\times$ `Propagation_Probability` terms as the §12.1 blast-radius formula, so the analyst sees the *consequence* of approving an action, not just the request. |
| **Attack-Path Overlay** | Renders A5's GAT attention weights directly on the Twin's edges, visually tracing the most-attended lateral-movement path for the current leading hypothesis. |

*Table 6.2 — Digital Twin components.*

**Real pipeline integration.** The Digital Twin is not a separate simulation running on synthetic data — it is served from the same `/api/gnn/visualization` endpoint (§24.2) that powers the Topology Dashboard, and is updated by the same A12 audit-write path that produces the tamper-evident decision log, so what the analyst sees in the Twin is guaranteed to be consistent with what is actually logged and actioned by the live pipeline.

**Relation to Feature #5 (Predictive Attack Topology Visualizer).** The Digital Twin is the runtime substrate for Feature #5 in the project's feature matrix (§8, Part A): the Cytoscape.js-based Predictive Attack Topology Visualizer is the front-end rendering of the Digital Twin's live graph state, including the progressive Level-of-Detail zoom behaviour described in §17.2 (top-15 highest-risk nodes rendered first, background technique/mitigation nodes loaded on zoom to support 2,000+ nodes without lag).

## Reference Demonstration Walkthrough

The architecture above is validated end-to-end through a rehearsed, 9-beat, 5-minute live demonstration built around the CBSE Web Server reference scenario (§2.2). The walkthrough exercises all three processing paths and the Human Gate / Kill Switch controls in a single continuous narrative, and is the operational basis for the 43-second MTTC headline figure.

| Beat | Time | What Is Shown |
|---|---|---|
| 1 — The Problem | 0:00–0:30 | CBSE Web Server shown healthy; narration sets up the 2026 reference incident (valid-credential entry, 3-day discovery lag). |
| 2 — The Attack | 0:30–1:00 | A Log4Shell payload is injected; the raw telemetry feed shows the event arriving in real time. |
| 3 — Fast Path | 1:00–1:30 | SHA-256 exact match fires in under 2ms; "KNOWN MALICIOUS — FAST PATH TRIGGERED" banner. |
| 4 — Novel Variant | 1:30–2:00 | Attack port changed 443$\to$8443 to evade the hash match; FAISS finds 92% semantic similarity in ~16ms via the Accelerated Path. |
| 5 — Full Investigation | 2:00–2:45 | Active Hunt queries VirusTotal (47/90 engines flag it); GNN ensemble proposes H1 = APT41 (91%); Critic finds no contradicting evidence; Risk = 0.826, Blast Radius = 0.73; Human Gate triggers. |
| 6 — Explainable Timeline | 2:45–3:30 | Scrubbable T-0 $\to$ T+43s timeline; clicking any node reveals the underlying Evidence JSON and confidence scores. |
| 7 — Human-in-the-Loop | 3:30–4:00 | Analyst approves "ISOLATE_HOST"; a signed Decision object is created and the SHA-256-chained audit log updates live. |
| 8 — Kill Switch | 4:00–4:30 | Emergency Stop is triggered; the dashboard shows "EMERGENCY STOP — ACTIVE" and all outbound autonomous actions freeze. |
| 9 — The Close | 4:30–5:00 | Summary view shows a green "CONTAINED" status at the 43-second mark, closing on the cost-avoidance framing (§16). |

*Table 6.3 — 9-beat reference demonstration flow (demo_script.md). A pre-recorded 1080p/30fps backup video is maintained as a fallback if the live environment or connectivity fails during presentation.*

The team's rehearsal log records three timed run-throughs, converging from an over-time 5:45 first attempt to a 4:32 final pass, with fixes to the GNN-explanation beat length and a UI pre-fetch cache added after the second rehearsal — evidence that the 43-second MTTC and full 9-beat flow have been exercised as a live system rather than only described.

\newpage

# Canonical Data Model

Every layer of HCI-OS communicates through three shared, versioned Pydantic v2 schemas: `Evidence`, `Hypothesis`, and `Decision`. These are implemented in `hci_os/objects/` and were the first component built in the sprint (Ticket 1), with 13 passing unit tests confirming SHA-256 validation, 256-dimensional embedding validation, confidence-range validation, decay computation, hash chaining, and JSON round-trip serialization.

$$\text{Evidence} \;\longrightarrow\; \text{Hypothesis} \;\longrightarrow\; \text{Decision}$$

## Evidence Object

Canonical, normalized representation of a single piece of telemetry.

| Field | Description |
|---|---|
| `evidence_id` | Unique identifier, e.g. `EV-2026-004471`. |
| `timestamp` | ISO-8601 UTC timestamp of the observation. |
| `source` | Originating feed, e.g. `web_access_log`, `cicids_2017`, `windows_event`, `netflow`, `scada`. |
| `asset_id` | Resolved asset identifier from the asset inventory, e.g. `CBSE-WebSvr-01`. |
| `normalized` | Schema-normalized fields (`src_ip`, `path`, `method`, etc.). |
| `content_fingerprint` | SHA-256 hex digest of the canonicalized event content (validated as 64-char hex). |
| `behavior_embedding` | 256-dimensional semantic/behavioural vector, L2-normalized, used for FAISS similarity search. |
| `context` | Criticality, mission tag, time-of-day, OT context (protocol, `can_reboot`, `safety_critical`) and Indian context (`exam_season`, `govt_year_end`, `election_period`, `holiday_period`) flags. |
| `confidence` / `uncertainty` | Floats in $[0,1]$ describing trust in the observation itself. |
| `provenance` | Which engine/agent produced this Evidence, e.g. `signature_engine_v2`. |

## Hypothesis Object

A competing explanation for observed behaviour, tracked through its own lifecycle. Calculates Bayesian probability updates:

$$P(H_i \mid E) = \frac{P(E \mid H_i)\, P(H_i)}{\sum_{j} P(E \mid H_j)\, P(H_j)}$$

and applies temporal decay to stale evidence over time:

$$C_{\text{decayed}} = C_{\text{initial}} \cdot e^{-\lambda \, t_{\text{hours}}}$$

| Field | Description |
|---|---|
| `hypothesis_id` | Unique identifier, e.g. `H-2026-0031`. |
| `goal` | Natural-language description of the proposed explanation, e.g. "Remote Code Execution via Log4Shell". |
| `supporting_evidence` / `evidence_against` | Lists of Evidence IDs for and against this hypothesis (the latter populated by A7's counter-evidence collection: whitelist hits, known-scanner IPs, etc.). |
| `confidence` / `uncertainty` / `confidence_decay_rate` | Bayesian probability the hypothesis is correct, its uncertainty, and an exponential decay rate applied over time via `confidence_decay(hours)`. |
| `mitre_chain` | Ordered list of MITRE ATT&CK technique IDs observed or predicted, e.g. `[T1595, T1190, T1059 (predicted)]`. |
| `mission_impact` | Business/mission criticality tag, e.g. `student_exam_records — CRITICAL`. |
| `state` | One of `ACTIVE_INVESTIGATION`, `CONFIRMED`, `REJECTED`, `CONTAINED`. |
| `competing_hypotheses` | Sub-models for alternative explanations with their own confidence values, e.g. "Security scanner false positive". |
| `world_model` | Environmental constraints — industry, criticality, `auto_isolate_allowed`, and OT safety constraints such as `can_reboot`. |
| `predicted_next_moves` | Ranked list of likely next MITRE techniques with a suggested preventive action, produced by A5's `predict_next_hop()`. |
| `get_primary_hypothesis()` / `add_timeline_event()` | Helper methods to select the leading hypothesis and append to the scrubbable investigation timeline. |

## Decision Object

A cryptographically chained containment record. Each decision calculates an `audit_hash` derived from the previous entry's `audit_chain_prev`, creating a tamper-evident audit log.

| Field | Description |
|---|---|
| `decision_id` | Unique identifier, e.g. `DEC-2026-000812`. |
| `hypothesis_id` | Foreign key to the Hypothesis that produced this decision. |
| `action_taken` | e.g. `BLOCK_IP + ISOLATE_ENDPOINT`. |
| `blast_radius_score` | Computed blast-radius value in $[0,1]$ (see §12). |
| `human_reviewed` / `reversible` | Whether a human approved the action, and whether it can be rolled back. |
| `audit_chain_prev` | SHA-256 hash of the previous Decision object, forming a tamper-evident chain. |
| `compute_hash()` / `chain(prev)` / `create_correction()` | Methods to compute the canonical hash, link to the prior decision, and produce a trust-weighted analyst correction record. |

> *Note: the worked JSON examples in the Appendix (§24.3) are reproduced from the project's own specification document as illustrative sample payloads, not live production output.*

\newpage

# Agent-by-Agent Breakdown (A1–A13)

HCI-OS organizes security operations into 12 layers orchestrated by 13 dedicated agents.

| Agent | Name | Core Responsibilities | Technology / Algorithms |
|---|---|---|---|
| **A1** | Ingestion & Trust | SD-0 input sanitization (7 regex patterns) & SD-1 trust scoring. Routes unknown sources to `quarantine.jsonl`. | Regex Sanitizer + Trust Matrix |
| **A2** | Normalizer & Context | Field mapping across 5 source types. Binds Indian context (holidays/elections) and OT device safety metadata (`can_reboot`). | Pydantic v2 + Asset JSON Lookup |
| **A3** | Fingerprint Router | Evaluates incoming events against Redis (Path 1) and FAISS (Path 2); routes novel events to Path 3. | Redis + FAISS Cosine Index |
| **A4** | Anomaly Detector | Tabular & temporal anomaly scoring. Generates 256-dim behavior embeddings and calculates epistemic uncertainty. | Isolation Forest + Welford Z-Score |
| **A5** | GNN Correlator | Builds dynamic subgraphs and calculates attack propagation probabilities using PyTorch model fusion. | Vectorized GAT + GraphSAGE + TGN |
| **A6** | Attribution & RAG | Queries MITRE ATT&CK, NVD CVEs, and CERT-In advisories via FAISS RAG to map threat actors and next moves. | FAISS Vector Store + Groq Llama 3.1 |
| **A7** | SOAR & Planner | Computes BFS blast radius, updates Bayesian competing hypotheses, collects counter-evidence, and triggers decisions. | BFS Graph Traversal + ACH Bayesian |
| **A8** | Critic / Skeptic | Adversarial challenger agent testing hypotheses for false-positive logic and business disruption risks. | Adversarial LLM Prompting |
| **A9** | Quarantine Verifier | Dual-agent execution sandbox validating proposed scripts/actions prior to deployment. | Dual-Agent Execution Sandbox |
| **A10** | Active Hunt | Triggered when anomaly score $> 0.7$ to query VirusTotal and Shodan feeds with rate-limiting and circuit breakers. | VirusTotal v3 API + Shodan Client |
| **A11** | Behavioral Watchdog | Governance wrapper enforcing agent output schemas, rate limits, and forbidden path access (SD-6). | Sliding Queue + Profile Validator |
| **A12** | Audit & Memory | Maintains immutable SHA-256 chained log (`audit_log.jsonl`), manages cognitive memory, and evaluates reviewer consensus. | SHA-256 Cryptographic Chaining |
| **A13** | Federation | Anonymizes confirmed malicious indicators and publishes STIX 2.1 bundles to peer organizations. | STIX 2.1 Indicator Exporter |

*Table 8.1 — Complete 13-agent specification.*

## A10 — Active Hunt Agent (Deep Dive)

**Trigger condition.** A10 fires when a compound gate is satisfied: the fused anomaly score from A4/A5 exceeds a hard threshold of **0.70**, *and* no active hypothesis already covers the target asset (preventing duplicate hunts on an asset already under investigation).

$$\text{trigger}(A10) = \big[\, \text{anomaly\_score} > 0.70 \,\big] \;\wedge\; \big[\, \neg\,\exists\, H_{\text{active}} \text{ for asset } a \,\big]$$

**Entity extraction.** Before querying external feeds, A10 extracts the enrichable entity set from the `Evidence` object — source/destination IPs, file hashes (MD5/SHA-1/SHA-256), and domains — deduplicating against entities already resolved in the current investigation window to avoid redundant API spend.

**VirusTotal integration.** `query_virustotal()` calls the VirusTotal v3 REST API, submitting extracted hashes/IPs and reading back the multi-engine detection ratio (e.g. `47/90 engines flagged`). This ratio is normalized into a `hunt_score` $\in [0, 1]$ used downstream in the confidence boost formula.

**Circuit breaker.** External threat-feed calls are wrapped in a resilience envelope shared with SD-3 (Resource Guardian):

- Rate limiter: **4 requests/minute** per feed.
- Circuit breaker: trips after **3 consecutive failures**, holding the circuit open ("cooling") for **60 seconds** (`CB_COOLING_SECS = 60`) before allowing a retry probe.
- On an open circuit, A10 returns immediately with `hunt_score = None` rather than blocking the pipeline, so a VirusTotal/Shodan outage never stalls Path 3 investigations.

**Confidence boost formula.** The hunt result feeds back into the current leading hypothesis's confidence as a bounded linear boost:

$$\text{boost} = 0.05 + 0.10 \times \text{hunt\_score}$$

so a fully-confirmed malicious indicator (`hunt_score = 1.0`) contributes a maximum boost of **+0.15** to hypothesis confidence, while an inconclusive result (`hunt_score = 0`) still contributes a minimum **+0.05** — reflecting that even a "clean" external lookup is weak evidence, not proof of benignity.

## A2 — Context Builders (Deep Dive)

A2 (Normalizer & Context) enriches every canonical `Evidence` object with two India- and OT-specific context blocks before it reaches the fingerprint router. These context flags are read downstream by A7 (risk scoring) and the CERT-In report generator, and are what let HCI-OS reason about *consequence*, not just *anomaly*.

### OT Context Builder

For events originating from OT/SCADA assets, A2 attaches a six-field OT context object:

| Field | Purpose |
|---|---|
| `protocol` | The industrial protocol observed (e.g. IEC-60870, Modbus, DNP3), used to select protocol-aware parsers and risk weighting. |
| `device_type` | Classifies the asset (PLC, RTU, HMI, grid controller, medical device controller, etc.). |
| `safety_critical` | Boolean flag marking assets whose disruption risks physical/human harm (e.g. life-support systems, grid breakers). |
| `can_interrupt` | Whether the asset's current process can be safely interrupted without a cascading failure. |
| `can_reboot` | Whether the asset can be power-cycled/rebooted as part of a containment action without causing an outage. |
| `impact_if_compromised` | A qualitative/quantitative estimate of downstream impact (e.g. "regional power outage", "exam-day service disruption"). |

*Table 8.2 — OT Context Builder fields (A2).* These fields feed directly into the §12.2 decision rule: `safety_critical = true` or `can_reboot = false` forces a Human Gate regardless of computed blast radius.

### Indian Context Builder

Alongside OT metadata, A2 attaches four India-specific temporal/contextual risk flags:

| Flag | Purpose |
|---|---|
| `exam_season` | True during CBSE/board-exam windows, when examination-board infrastructure is a higher-value target and false positives are more operationally costly. |
| `govt_year_end` | True during the government fiscal year-end window, when administrative systems see atypical (but legitimate) load spikes that could otherwise resemble anomalies. |
| `election_period` | True during active election windows, when state and central infrastructure face elevated, politically-motivated targeting. |
| `holiday_period` | True during national/regional holidays, when reduced staffing changes the expected baseline of "normal" administrative activity and legitimate access patterns. |

*Table 8.3 — Indian Context Builder flags (A2).* These flags act as risk multipliers rather than hard gates — e.g. an anomalous access pattern against CBSE infrastructure during `exam_season = true` is up-weighted in the A7 risk score, reflecting real-world targeting patterns rather than triggering an automatic block.

## LLM Usage Across Agents

Of the 13 agents, 4 make direct LLM calls (A6, A7, A8, A9 — the last using two isolated calls), for a conceptual total of 5 LLM "instances" in the production design. The remaining 9 agents (A1–A5, A10, A11, A12, A13) are deterministic / classical-ML and involve no LLM inference, which keeps the majority of the pipeline fast, auditable, and immune to prompt-injection risk by construction.

## Build-Mode Status (v3.3 Decision)

A major architectural decision recorded in the engineering log overrode the original plan to simulate A5, A8, and A9 with diagrams. All 13 agents were committed to real implementations; only A13 Federation remains explicitly simulated, using two local Python processes exchanging STIX-shaped JSON rather than a real cross-organization network exchange.

| Agent | Original Sprint Plan | Final Build Mode |
|---|---|---|
| A5 — GNN Correlator | SIMULATE (diagram only) | REAL — small real GAT, vectorized, trained on a seeded 25–40 node graph; GraphSAGE and TGN retrained with class weighting. |
| A8 — Critic / Skeptic | SIMULATE (diagram only) | REAL — genuine second LLM call with an adversarial system prompt. |
| A9 — Quarantine Verifier | SIMULATE (diagram only) | REAL — dual-LLM sandbox with two isolated instances. |
| A13 — Federation | SHOULD build | SIMULATED — two local processes exchanging STIX-shaped JSON (explicit, documented scope choice). |

\newpage

# Detection & ML Layer

## GNN Ensemble Design (Agent A5)

The full ensemble design combines three GNN architectures, each solving a distinct sub-problem, with their outputs concatenated and linearly projected to a 256-dimensional final node embedding:

| Model | Problem Solved | Graphs Used |
|---|---|---|
| GAT (Graph Attention Network) | Learns which relationships matter more between connected nodes; attention weights double as an explainability signal in the UI. | Entity Graph + Threat Graph |
| GraphSAGE | Inductive classification of unseen/new nodes as "Compromised" or "Clean" via neighbourhood aggregation, resilient to class imbalance. | Infrastructure Graph + Decision Graph |
| TGN (Temporal Graph Network) | Incorporates event timestamps to flag fast, sequential lateral-movement or brute-force propagation. | Evidence Graph + Entity Graph |

Ensemble fusion score:

$$\text{Score}_{\text{fused}} = 0.4 \cdot \text{Score}_{\text{GAT}} + 0.3 \cdot \text{Score}_{\text{TGN}} + 0.3 \cdot \text{Score}_{\text{GraphSAGE}}$$

For the 30-day build, the team committed to implementing a real, small GAT on a seeded graph; GraphSAGE and TGN were subsequently trained for real as well once class-imbalance weighting was resolved (see §14).

## Hashing vs. Embedding — Why Both

SHA-256 exact hashing is deterministic and near-instant, but brittle: any single-byte change in a payload defeats it. FAISS-based cosine similarity search over 256-dimensional behavioural embeddings tolerates small variations (e.g. a changed port number or slightly reworded request) while remaining fast (~16 ms). HCI-OS deliberately uses both, tiered by cost, rather than replacing one with the other.

## Datasets Used

| Dataset | Used By | Purpose |
|---|---|---|
| CICIDS-2017 / CICIDS-2018 | A4 anomaly baseline; GAT training/eval; benchmarking suite | Labelled network attack traffic (lateral movement, brute force, DDoS) for anomaly and GNN evaluation. |
| DAPT 2020 | TGN training reference; MTTD/detection-rate benchmark target | APT-style multi-stage attack telemetry for temporal correlation. |
| SWaT (Secure Water Treatment) | TGN training reference (OT/SCADA) | Industrial control system telemetry for OT-context temporal modelling. |
| UNSW-NB15 | GraphSAGE training reference; benchmark dataset | Nine attack categories used for inductive node classification evaluation. |
| CTU-13 | GraphSAGE training reference | Botnet traffic captures used for neighbourhood-aggregation classification. |
| MITRE ATT&CK (STIX 2.1) / NVD CVE feeds | A6 Attribution & RAG | TTP mapping and vulnerability context, refreshed daily (~100–150 new CVEs/day cited). |

*Table 9.1 — Datasets referenced across the ML/GNN pipeline.*

## Cross-Attention Signal Fusion

Agent A4 fuses four independent signal streams using a multi-head attention mechanism (4 heads) so that the anomaly score reflects which signal(s) most strongly drove a given verdict; the resulting attention weights are exported to a UI heatmap for analyst review.

| Signal Stream | What It Captures | Role in Fusion |
|---|---|---|
| DNS | Domain-resolution patterns, beaconing intervals, DGA-like lookups | Flags C2 beaconing and exfil-staging domains |
| Authentication | Login success/failure sequences, off-hours access, privilege escalation attempts | Flags credential misuse and lateral-movement precursors |
| Process | Parent/child process trees, unusual binary execution | Flags living-off-the-land and payload execution |
| Network | Flow volume, port/protocol anomalies, east-west traffic ratios | Flags lateral movement and data-exfiltration volume spikes |

*Table 9.2 — The four fused signal streams (`CrossAttentionFusion`, `a4_anomaly.py`).*

The fusion module computes scaled dot-product attention across the four streams (`CrossAttentionFusion` class, 4-head), so that — for example — an anomalous authentication event co-occurring with an anomalous DNS beacon is weighted more heavily than either signal alone. The resulting per-head attention weights are surfaced directly in the analyst UI as a heatmap, so a reviewer can see *which* signal combination drove a given anomaly score rather than treating A4 as a black box. For the 30-day build this fusion layer is implemented as a hand-written NumPy computation rather than a trained PyTorch `nn.MultiheadAttention` module — an explicit, documented scope simplification (§14.7, §19).

## Isolation Forest Baseline Performance

Alongside the GNN ensemble evaluated in §14.2, A4's classical Isolation Forest baseline (`IsolationForestDetector`, org-level online baseline) was evaluated independently on the same held-out telemetry window.

| Metric | Result |
|---|---|
| ROC-AUC | 0.565 |
| Detection Rate (Recall) | $\approx$ 0% on the labelled attack subset |
| FPR | Low, but uninformative given near-zero recall |

*Table 9.3 — Isolation Forest baseline evaluation.*

**Why the baseline underperforms.** Isolation Forest is an unsupervised, point-anomaly detector: it isolates observations that are numerically distant from the bulk of the data in feature space, with no awareness of graph topology, attack sequencing, or temporal context. On this dataset, the small number of true attack nodes (16 out of 5,026, $\approx$313:1 imbalance) sit close enough to the benign feature distribution — because the attacker used valid credentials and normal-looking request shapes — that a purely tabular, non-relational detector cannot separate them from noise. A ROC-AUC of 0.565 is only marginally better than random guessing (0.50).

**Impact on the architecture.** This result is the direct empirical justification for A4 acting only as a **first-pass, low-cost filter** rather than the system's primary detector: A4's role is to cheaply flag "worth a closer look," while the actual discriminative power comes from A5's graph-relational GNN ensemble (§14.2), which achieves near-perfect metrics on the same underlying attack population precisely because it can use topological and temporal context that Isolation Forest cannot see. This is reported here as an honest baseline weakness rather than omitted, consistent with the project's disclosure principle (§14.7).

\newpage

# LLM Strategy

## Production Design: 5 LLM Instances

| Instance | Model | Agent | Purpose |
|---|---|---|---|
| LLM-1 | Llama 3.x 8B (Q4, quantized) | A6 | RAG-grounded threat-intel reasoning and MITRE ATT&CK mapping. |
| LLM-2 | Llama 3.x 8B (LoRA, JSON-tuned) | A7 | Chain-of-thought playbook selection and structured Decision-object generation. |
| LLM-3 | Llama 3.x 8B (vanilla) | A8 | Critic / Skeptic — adversarial challenge of the leading hypothesis. |
| LLM-4 | Llama 3.x 8B (vanilla) | A9 (Processor) | Processes untrusted input in an isolated sandbox context. |
| LLM-5 | Llama 3.x 8B (vanilla) | A9 (Verifier) | Independently re-verifies LLM-4's output before it is trusted. |

## Why One LLM With Four Prompts (Not Five Separate Instances) for the 30-Day Build

Running five separately fine-tuned 8B models simultaneously would require roughly **40GB of VRAM** — impractical for a hackathon build environment. The team's engineering decision was to run one shared Llama 3.x 8B (Q4) instance, served locally via Ollama, and achieve the same separation of concerns through **prompt-level isolation**: each agent (A6, A7, A8, and the two A9 sub-roles) calls the model with a distinct, role-specific system prompt rather than a distinct model checkpoint.

**The trade-off, stated plainly.** A single shared instance means the "five LLM roles" are not five independently-weighted models with different training biases — they are one base model conditioned by four different system prompts. This is weaker isolation than physically separate models: in principle, a systemic bias or blind spot in the base Llama 3.x 8B checkpoint could affect A6, A7, A8, and both A9 sub-roles simultaneously, whereas genuinely separate fine-tuned instances would be less likely to share the same blind spot. The team documents this explicitly as a scope trade-off: *"Production would use 5 separate fine-tuned instances. For a 30-day build, prompt-level separation gives the same separation-of-concerns without 40GB VRAM."*

**The four role-specific prompts.** Despite sharing one checkpoint, each call site is configured with a distinct system prompt tuned to its role:

1. **Attribution prompt (A6):** grounds the model in retrieved MITRE/CVE/CERT-In context and constrains it to map observed behaviour onto known TTPs rather than speculate freely.
2. **Planner prompt (A7):** instructs the model to reason step-by-step over risk and blast-radius inputs and emit a structured, schema-conformant Decision payload.
3. **Critic/Skeptic prompt (A8):** explicitly instructs the model to *argue against* the leading hypothesis — surfacing whitelist matches, benign explanations, and business-disruption risk — rather than confirm it.
4. **Sandbox Processor/Verifier prompts (A9):** one prompt processes untrusted content defensively; a second, independent prompt re-checks that output for injected instructions or leaked secrets before it is trusted downstream.

**What this preserves, and what it doesn't.** This design preserves the architectural guarantee that matters most for defensibility under judge questioning — that A8's Critic reasoning is *procedurally* adversarial to A7's proposing reasoning (different prompt, different objective, run as a separate call), and that A9's Verifier call is *procedurally* independent of its own Processor call — while remaining feasible to run on commodity hackathon hardware. It does not, however, provide the stronger guarantee that five separately-trained models would: full independence of underlying model weights. The **production path** documented for this system is to move from one shared checkpoint with four prompts to five separately fine-tuned instances once serving infrastructure (VRAM budget, GPU fleet) supports it (§20.2).

## Fallback and Resilience

A6's Attribution & RAG agent calls the local Ollama endpoint and falls back gracefully to scenario-specific mock responses (e.g. a CBSE exam-portal or power-grid scenario template) if Ollama is offline or the call exceeds a 10-second timeout, so a single model outage does not stall the investigation pipeline. In the deployed UI, the CERT-In report narrative and the chatbot both call the Groq Cloud API (`llama-3.1-8b-instant`) on demand rather than automatically, to avoid unnecessary API cost on every event.

\newpage

# Attribution & Threat Intelligence

## MITRE ATT&CK TTP Mapping

Agent A6 maps observed and predicted adversary behaviour onto MITRE ATT&CK technique IDs (e.g. T1595 reconnaissance $\to$ T1190 exploit public-facing application $\to$ T1059 command/scripting interpreter, predicted) using STIX 2.1-formatted threat data. This produces the `mitre_chain` field on the Hypothesis object and lets the SOC analyst see not just "an anomaly occurred" but "this looks like stage 3 of an established attack pattern."

## RAG over CERT-In and CVE Feeds

A LangChain-style Retrieval-Augmented Generation pipeline indexes MITRE ATT&CK, NVD CVE data (refreshed daily, on the order of 100–150 new CVEs/day per the team's design notes), and CERT-In advisories into FAISS, so that A6's LLM call is grounded in retrieved, citeable threat-intelligence context rather than relying purely on the model's parametric knowledge.

## Campaign Genome (Sequence Attribution)

A v3.3 addition to A6 replaces a plain dictionary lookup of known campaigns with an **order-preserving sequence embedding** matched against known campaign "genomes."

**How it works.** Each observed hypothesis accumulates an ordered `mitre_chain` — the sequence of MITRE ATT&CK technique IDs observed so far, in the order they occurred (e.g. T1595 $\to$ T1190 $\to$ T1059). `match_campaign_genome()` converts this ordered sequence into a fixed-length embedding vector that preserves positional information (not just a bag of techniques), and compares it via cosine similarity against a library of known campaign genomes stored in `known_campaigns.json` — each of which is itself an ordered TTP sequence characteristic of a named threat actor or campaign family.

**Threshold and prediction.** A cosine similarity above the matching threshold surfaces the closest known campaign genome as a candidate attribution, and — critically — lets A6 read the *next* technique in that known genome's sequence as a `predicted_next` MITRE TTP, which A7 uses to suggest a targeted preventive action (e.g. pre-emptively blocking LSASS access if the matched genome's next historical step is `T1003` credential dumping).

**Why sequence order matters.** Two campaigns can involve the exact same *set* of techniques in a different order (e.g. reconnaissance-then-exploit vs. exploit-then-reconnaissance-for-persistence), which represent materially different threat actors and risk profiles. An order-preserving embedding distinguishes these cases; a plain set/dictionary lookup over technique IDs alone would treat them as identical, which is the specific gap this v3.3 addition closes.

## Indian-Context Awareness

Agent A2's Indian Context Builder attaches four contextual flags to every Evidence object — `exam_season`, `govt_year_end`, `election_period`, and `holiday_period` — using hardcoded calendar checks for the hackathon build. The design intent (documented for production) is to source these flags from live Election Commission, CBSE, and government fiscal-year calendars, since attacker activity and legitimate load patterns both shift meaningfully around these periods (e.g. exam-season traffic spikes at CBSE, or reduced SOC staffing over holiday periods).

\newpage

