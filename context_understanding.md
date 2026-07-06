# 🛡️ HCI-OS — Full Context Understanding
## ET Hackathon 2.0 | Round 2: Prototype Sprint

---

## 1. HACKATHON META

| Field | Details |
|-------|---------|
| Event | ET Hackathon 2.0 by Economic Times |
| Round | Round 2 — Prototype Sprint |
| Teams | ~9,800 participating |
| PS No. | PS #7 |
| Theme | Cybersecurity / Industrial Intelligence / National Security |

---

## 2. TEAM — PraxisCode X

| Member | Role |
|--------|------|
| V S S K Sai Narayana | Team Leader / Architect / Backend |
| Sujeet Jaiswal | Data Analysis / ML Modeling / DBMS |
| Sujeet Sahni | Cyber Threat Analysis / Frontend Dev / DevOps |

**Team Assignment Map:**
- **Person A (Sai Narayana)** → A2, A3, A4, A12 — Ingestion, SHA-256, Isolation Forest, JSON Audit, PostgreSQL
- **Person B (Sujeet Jaiswal)** → A5, A6, A7, A10, A13 — FAISS RAG, GNN (GAT), LLM prompts, Hunt, Federation sim
- **Person C (Sujeet Sahni)** → Dashboard, Chatbot, RBAC, Visuals — Flask/React, Timeline, Sun Graph, Kill Switch

**Critical Dependency Rule:** Person A's work (weeks 1–2) is the foundation. B & C cannot start until A finishes. B's LLM work (weeks 2–3) can run parallel to C's UI skeleton.

---

## 3. PROBLEM STATEMENT (#7)

> Build an AI-powered Cyber Resilience platform for Critical National Infrastructure that autonomously detects behavioural anomalies, correlates weak signals across heterogeneous IT and OT environments, maps attack progression against known threat frameworks, and orchestrates containment actions — compressing the time from initial compromise to detection and response **from weeks to hours**.

### Real-World Context
| Incident | Impact |
|----------|--------|
| CERT-In 2023 | 1.59M cybersecurity incidents |
| AIIMS Delhi (2022) | Ransomware → 2+ weeks downtime |
| CBSE (2024) | Student exam records breached |
| CBSE (early 2026) | Coordinated attack, multi-state emergency shutdown |
| 70%+ govt entities | Running end-of-life IT infrastructure |
| CERT-In mandate | Breach reporting within 6 hours — almost no entity can meet this |

---

## 4. SOLUTION — HCI-OS v3.3

**Full Name:** Hypothesis-Driven Cyber Investigation Operating System

**One-Line Pitch:**
> "HCI-OS is to traditional SIEM what an AI detective is to a log viewer — it investigates hypotheses, not events."

**Novelty Claim:** Context-Aware Decision Fingerprinting — every observation becomes a layered fingerprint (content → behavior → decision), matched against human-verified memory before any model inference runs.

**HCI-OS = All 5 PS options merged:**
1. Behavioural Anomaly Detection
2. APT Campaign Attribution & Prediction
3. Autonomous Incident Response Orchestration
4. Vulnerability Prioritisation
5. Cyber Resilience Digital Twin

---

## 5. FORMAL SYSTEM MODEL

```
S = ⟨ H, E, G, M, P, A, Θ ⟩
```

| Symbol | Meaning |
|--------|---------|
| H | Hypothesis Space (DAG of competing explanations) |
| E | Evidence Space (observations + provenance) |
| G | Graph (5 typed graphs) |
| M | Memory (Episodic/Semantic/Procedural/Institutional) |
| P | Policy (versioned risk thresholds, blast-radius rules, mission constraints) |
| A | Agents (13 pure functions) |
| Θ | Optimization Objective |

**Optimization Objective:**
```
Maximize U = Σ [ TP_value × Mission_Weight - FP_cost - FN_cost - Latency_penalty(t) - Blast_radius_risk ]
```

**Investigation Loop:**
```
Perception → Hypothesize → Active Hunt → Challenge (Critic) → Bayesian Update → Predict → Execute → Reflect → Learn → (loop)
```

---

## 6. THE 13 AGENTS (A1–A13)

| # | Agent | Role | Layer | LLM? |
|---|-------|------|-------|------|
| A1 | Ingestion & Trust | Sanitizes input, strips injections, scores source trust | L1 | No |
| A2 | Normalizer & Context | Schema normalization, entity extraction, mission tagging | L2 | No |
| A3 | Hash & Fingerprint | Exact (SHA-256) + Fuzzy (FAISS) lookup | L3 | No |
| A4 | Anomaly Detector | Isolation Forest, LSTM-AE vs. adaptive baseline | L4 | No |
| A5 | GNN Correlator | Heterogeneous graph; GAT/TGN/GraphSAGE | L5 | No |
| A6 | Attribution & RAG | MITRE mapping, CVE reasoning, threat actor profiles | L6 | Yes (LLM-1) |
| A7 | SOAR & Planner | Confidence/blast routing, playbook execution | L7 | Yes (LLM-2) |
| A8 | Critic / Skeptic | Challenges hypotheses, counterfactuals | L7 | Yes (LLM-3) |
| A9 | Quarantine Verifier | Dual-LLM for low-trust input | SD-2 | Yes (LLM-4 & 5) |
| A10 | Active Hunt Agent | VirusTotal, Shodan, internal searches | L5.5 | No |
| A11 | Behavioral Watchdog | Monitors agents against role profiles | SD-6 | No |
| A12 | Audit, Memory & Learning | Immutable logging, cognitive memory, EWC, RLHF | L8–L10 | No |
| A13 | Federation Agent (NEW) | Shares/receives anonymized threat intel via mock STIX/TAXII | L6 | No |

---

## 7. THE 5 LLM INSTANCES

| Instance | Model | Agent | Purpose |
|----------|-------|-------|---------|
| LLM-1 | Llama 3.x 8B (Q4) | A6 | RAG threat-intel, MITRE mapping |
| LLM-2 | Llama 3.x 8B (LoRA JSON) | A7 | Chain-of-thought, playbook selection |
| LLM-3 | Llama 3.x 8B (vanilla) | A8 | Critic/Skeptic — challenges hypotheses |
| LLM-4 | Llama 3.x 8B (vanilla) | A9 (Processor) | Processes untrusted input in isolation |
| LLM-5 | Llama 3.x 8B (vanilla) | A9 (Verifier) | Independently verifies LLM-4 output |

> **30-day build:** Use ONE Llama 3.x 8B with 4 system prompts.

---

## 8. THE 5 GRAPHS

| Graph | Node Types | Owner | Purpose |
|-------|-----------|-------|---------|
| Entity Graph | User, Device, Process, File, IP, Domain, Cloud, IAM | A5 | Raw topology |
| Infrastructure Graph | Segment, Asset, Patch, Policy, Zone | A5, A10 | Reachability + Blast Radius |
| Threat Graph | MITRE TTP, CVE, CWE, CAPEC, Threat Actor, Exploit | A6 | Attribution & reasoning |
| Evidence Graph | Hypothesis nodes, DAG edges, provenance | A8, A12 | Investigation branching |
| Decision Graph | Decision Fingerprints, supersession edges, human-overrides | A12 | Institutional memory |

**Temporal:** Sliding window 30 days; decay half-life 7 days.

---

## 9. THE 8 DATA STORES

| Level | Store | Contents | Speed | Retention |
|-------|-------|---------|-------|-----------|
| L1 — Hot Cache | Redis | Exact/fuzzy hash → verdict cache | Sub-ms | TTL-evicted |
| L2 — Threat Memory | PostgreSQL (Hash Vault) | Full hash records; human corrections | ms | Indefinite |
| L2 — Threat Memory | Neo4j (Graphs) | 5 graphs | ms | Indefinite |
| L2 — Vector Memory | FAISS | CVE/MITRE/behavior embeddings | Sub-ms ANN | Indefinite |
| L3 — Institutional | Elasticsearch + ClickHouse | Raw logs (90d); baselines; replay buffer | Second | Rolling |
| L4 — Cognitive Memory | PostgreSQL (Episodic) | Full Hypothesis Objects; past incidents | ms | Permanent |
| L4 — Immutable Audit | PostgreSQL (append-only) | Every decision, crypto-chained | Append | Permanent |
| L4 — Federation Store | PostgreSQL / JSON (DS7) | Shared IOCs, campaign genomes, peer confirmations | ms | Indefinite |

---

## 10. THE 12 LAYERS (L0–L11)

| Layer | Name | Core Job |
|-------|------|---------|
| Layer 0 | Data Sources / Ingestion | Kafka + Logstash + OpenTelemetry |
| Layer 1 | Secure Ingestion & Trust Boundary | Input sanitization, injection filtering, source trust scoring |
| Layer 2 | Normalization & Context Engine | Schema normalization, entity extraction, Indian context |
| Layer 3 | Threat Fingerprinting & Hash Acceleration | SHA-256 (exact) + FAISS (semantic) — 3 paths |
| Layer 4 | Adaptive Baseline & Concept Drift | Per-network rolling baselines; online learning |
| Layer 5 | GNN Correlation & Deep Intelligence | Heterogeneous GNN (GAT/TGN/GraphSAGE) + Cross-Attention |
| Layer 6 | Threat Attribution & Prediction | MITRE ATT&CK mapping, APT attribution, next-step prediction |
| Layer 7 | SOAR Orchestration | Confidence-tier + blast-radius routing; executes playbooks |
| Layer 8 | Audit & Decision Memory | Immutable, hash-chained logging |
| Layer 9 | Human-in-the-Loop Correction | SOC officer marks FP/FN; trust-weighted correction; RBAC |
| Layer 10 | Continual Learning & Institutional Memory | EWC + RLHF + Shadow deployment |
| Layer 11 | Agent Self-Defense | 8 sub-layers (SD-0 to SD-8) wraps ALL layers |

---

## 11. THREE PROCESSING PATHS

| Path | Trigger | Time | Compute Saved | Action |
|------|---------|------|--------------|--------|
| Path 1 — Exact Match | SHA-256 hit in Redis | < 2ms | ~80% | Immediate reuse of stored verdict |
| Path 2 — Fuzzy/Semantic | FAISS cosine > 0.85 | ~16ms | ~60% | Accelerated path + lightweight confirm |
| Path 3 — Hypothesis Investigation | No match (novel) | < 1 min | 0% | Full loop → New Decision Hash created |

---

## 12. THREE CORE OBJECTS

### Evidence Object
```json
{
  "evidence_id": "EV-2026-004471",
  "timestamp": "2026-01-15T02:47:33Z",
  "source": "web_access_log",
  "asset_id": "CBSE-WebSvr-01",
  "normalized": { "src_ip": "185.23.147.82", "path": "/api/users", "method": "GET" },
  "content_fingerprint": "sha256:...",
  "behavior_embedding": [0.031, -0.114],
  "context": { "criticality": "HIGH", "mission": "exam_records", "time_of_day": "off_hours" },
  "confidence": 0.97, "uncertainty": 0.04,
  "provenance": "signature_engine_v2"
}
```

### Hypothesis Object
```json
{
  "hypothesis_id": "H-2026-0031",
  "goal": "Remote Code Execution via Log4Shell",
  "supporting_evidence": ["EV-004471", "EV-004455"],
  "confidence": 0.91, "uncertainty": 0.05, "confidence_decay_rate": 0.02,
  "mitre_chain": ["T1595", "T1190", "T1059 (predicted next)"],
  "mission_impact": "student_exam_records — CRITICAL",
  "state": "ACTIVE_INVESTIGATION",
  "competing_hypotheses": [
    {"goal": "Security scanner false positive", "confidence": 0.06}
  ],
  "world_model": {"industry": "education", "criticality": "HIGH", "auto_isolate_allowed": true},
  "predicted_next_moves": [{"ttp": "T1003", "confidence": 0.76, "preventive_action": "block_lsass_access"}]
}
```

### Decision Object
```json
{
  "decision_id": "DEC-2026-000812",
  "hypothesis_id": "H-2026-0031",
  "action_taken": "BLOCK_IP + ISOLATE_ENDPOINT",
  "blast_radius_score": 0.42,
  "human_reviewed": false, "reversible": true,
  "audit_chain_prev": "DEC-2026-000811"
}
```

---

## 13. KEY FORMULAS

```
Risk Score = Likelihood × Impact × Exposure × Confidence

Blast Radius = Σ (Reachability_to_Crown_Jewel × Criticality × Propagation_Probability)

P(H₁ | E) = P(E | H₁) × P(H₁) / Σ P(E | Hᵢ) × P(Hᵢ)   [Bayesian Update]

Decision Rule:
  IF P(H₁) > 0.70 AND P(H₁) > 2 × P(H₂) → AUTO-RESPOND
  ELSE IF P(H₁) > 0.50 → HUMAN GATE
  ELSE → MONITOR

Decayed_Confidence = Confidence × exp(-λ × hours_since_last_update)

Effective_Weight = Base_Weight × Analyst_Seniority_Score
  Senior=0.9, Junior=0.3, External=0.8
```

---

## 14. SELF-DEFENSE LAYERS (SD-0 to SD-8)

| Sub-layer | Defends Against | Mechanism | Agent |
|-----------|----------------|-----------|-------|
| SD-0 | Direct prompt injection | Regex + pattern scan | A1 |
| SD-1 | Injection via crafted source | Source trust scoring; unknown → quarantine | A1 |
| SD-2 | Indirect injection (files/logs/RAG) | Dual-LLM sandbox (LLM-4 processes, LLM-5 verifies) | A9 |
| SD-3 | Infinite loop / DoS | Token/time/complexity limits; circuit breaker | A7 runtime |
| SD-4 | RAG poisoning, memory poisoning | Document fingerprint; write-auth; zero-trust PKI | All agents |
| SD-5 | Data exfiltration via output | Every output scanned for secrets/policy violations | Per-agent gate |
| SD-6 | Jailbreaking / gradual erosion | Behavioral Watchdog compares against role profile | A11 |
| SD-7 | All of above (forensics) | Every action logged, signed, tamper-evident | A12 |
| 🔴 SD-8 | KILL SWITCH — AI goes rogue | Emergency Stop API; 300s max autonomy timer; rollback | Dashboard |

---

## 15. THE 15 REQUESTED FEATURES

| # | Feature | Agent(s) | Status |
|---|---------|---------|--------|
| 1 | Federation simulation | A13 + DS7 | ✅ Simulated |
| 2 | Human-in-the-loop | A7 + UI (L9) | ✅ Built |
| 3 | Cross-attention (small) | A4 + XATTN | ✅ In workflow |
| 4 | Detailed report | UI + A12 | ✅ In workflow |
| 5 | Rich/interactive visuals (sun graph) | UI (Cytoscape) | ✅ In workflow |
| 6 | Predictive attack topology | A7 + UI | ✅ In workflow |
| 7 | Chatbot integration | UI + A6 | ✅ In workflow |
| 8 | Adaptive | A4 (Dual KG) | ✅ Named as limit |
| 9 | Optimized / cost-effective | A3 (3 paths) | ✅ By design |
| 10 | Indian context aware | A2 + A6 (CERT-In RAG) | ✅ By design |
| 11 | Attack campaign genome | A6 (RAG) | ✅ In workflow |
| 12 | Self-defended | A11 + SD-0..8 | ✅ Built |
| 13 | History management | A12 (Audit) | ✅ Built |
| 14 | Different UI per admin role | UI (RBAC) | ✅ In workflow |
| 15 | CERT-In compliance | A12 + UI | ✅ In workflow |

---

## 16. TECHNOLOGY STACK

| Function | Technology | Why |
|----------|-----------|-----|
| Ingestion | Apache Kafka | Exactly-once, millions/sec |
| Parsing | Logstash + OpenTelemetry | 200+ plugins, OT standard |
| Storage | Elasticsearch + ClickHouse | Full-text + 10-100× aggregation |
| Exact Hash | SHA-256 / BLAKE3 | NIST / 4× faster |
| Semantic/Behavior | FAISS + SimHash | Event-stream embedding |
| Cache | Redis | Sub-ms O(1) |
| Persistence | PostgreSQL | ACID, versioned JSON |
| Classical ML | PyOD (Isolation Forest) | Unsupervised |
| Deep ML | PyTorch (LSTM-AE, VAE) | Temporal + probabilistic |
| GNN | PyTorch Geometric (GAT, TGN, GraphSAGE) | Graph + temporal |
| Cross-Attention | PyTorch nn.MultiheadAttention | Multi-signal fusion |
| Knowledge Graph | Neo4j + NetworkX / DGL | Native graph + Cypher |
| RAG | LangChain + FAISS | Chunk → embed → retrieve → prompt |
| LLM Serving | Ollama | Local, quantized, zero cloud |
| Agent Orchestration | LangGraph + CrewAI | Stateful DAGs + role-scoped agents |
| SOAR | FastAPI + Ansible | Async + agentless automation |
| Online Learning | River ML | Incremental, concept-drift |
| Anti-Forgetting | Custom EWC | Preserves old knowledge |
| RLHF | Stable Baselines 3 (PPO) | Human preference integration |
| Audit | PostgreSQL append-only + SHA-256 chain | Tamper-evident |
| Dashboard | React + Grafana + Sigma.js | UI + metrics + graphs |
| Deployment | Docker + Kubernetes | Isolation, MeghRaj-compatible |
| Threat Intel | MITRE STIX 2.1, NVD JSON, CERT-In | Machine-readable |

---

## 17. 30-DAY BUILD SPRINT

### Priority Matrix

| Priority | Agents | What to Build | Technology | Days |
|----------|--------|--------------|-----------|------|
| 🚨 MUST (Spine) | A2, A3, A4, A7, A12 | Ingestion → SHA-256 (dict) → Isolation Forest → Mock SOAR (print) → JSON Audit | Python, sklearn, JSONL | 18 |
| ✅ SHOULD (Muscles) | A1, A6, A10, A11, A13 | Regex sanitizer → FAISS RAG → Mock Hunt (VirusTotal API) → Watchdog → Federation sim | regex, FAISS, requests | 7 |
| 📄 SIMULATE (Slides) | A5, A8, A9 | Pre-computed GNN; Describe Critic & Dual-LLM (diagrams) | NetworkX (visual) | 5 |

### Week-by-Week Milestones

| Week | Focus | Deliverable |
|------|-------|------------|
| Week 1 | Ingestion + Hash dict + Evidence Object | CSV → Evidence Object → SHA-256 lookup works |
| Week 2 | Anomaly Detection + FAISS RAG | Anomalies detected → MITRE technique mapped |
| Week 3 | SOAR mock + Audit + Human Correction + Confidence Decay | Actions logged → human correction modifies JSON → replay works |
| Week 4 | Hunt mock, Watchdog, Hypothesis UI, Benchmarks, Demo Video, Slides | Watchdog prints logs → NetworkX visual → Slides → Demo Video → Submit |

### Detailed Ticket Path

| Ticket | Scope | Phase | Developed By |
|--------|-------|-------|--------------|
| **Ticket 0** | Repo skeleton & initial stubs | Setup | Done (V S S K Sai Narayana) |
| **Ticket 1** | Evidence / Hypothesis / Decision core object schemas | Foundation | |
| **Ticket 2** | A2 Normalizer | Spine | |
| **Ticket 3** | A3 Hash/Fingerprint router | Spine | |
| **Ticket 4** | A4 Anomaly Detector | Spine | |
| **Ticket 6** | A7 SOAR & Decision | Spine | |
| **Ticket 7** | A12 Audit & Memory | Spine | |
| **Ticket 5** | A6 Attribution & RAG (once Spine produces Evidence) | Muscles | |
| **Ticket 8** | A1 Ingestion & Trust | Muscles | |
| **Ticket 9** | A10 Active Hunt | Muscles | |
| **Ticket 10**| A11 Watchdog | Muscles | |
| **Ticket 11**| A13 Federation | Muscles | |
| **Ticket 12**| Self-Defense wiring (SD-0..SD-8 integration) | Core Wiring | |
| **Ticket 13**| A5/A8/A9 simulated agents (GNN, Critic, Quarantine) | Simulation | |
| **Ticket 13.5**| Digital Twin Lite (reuses A5 GNN topology graph) | Simulation | |
| **Ticket 14**| UI layer (starts skeleton in parallel with Muscles) | UI/UX | |
| **Ticket 15**| Benchmarking & evaluation scripts (Week 4) | Testing | |
| **Ticket 16**| Business Impact & Cost Case slide prep | Judging Prep | |
| **Ticket 17**| Demo Script & backup walkthrough video | Judging Prep | |
| **Ticket 18**| Judge Q&A Playbook review & dry runs | Judging Prep | |

---

## 18. EVALUATION BENCHMARKS

| Metric | Dataset | Pass Bar |
|--------|---------|---------|
| Anomaly Detection Rate | CICIDS 2017 | Recall ≥ 0.70 |
| False Positive Rate | CICIDS 2017 | FPR ≤ 0.10 |
| MTTD | Replayed APT scenario | ≤ 60 seconds |
| MTTR | Replayed APT scenario | ≤ 90 seconds |
| MITRE ATT&CK Attribution | Replayed APT scenario | ≥ 80% accuracy |
| Automation Coverage | Ransomware playbook | ≥ 75% |

### Performance Targets vs Baseline SOC

| Metric | Baseline SOC | HCI-OS Target |
|--------|-------------|--------------|
| Known Threat Detection | Minutes | < 2ms |
| Similar Threat Detection | Hours | ~16ms |
| Novel Threat Detection | Weeks | < 1 minute |
| False Positive Rate | 35–40% | < 3% |
| MITRE Attribution | Manual/None | > 88% |
| Playbook Automation | ~25% | > 90% |
| Audit Coverage | Partial | 100% |

### Datasets to Use
- CICIDS 2017/2018 — Network attacks (lateral movement, brute force, DDoS)
- UNSW-NB15 — 9 attack categories
- SWaT / BATADAL — OT/SCADA attack detection
- CERT-In Advisories — India-specific context
- MITRE ATT&CK STIX 2.1 — TTP mapping
- NVD CVE — Daily refresh (100–150 new CVEs/day)

---

## 19. BUSINESS IMPACT

| Incident Type | Cost |
|--------------|------|
| AIIMS Delhi ransomware | ₹50–100 crore |
| CBSE data breach (2024) | ₹20–50 crore |
| Average ransomware recovery | ₹10–20 crore |
| 1.59M incidents/year | ₹10,000+ crore/year |

| HCI-OS Component | Annual Cost |
|-----------------|------------|
| Compute (3-node K8s + GPU) | ₹8–10 lakh/year |
| Storage (8 data stores) | ₹5–7 lakh/year |
| Maintenance (3-person SOC augmentation) | ₹30–40 lakh/year |
| **Total** | **~₹50 lakh/year** |

**ROI: ~20,000x** — "A single AIIMS-style outage costs ₹100 crore. HCI-OS costs ₹50 lakh/year."

---

## 20. DEMO SCRIPT (5 MINUTES)

| Time | Section | What to Show |
|------|---------|-------------|
| 0:00–0:30 | The Problem | "This is CBSE Web Server. In 2026, attackers hit it. We show how HCI-OS stops it in 43 seconds." |
| 0:30–1:00 | The Attack | Inject Log4Shell payload. Show log appearing. |
| 1:00–1:30 | Fast Path | SHA-256 match → <2ms → "KNOWN MALICIOUS" instantly. |
| 1:30–2:00 | Novel Attack | Change port (443→8443). FAISS 92% similarity → ~16ms → "SIMILAR - ACCELERATED". |
| 2:00–2:45 | Full Investigation | Active Hunt → VirusTotal → Hypothesis (H1=APT 91%, H2=Admin 6%) → Critic → Risk=0.826, Blast=0.73 → Human Gate. |
| 2:45–3:30 | Explainable Timeline | Scrubbable timeline T-0 → DNS → PowerShell → Lateral Move → Hypothesis → Decision. |
| 3:30–4:00 | Human-in-the-Loop | Human Gate panel: "ISOLATE_HOST?" APPROVE → Decision Object → Audit log. |
| 4:00–4:30 | Kill Switch | Red button → all autonomous actions freeze → "EMERGENCY STOP - ACTIVE". |
| 4:30–5:00 | Close | "43 seconds from detection to containment." |

---

## 21. JUDGE Q&A PLAYBOOK

| Question | Answer |
|---------|--------|
| "How is HCI-OS different from a SIEM?" | "A SIEM processes alerts. HCI-OS investigates hypotheses — hunts, generates competing explanations, challenges itself with a Skeptic Agent, predicts next moves, and learns permanently." |
| "What's your actual novel contribution?" | "Context-Aware Decision Fingerprinting — every observation becomes a layered fingerprint matched against human-verified memory before any model inference runs." |
| "Is the GNN real?" | "Real — GAT only, on a 25–40 node seeded graph. Attention weights actually drive what highlights on screen." |
| "Why 1 LLM instead of 5?" | "Production would use 5 separate fine-tuned instances. For 30-day build, prompt-level separation gives same separation-of-concerns without 40GB VRAM." |
| "Is the federation real?" | "No — explicitly simulated. A second local process exchanges genome match and verdict." |
| "Does this retrain itself?" | "Vault updates from human corrections change future lookups immediately. Isolation Forest and GAT do not retrain live — EWC/RLHF is roadmap." |
| "Is this connected to CERT-In?" | "No — it's an export mapping to CERT-In's 6-hour breach-reporting field format." |
| "How do you handle OT/SCADA?" | "OT Context Builder tags can_reboot, can_interrupt, safety_criticality. If can_reboot=false, Human Gate is forced regardless of confidence." |

---

## 22. RISK REGISTER

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| LLM latency >10 seconds | Medium | High | Use quantized Llama 3.x 8B (Q4). Measure Week 3. |
| GNN fails to show path | Medium | High | Pre-seed graph with exact attack path. Use pre-computed screenshot as fallback. |
| Dashboard crashes live | Medium | High | Pre-recorded video on second screen. |
| Benchmark numbers bad | Medium | Medium | Present honestly. "Directional results on subset." |
| Team member sick | Low | High | Each person documents their component. All code on GitHub. |
| Sequential component fails | Medium | High | Sprint fail-fast: if Week 1 fails, scope cut early. |
| Federation sim doesn't work | Low | Low | Show screenshot of Federation Boost logic. |

---

## 23. JUDGING CRITERIA

| Criteria | Weight |
|---------|--------|
| Innovation | 25% |
| Business Impact | 25% |
| Technical Excellence | 20% |
| Scalability | 15% |
| User Experience | 15% |

---

## 24. RED TEAM HISTORY (3 ROUNDS, 66/66 ATTACKS SOLVED)

| Round | Attacker Profile | Key Fixes Made |
|-------|----------------|---------------|
| R1 — Engineering | Microsoft Defender, CrowdStrike, Palo Alto | Created Evidence Object as shared contract; fixed fingerprint disambiguation; replaced ssdeep with FAISS |
| R2 — Research | DARPA, USENIX, NDSS | Created formal system model S=⟨H,E,G,M,P,A,Θ⟩; added risk/blast formulas; converted to Evidence DAG |
| R3 — Philosophy | "Destroy HCI-OS" Round | Shifted to hypothesis-centric paradigm; added A8 Skeptic; added A10 Active Hunt; added world_model; added kill switch |

---

## 25. FINAL SUMMARY STATISTICS

| Category | Count | Details |
|---------|-------|---------|
| Total Agents | 13 | A1–A13 |
| Agents Using LLMs | 3 | A6, A7, A8 |
| Agents with NO LLM | 10 | A1–A5, A9, A10, A11, A12, A13 |
| Total LLM Instances | 5 | Llama 3.x 8B |
| System Layers | 12 | Layer 0 → Layer 11 |
| Self-Defense Sub-layers | 8 | SD-0 to SD-7 + Kill Switch |
| Data Stores | 8 | Redis, PostgreSQL×2, Neo4j, FAISS, Elasticsearch, Cognitive Memory, Federation Store |
| Processing Paths | 3 | Exact (2ms), Fuzzy (~16ms), Hypothesis Investigation (<1min) |
| Investigation Loop Stages | 8 | Observe → Hypothesize → Hunt → Challenge → Update → Predict → Act → Reflect |
| Red Team Attacks Satisfied | 66/66 | All R1+R2+R3 |
| Features Integrated | 15/15 | All features mapped |
| ROI | ~20,000x | ₹100cr incident vs ₹0.5cr/year |

---

## 26. v3.3 FINAL COMPLIANCE — CORRECTIONS & NEW ADDITIONS
> *Sourced from KAVACH_v3.3_FINAL_COMPLETE_TICKETS.md — the authoritative implementation spec*

### 26a. Corrected Agent Count

The definitive agent count is **13 agents (A1–A13)**. The v3.3 tickets explicitly state "13 agents" in the Ticket 0 header. Any earlier reference to "12 agents" was from a prior draft and is superseded by v3.3.

> ⚠️ **MAJOR ARCHITECTURE DECISION (2026-07-07):** All agents are to be built as **REAL implementations**. The earlier "SIMULATE" designation for A5, A8, A9 is overridden. Only **A13 Federation** is explicitly simulated (two local processes). Everything else — including the GNN (A5), Critic (A8), and Dual-LLM Quarantine (A9) — will be attempted as real code. If scope constraints prevent a full implementation during the sprint, document it as a scope cut with a clear roadmap note — do NOT silently mock it.

> ⚠️ **DATA BIAS WARNING:** Architecture data has been sourced from multiple AI systems and documents across multiple sessions. There may be subtle mismatches, contradictions, or hallucinated numbers (e.g. "12 agents" vs "13 agents"). **Always treat `KAVACH_v3.3_FINAL_COMPLETE_TICKETS.md` as the single source of truth.** Cross-check any number or design decision against that file before coding.

| # | Agent | LLM? | Build Mode |
|---|-------|-------|------------|
| A1 | Ingestion & Trust | No | ✅ **REAL** (Ticket 8) |
| A2 | Normalizer & Context | No | ✅ **REAL** (Ticket 2) |
| A3 | Hash & Fingerprint Router | No | ✅ **REAL** (Ticket 3) |
| A4 | Adaptive Anomaly Detector | No | ✅ **REAL** (Ticket 4) |
| A5 | GNN Correlator (GAT + predict_next_hop) | No | ✅ **REAL** — real small GAT on seeded graph (Ticket 13) |
| A6 | Attribution & RAG | LLM-1 | ✅ **REAL** (Ticket 5) |
| A7 | SOAR & Planner | LLM-2 | ✅ **REAL** (Ticket 6) |
| A8 | Critic / Skeptic | LLM-3 | ✅ **REAL** — real second LLM call, different system prompt (Ticket 13) |
| A9 | Quarantine Verifier | LLM-4+5 | ✅ **REAL** — dual-LLM sandbox with two isolated instances (Ticket 13) |
| A10 | Active Hunt | No | ✅ **REAL** — real VirusTotal API (Ticket 9) |
| A11 | Behavioral Watchdog | No | ✅ **REAL** (Ticket 10) |
| A12 | Audit, Memory & Learning | No | ✅ **REAL** (Ticket 7) |
| A13 | Federation Agent | No | 🔁 **SIMULATED** — two local processes, STIX-shaped JSON (Ticket 11) |


### 26b. GNN Architecture (3 types, not 12)

All 3 GNN architectures run inside **Agent A5** only, using PyTorch Geometric:

| GNN | Problem Solved | Graphs Used |
|-----|---------------|-------------|
| **GAT** (Graph Attention Network) | Which relationships matter more | Entity Graph + Threat Graph |
| **TGN** (Temporal Graph Network) | How connections change over time | Evidence Graph + Entity Graph |
| **GraphSAGE** | Characterize unseen nodes from neighborhood | Infrastructure Graph + Decision Graph |

**Combined forward pass in A5:**
1. GraphSAGE → handle new/unseen nodes → `node_embeddings_sage`
2. GAT → attention-weighted embeddings + edge weights → `node_embeddings_gat` + `attention_weights` (used for UI explainability)
3. TGN → temporal memory update → `node_embeddings_tgn` + `sequence_anomaly_scores`
4. Fusion → `concat(sage, gat, tgn)` → linear projection → **256-dim final embedding** per node

For the 30-day build: **real small GAT only** on a 25–40 node seeded graph. TGN and GraphSAGE documented as roadmap.

### 26c. New Components Added in v3.3

| Component | Location | Ticket | Description |
|-----------|----------|--------|-------------|
| **OT Context Builder** | `agents/a2_normalize.py` | 2 | `build_ot_context()` function; reads `can_reboot`, `can_interrupt`, `safety_critical` from `asset_inventory.json` |
| **Indian Context Builder** | `agents/a2_normalize.py` | 2 | `build_indian_context()` — flags `exam_season`, `govt_year_end`, `election_period`, `holiday_period` |
| **Cross-Attention Fusion** | `agents/a4_anomaly.py` | 4 | `nn.MultiheadAttention(embed_dim, num_heads=4)` over stacked signal vectors; weights exported to UI heatmap |
| **Campaign Genome (sequence)** | `agents/a6_attribution.py` | 5 | Order-preserving sequence embedding + cosine similarity vs known campaigns (not plain dict lookup) |
| **Counter-Evidence Collection** | `agents/a7_soar.py` | 6 | Populates `evidence_against` in Hypothesis; penalises confidence for whitelist/scanner matches |
| **Trust-Weighted Feedback** | `agents/a12_audit.py` | 7 | `apply_human_correction()` with `SENIOR=0.9`, `JUNIOR=0.3`, `EXTERNAL=0.8`; consensus gate for high-impact corrections |
| **Shadow Deployment Promotion Check** | `agents/a12_audit.py` | 7 | `should_promote_shadow_model()` — requires precision/recall/f1 ≥ 95% of live model before promotion |
| **Federation PII Anonymizer** | `agents/a13_federation.py` | 11 | `anonymize_ioc()` strips `src_ip`, `user`, `asset_id`, `internal_domain`, `hostname`, `email` before any federation write |
| **SD-5 Secrets/PII Scanner** | `agents/a7_soar.py` / pipeline | 12 | `scan_output()` regex scanner — blocks api_key, AWS keys, phone, email, passwords from leaving pipeline |
| **Kill Switch Endpoint** | FastAPI app | 12 | `POST /emergency-stop` sets `AUTONOMY_FROZEN=True`; every autonomous action checks this flag first |
| **1-hop Predictive Attack Topology** | `agents/a5_gnn.py` | 13 | `predict_next_hop(current_node, graph, gat_attention_weights, top_k=2)` — feeds into `predicted_next_moves` |
| **🆕 Digital Twin Lite** | `agents/digital_twin.py` | 13.5 | `DigitalTwin` class with `_build_seeded_graph()`, `simulate_attack()`, `render_path()` — reuses Ticket 13 graph |
| **CERT-In Report Template** | UI (Ticket 14) | 14 | Auto-drafted report on hypothesis confirmation — includes IOCs, timeline, DPDP field, 6-hr countdown |
| **docs/** folder | repo root | 16–18 | `docs/business_impact.md`, `docs/demo_script.md`, `docs/qa_playbook.md` |

### 26d. Corrected File/Folder Structure (v3.3)

```
hci_os/
├── agents/
│   ├── a1_ingest.py
│   ├── a2_normalize.py         ← OT Context Builder + Indian Context
│   ├── a3_fingerprint.py       ← 3-path router (Exact/Fuzzy/Novel)
│   ├── a4_anomaly.py           ← Isolation Forest + LSTM-AE + Cross-Attention
│   ├── a5_gnn.py               ← GAT (real, small) + predict_next_hop()
│   ├── a6_attribution.py       ← RAG + Campaign Genome (sequence embedding)
│   ├── a7_soar.py              ← Risk/Blast formulas + Counter-Evidence + Kill Switch check
│   ├── a8_critic.py            ← Real second LLM call (different system prompt)
│   ├── a9_quarantine.py        ← Diagram only (no live code)
│   ├── a10_hunt.py             ← VirusTotal API + timeout/retry
│   ├── a11_watchdog.py         ← Role profile checker
│   ├── a12_audit.py            ← Append-only audit + trust-weighted feedback + shadow deploy
│   ├── a13_federation.py       ← anonymize_ioc() + two-process simulation
│   └── digital_twin.py         ← 🆕 DigitalTwin class (simulate_attack, render_path)
├── objects/
│   ├── evidence.py             ✅ DONE (Sujeet Jaiswal)
│   ├── hypothesis.py           ✅ DONE (Sujeet Jaiswal)
│   └── decision.py             ✅ DONE (Sujeet Jaiswal)
├── stores/
│   ├── redis_store.py
│   ├── postgres_store.py
│   ├── faiss_store.py
│   ├── neo4j_store.py
│   ├── es_store.py
│   └── federation_store.py     ← JSON/Postgres store for anonymized IOCs
├── pipeline/
│   └── investigation_loop.py
├── ui/                         ← React/Flask dashboard (Person C)
├── benchmark/
│   ├── benchmark.py
│   └── report.py
├── data/
│   ├── asset_inventory.json    ← must include can_reboot, can_interrupt, safety_critical fields
│   └── sample_logs.csv
├── docs/
│   ├── business_impact.md      ← Ticket 16
│   ├── demo_script.md          ← Ticket 17
│   └── qa_playbook.md          ← Ticket 18
└── tests/
    ├── test_objects.py          ✅ DONE — 13 passed
    └── test_agents.py
```

### 26e. Ticket 1 Compliance Check — Evidence / Hypothesis / Decision

| Criterion | Required | Implemented | Status |
|-----------|---------|-------------|--------|
| Pydantic v2 BaseModel | ✅ | ✅ | PASS |
| SHA-256 validation (64-char hex) | ✅ | ✅ | PASS |
| 256-dim embedding validation | ✅ | ✅ | PASS |
| confidence in [0,1] | ✅ | ✅ | PASS |
| `confidence_decay(hours)` method | ✅ | ✅ | PASS |
| `to_json()` / `from_json()` | ✅ | ✅ | PASS |
| Decision `compute_hash()` | ✅ | ✅ | PASS |
| Decision `chain(prev)` | ✅ | ✅ | PASS |
| Decision `create_correction()` | ✅ | ✅ | PASS |
| Hypothesis `get_primary_hypothesis()` | ✅ | ✅ | PASS |
| Hypothesis `add_timeline_event()` | ✅ | ✅ | PASS |
| 12+ unit tests all passing | ✅ | ✅ 13 passed | PASS |
| `WorldModel` sub-model | ✅ | ✅ | PASS |
| `CompetingHypothesis` sub-model | ✅ | ✅ | PASS |
| `PredictedMove` sub-model | ✅ | ✅ | PASS |

**Ticket 1 verdict: ✅ FULLY COMPLIANT**

### 26f. Key Architectural Rules (from v3.3 tickets)

1. **OT SCADA force rule:** If `can_reboot=false` → always force HUMAN_GATE regardless of confidence.
2. **Decision rule (exact):**
   - `P(H1) > 0.70 AND P(H1) > 2×P(H2)` → AUTO-RESPOND
   - `P(H1) > 0.50` → HUMAN_GATE
   - else → MONITOR
3. **Kill Switch:** `AUTONOMY_FROZEN` global flag. Every autonomous action in A7/A10/A13 must check this. No auto-release on timeout — fail-safe by design.
4. **Federation:** `anonymize_ioc()` is the ONLY write path to the Federation Store — never write raw data directly.
5. **SD-5 output judge:** `scan_output()` runs on every pipeline output before it reaches UI or external API.
6. **Shadow deployment promotion:** `should_promote_shadow_model()` must return `True` (all metrics ≥ 95% of live model) before any shadow model replaces the live model.
7. **Adaptive mode:** A4 has 3 modes controlled by config flag: `OBSERVE_ONLY` (Week 0–1) → `SUPERVISED_HYBRID` (Week 1–2) → `AUTONOMOUS` (Week 2+).
8. **Campaign Genome:** Must use order-preserving sequence embedding + cosine similarity — NOT a plain dict lookup.

### 26g. Updated Final Verified Component Counts (v3.3)

| Category | Count | Details |
|---------|-------|---------|
| Total Agents | 13 | A1–A13 |
| Agents Using LLMs | 5 | A6 (LLM-1), A7 (LLM-2), A8 (LLM-3), A9 (LLM-4+5) |
| Agents with NO LLM | 8 | A1, A2, A3, A4, A5, A10, A11, A12, A13 |
| LLM Instances | 5 | Llama 3.x 8B × 5 (1 standard, 1 LoRA JSON, 1 vanilla, 2 isolated) |
| GNN Architectures | 3 | GAT, TGN, GraphSAGE (all in A5 via PyTorch Geometric) |
| Knowledge Graphs | 5 | Entity, Infrastructure, Threat, Evidence, Decision |
| Data Stores | 8 | Redis, PostgreSQL×3, Neo4j, FAISS, Elasticsearch, Federation Store |
| Processing Paths | 3 | Exact (<2ms), Fuzzy (~16ms), Full Investigation (<1min) |
| Self-Defense Layers | 9 | SD-0 to SD-7 + Kill Switch (SD-8) |
| New in v3.3 | 5 | Digital Twin Lite, SD-5 scanner, Campaign Genome sequence, Shadow Promote Check, Federation PII anonymizer |
| Red Team Attacks | 66/66 | All R1+R2+R3 solved |
| Features Mapped | 15/15 | Including Digital Twin as Feature #5 |
| ROI | ~20,000x | ₹100cr incident vs ₹0.5cr/year |
