# 🛡️ HCI-OS — Complete Feature List & Agent Tool Call Specification
## ET AI Hackathon 2026 | Comprehensive Technical Reference

> **This document contains the 100% code-accurate feature matrix and agent-by-agent tool call specification for HCI-OS.**

---

# PART A — COMPLETE FEATURE MATRIX (HCI-OS)

| # | Feature | Category / Tier | Status in Codebase | Implementation Details |
|---|---|---|---|---|
| **1** | **Exact Hash Matching (SHA-256)** | Core Fast-Path | 🟢 **Implemented** | `a3_fingerprint.py` & `redis_store.py` (Sub-millisecond SHA-256 lookup in Redis/memory cache, `< 0.1ms`). Bypasses downstream ML/LLM calls. |
| **2** | **Fuzzy/Semantic Matching** | Core Fast-Path | 🟢 **Implemented** | `a3_fingerprint.py` & `faiss_store.py` (256-dim behavior embedding search in FAISS with cosine similarity $\ge 0.85$, `~16ms`, confidence $\times 0.95$). |
| **3** | **Dual Baseline Anomaly Detection** | Core Detection | 🟢 **Implemented** | `a4_anomaly.py` (Generic pre-trained baseline + `_org_isolation_forest` online organizational baseline). |
| **4** | **Unsupervised Anomaly Ensemble** | Core Detection | 🟢 **Implemented** | `a4_anomaly.py` (Ensemble of One-Class SVM, Isolation Forest, and Welford Rolling Z-score temporal baseline). |
| **5** | **Cross-Attention Feature Fusion** | Signal Fusion | 🟢 **Implemented** | `a4_anomaly.py` (`CrossAttentionFusion` class with 4-head scaled dot-product attention over network, auth, process, & DNS streams). |
| **6** | **Triple GNN Topology Engine** | Graph Core | 🟢 **Implemented** | `a5_gnn.py` (PyTorch GAT multi-head attention + GraphSAGE inductive classification + TGN temporal GRU dynamic memory). |
| **7** | **RAG over MITRE / CVE / CERT-In** | Threat Intel | 🟢 **Implemented** | `a6_attribution.py` & `stores/faiss_rag.py` (FAISS vector retrieval over `mitre_stix.json`, `nvd_cves.json`, and CERT-In advisories). |
| **8** | **Hypothesis Object Generation** | Core Novelty | 🟢 **Implemented** | `objects/hypothesis.py` & `a7_soar.py` (Competing Bayesian hypothesis updates $P(H_i\|E)$ with exponential decay $C \cdot e^{-\lambda t}$). |
| **9** | **Critic / Skeptic Challenge Loop** | Core Novelty | 🟢 **Implemented** | `a8_critic.py` (Groq Llama 3.1 8B call with adversarial skeptic system prompt calculating `false_positive_likelihood`). |
| **10** | **APT Attribution & Next-Move Prediction** | Threat Intelligence | 🟢 **Implemented** | `a6_attribution.py` (Predicts `predicted_next` MITRE TTPs and suggests targeted preventive actions). |
| **11** | **Attack Campaign Genome** | Novel Feature | 🟢 **Implemented** | `a6_attribution.py` (`match_campaign_genome()`, order-preserving sequence vector similarity against `known_campaigns.json`). |
| **12** | **Predictive Attack Topology Visualizer** | Interactive UX | 🟢 **Implemented** | `ET_UI/src/components/investigation/GraphView.jsx` (Cytoscape.js topological graph visualizer with progressive Level-of-Detail zoom). |
| **13** | **Autonomous SOAR Orchestrator** | Risk & Mitigation | 🟢 **Implemented** | `a7_soar.py` (Formulaic Risk Score $L \times I \times E \times C$ + BFS Blast Radius calculation over asset graph). |
| **14** | **Mission-Aware Policy Constraints** | Safety & Impact | 🟢 **Implemented** | `a2_normalize.py` & `a7_soar.py` (`can_reboot=False` or `CRITICAL` asset forces `HUMAN_GATE` instead of `AUTO_RESPOND`). |
| **15** | **Human-in-the-Loop Consensus Voting** | Governance | 🟢 **Implemented** | `a12_audit.py` & `app.py` (`process_feedback()` with trust-weighted votes: Senior: 0.9, Junior: 0.3, External: 0.8; requires $\ge 0.70$ consensus). |
| **16** | **Permanent Learning from Corrections** | Core Novelty | 🟢 **Implemented** | `a12_audit.py` & `a3_fingerprint.py` (Human corrections update decision cache and retrain baseline profiles). |
| **17** | **Immutable SHA-256 Audit Trail** | Compliance | 🟢 **Implemented** | `a12_audit.py` (`audit_log.jsonl` with `audit_hash` and `audit_chain_prev`, verified via `verify_chain()` on startup). |
| **18** | **AISOC Copilot & Chatbot** | Analyst UX | 🟢 **Implemented** | `app.py` (`POST /copilot/query`) & `CopilotPanel.jsx` (Groq Llama 3.1 8B conversational assistant with RAG context). |
| **19** | **CERT-In 6-Hour SLA Report Generator** | Compliance & Impact | 🟢 **Implemented** | `reports/generator.py`, `reports/exporter.py` (ReportLab PDF engine), and synchronized live timer (`useCountdown.js`). |
| **20** | **Vulnerability Risk Prioritization** | Asset Security | 🟢 **Implemented** | `a6_attribution.py` & `a7_soar.py` (Asset criticality $\leftrightarrow$ NVD CVE $\leftrightarrow$ Risk score mapping). |
| **21** | **Active Threat Feeds (VirusTotal & Shodan)** | Threat Hunting | 🟢 **Implemented** | `a10_hunt.py` (VirusTotal v3 REST API & Shodan REST API with rate-limiter, retries, and 60s circuit breaker). |
| **22** | **Federation STIX 2.1 Sharing** | Scalability | 🟢 **Implemented** | `a13_federation.py` & `stores/federation_store.py` (Packages IOC hashes/IPs into STIX 2.1 JSON indicators for peer orgs). |
| **23** | **9-Layer Self-Defense Framework** | AI Resilience | 🟢 **Implemented** | `a1_ingest.py`, `agents/self_defense.py`, `a11_watchdog.py` (SD-0 input sanitization, SD-1 trust gate, SD-4 write auth, SD-5 output judge, SD-6 watchdog). |
| **24** | **Role-Based Dashboard Views** | UX Polish | 🟢 **Implemented** | `ET_UI` (Incident Overview, Topology Graph, Gatekeeper Panel, Code Execution Trace, Audit Log View). |
| **25** | **Indian Context-Aware Threat Intel** | Regional Target | 🟢 **Implemented** | `a2_normalize.py` & `reports/generator.py` (Applies risk multipliers for Indian exam seasons, elections, and CERT-In advisories). |
| **26** | **Emergency Autonomy Kill Switch** | Emergency Safety | 🟢 **Implemented** | `agents/self_defense.py` (`check_kill_switch()`, `KillSwitchError`, SD-8) & `app.py` (`POST /emergency-stop`). |
| **27** | **Multi-Database Data Persistence Layer** | Persistence | 🟢 **Implemented** | `stores/mysql_store.py` (MySQL telemetry counter tables) & `stores/neo4j_store.py` (5,026 graph nodes & 565,752 edges). |
| **28** | **Stealth-Level Detection Curve** | Evaluation | ⚠️ **Methodology** | Benchmark evaluation methodology comparing MTTD against low-and-slow temporal GNN detection. |
| **29** | **Honeytoken Deception Layer** | Validation | ⚙️ **Scope Cut** | Documented architecture enhancement; simulated in telemetry feeds. |

---

# PART B — AGENT-BY-AGENT TECHNICAL OPERATIONS & CODE MAP

### 1. A1: Ingestion & Trust Agent (`a1_ingest.py`)
* **Triggered:** On every raw telemetry event (`POST /ingest` or batch loop).
* **Technical Operations & Tool Calls:**
  * **`SD-0 Input Sanitization`:** `sanitize_input()` runs 7 regex patterns screening for JNDI (`${jndi:`), SQLi, XSS, Path Traversal, and Unicode injections.
  * **`SD-1 Source Trust Scoring`:** `calculate_trust_score(source)` queries trust matrix (CERT-In: 0.95, Internal: 0.70, Unknown: 0.00).
  * **Quarantine Gate:** If `trust_score == 0.00`, routes event to `data/quarantine.jsonl` and halts pipeline execution.

### 2. A2: Normalizer & Context Agent (`a2_normalize.py`)
* **Triggered:** Immediately after A1 passes a sanitized event.
* **Technical Operations & Tool Calls:**
  * **`Schema Normalization`:** Unifies raw JSON/CSV log fields into canonical Pydantic `Evidence` object.
  * **`Entity Extraction`:** Extracts IPs, user accounts, and process IDs.
  * **`Asset Inventory Lookup`:** Reads `data/asset_inventory.json` to attach asset criticality (`CRITICAL`/`HIGH`) and OT safety metadata (`can_reboot`).
  * **`Indian Context Binds`:** Appends regional multipliers (CBSE exam season, government holidays).

### 3. A3: Fingerprint Router Agent (`a3_fingerprint.py`)
* **Triggered:** On every new `Evidence` object.
* **Technical Operations & Tool Calls:**
  * **`Exact Fingerprinting`:** `hashlib.sha256()` calculates SHA-256 `content_fingerprint`.
  * **`Path 1 (Exact Match)`:** `redis_store.get(fingerprint)` $\rightarrow$ hits Redis/memory cache (`< 0.1ms`), returning cached `Decision`.
  * **`Path 2 (Fuzzy Match)`:** `faiss_store.search(behavior_embedding, k=1, threshold=0.85)` $\rightarrow$ returns fuzzy `Decision` (`~16ms`) with confidence adjusted ($\times 0.95$).
  * **`Path 3 (Novel Event)`:** Forwards unseen events to A4 Anomaly Detector. Once A7 creates a decision, `router.cache_decision()` populates both Redis and FAISS.

### 4. A4: Anomaly Detector Agent (`a4_anomaly.py`)
* **Triggered:** Only when A3 router misses exact and fuzzy caches (novel event).
* **Technical Operations & Tool Calls:**
  * **`Point Anomaly Scoring`:** `OneClassSVMDetector.score()` (primary classifier loaded from `one_class_svm.pkl`) & `IsolationForestDetector.score()` (org baseline).
  * **`Temporal Anomaly Scoring`:** `TemporalAnomalyDetector.score()` (Welford rolling Z-score).
  * **`Cross-Attention Fusion`:** `CrossAttentionFusion.forward(signals)` applies 4-head scaled dot-product attention over network, auth, process, and DNS vectors.
  * **`Behavior Embedding`:** `BehaviorEmbedder.embed()` generates 256-dim embedding for FAISS index.

### 5. A5: GNN Correlator Ensemble Agent (`a5_gnn.py`)
* **Triggered:** When event anomaly score exceeds threshold.
* **Technical Operations & Tool Calls:**
  * **`Vectorized GAT`:** Forward pass on `models/gat.py` (multi-head attention attack path correlation, optimized via PyTorch `index_add_`).
  * **`GraphSAGE`:** Forward pass on `models/graphsage.py` (inductive node classification with class-weighting).
  * **`TGN`:** Forward pass on `models/tgn.py` (temporal GRU node memory tracking).
  * **`Ensemble Fusion`:** $\text{Score} = 0.4 \cdot \text{GAT} + 0.3 \cdot \text{TGN} + 0.3 \cdot \text{GraphSAGE}$.

### 6. A6: Attribution & RAG Agent (`a6_attribution.py`)
* **Triggered:** After A5 GNN returns correlated graph subgraphs.
* **Technical Operations & Tool Calls:**
  * **`FAISS RAG Search`:** `faiss_rag.search()` queries `mitre_stix.json`, `nvd_cves.json`, and `known_campaigns.json`.
  * **`LLM Attribution Call`:** `_call_llm()` queries Groq API (`llama-3.1-8b-instant`) with RAG context (falls back to local scenario dictionary if offline).
  * **`Campaign Genome Match`:** `match_campaign_genome()` matches TTP sequence vectors against known APT campaign genomes, predicting `predicted_next` MITRE TTPs.

### 7. A7: SOAR & Planner Agent (`a7_soar.py`)
* **Triggered:** After A6/A8 finalizes hypothesis confidence.
* **Technical Operations & Tool Calls:**
  * **`Bayesian Updating`:** Computes $P(H_i\|E)$ and applies exponential confidence decay $C \cdot e^{-\lambda t}$.
  * **`Counter-Evidence Collector`:** Checks 5 rules (whitelists, scanner IPs, TLS certs, patch windows, red-team log).
  * **`Risk & Blast Radius Math`:** Formulaic Risk Score ($L \times I \times E \times C$) + BFS Blast Radius score on `asset_graph.json`.
  * **`Gating & Playbooks`:** Directs to `AUTO_RESPOND` (Blast Radius $\le 0.3$) vs `HUMAN_GATE` (Blast Radius $> 0.3$ or `can_reboot=False`). Executes `_execute_playbook()` for `ISOLATE_HOST`, `BLOCK_IP`, `REVOKE_SESSION`.

### 8. A8: Critic / Skeptic Agent (`a8_critic.py`)
* **Triggered:** Immediately after Hypothesis Object creation.
* **Technical Operations & Tool Calls:**
  * **`Adversarial LLM Call`:** `_call_llm()` queries Groq API (`llama-3.1-8b-instant`) with `CRITIC_SYSTEM_PROMPT`.
  * **`False-Positive Scoring`:** Computes `false_positive_likelihood`. If $> 0.5$, forces `auto_isolate_allowed = False` (`HUMAN_GATE`).

### 9. A9: Quarantine Verifier Agent (`a9_quarantine.py`)
* **Triggered:** Untrusted payload sandbox verification.
* **Technical Operations & Tool Calls:**
  * **`Dual-LLM Sandbox Simulation`:** Delegates to `simulate_dual_llm()` in `agents/self_defense.py`, screening inputs across 6 injection patterns (Log4Shell, SQLi, XSS, jailbreaks).

### 10. A10: Active Hunt Agent (`a10_hunt.py`)
* **Triggered:** `anomaly_score > 0.70` AND no active hypothesis covering asset.
* **Technical Operations & Tool Calls:**
  * **`Threat Feed APIs`:** `query_virustotal()` (VirusTotal v3 REST API) & `query_shodan()` (Shodan REST API).
  * **`Circuit Breaker & Limiter`:** 4 req/min rate limiter and 60s circuit breaker (`CB_COOLING_SECS = 60`).
  * **`Confidence Boost`:** Boosts hypothesis confidence linearly: $\text{boost} = 0.05 + 0.10 \times \text{hunt\_score}$.

### 11. A11: Behavioral Watchdog Agent (`a11_watchdog.py`)
* **Triggered:** Wraps every agent execution in the pipeline (SD-6).
* **Technical Operations & Tool Calls:**
  * **`Watchdog Execution`:** `execute_with_watchdog()` enforces sliding rate limits, validates Pydantic output schemas, checks `forbidden_actions`, and blocks unauthorized path access.

### 12. A12: Audit, Memory & Learning Agent (`a12_audit.py`)
* **Triggered:** On creation or update of any `Decision` object.
* **Technical Operations & Tool Calls:**
  * **`SHA-256 Chained Logging`:** Appends entries to `data/audit_log.jsonl` with `audit_hash` and `audit_chain_prev`.
  * **`Startup Integrity Verification`:** `verify_chain()` checks log chain integrity on startup.
  * **`Human Consensus Voting`:** `process_feedback()` aggregates trust-weighted reviewer votes (Senior: 0.9, Junior: 0.3, External: 0.8) requiring $\ge 0.70$ consensus.
  * **`Cognitive Memory`:** Stores episodic memory of past hypotheses in `data/cognitive_memory.jsonl`.

### 13. A13: Federation Agent (`a13_federation.py`)
* **Triggered:** On finalized high-confidence malicious decisions.
* **Technical Operations & Tool Calls:**
  * **`SD-5 Output Gate`:** Screens outgoing payloads for secrets/PII.
  * **`STIX 2.1 Bundling`:** Packages IOC hashes and IPs into STIX 2.1 JSON indicators (`data/federation_indicators.json`).

### 14. AISOC Copilot Agent (`app.py` & `CopilotPanel.jsx`)
* **Triggered:** On-demand analyst chat queries.
* **Technical Operations & Tool Calls:**
  * **`RAG Copilot API`:** `POST /copilot/query` calls Groq Llama 3.1 8B with RAG context to answer analyst questions in natural language.

### 15. CERT-In Report Generator Agent (`reports/generator.py` & `exporter.py`)
* **Triggered:** Report export request or CERT-In tab click.
* **Technical Operations & Tool Calls:**
  * **`Dynamic PDF Engine`:** `ReportLab` PDF generator binding contact info, sector checkboxes, asset tables, and mitigation actions into official 4-page CERT-In Section 70B reports.

### 16. Emergency Autonomy Kill Switch (`agents/self_defense.py` & `app.py`)
* **Triggered:** Manually via `POST /emergency-stop` by authorized role (CISO/sysadmin).
* **Technical Operations & Tool Calls:**
  * **`Global Autonomy Freeze`:** `check_kill_switch()` raises `KillSwitchError` across A7, A10, and A13, freezing all autonomous actions instantly and forcing `HUMAN_GATE`.

---

### 💡 Presentation Key Takeaways:
* **LLM Usage:** Exactly **3 agent functions** invoke an LLM (**A6 Attribution**, **A8 Critic**, and **AISOC Copilot**) — using Groq Llama 3.1 8B with specialized system prompts and RAG context.
* **High-Speed Deterministic Core:** All other 10 agents operate using high-performance deterministic algorithms (PyTorch GAT/GraphSAGE/TGN, Isolation Forest, One-Class SVM, FAISS vector search, SHA-256 Redis caching, and BFS graph traversal).
