# HCI-OS — Technical Architecture

HCI-OS organizes security operations into **12 layers** orchestrated by **13 dedicated agents (A1–A13)**. The system moves away from flat rule matching, instead representing threats as evolving graph states and competing hypotheses.

---

## 1. Core Data Objects

The system shares state across layers using three primary schemas:

```
[Evidence] (Canonical telemetry & embeddings)
    │
    ▼
[Hypothesis] (Bayesian competing explanations)
    │
    ▼
[Decision] (Cryptographically signed playbooks)
```

1. **Evidence:** Raw telemetry (logs, network flows, registry changes) normalized into a canonical schema. Features a 256-dimensional semantic behavior embedding.
2. **Hypothesis:** Competing explanations for observed behavior. Tracks probability metrics, MITRE TTP alignments, and temporal decay.
3. **Decision:** Cryptographically chained containment playbooks (e.g., host isolation, credential revocation) signed by SOAR and Reviewer modules.

---

## 2. The Three Processing Paths

HCI-OS routes inbound telemetry through three distinct paths to balance speed, cost, and analytical depth:

```
                  [ Ingested Log ]
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   [ Fast Path ]   [ Accelerated ]   [ Full Loop ]
     SHA-256           FAISS          GNN + LLM
     < 0.1ms           ~16ms            < 1m
```

1. **Exact Match (Fast Path):**
   - **Trigger:** SHA-256 exact match in Redis threat cache.
   - **Performance:** `< 0.1ms`. Bypasses ML/LLM inference to block known attacks instantly, saving ~80% compute.
2. **Fuzzy/Semantic Match (Accelerated Path):**
   - **Trigger:** Cosine similarity match ($\ge 0.85$) against FAISS vector database.
   - **Performance:** `~16ms`. Bypasses LLM generation to reuse historical critic verdicts, saving ~60% compute.
3. **Hypothesis Loop (Full Path):**
   - **Trigger:** Novel/unseen behavior logs.
   - **Performance:** `< 1 minute`. Triggers full GNN correlation, RAG enrichment, Critic validation, and Human Gate evaluation.

---

## 3. The 13 Agents (A1–A13)

| Agent ID | Agent Name | Primary Function | Core Technology |
|---|---|---|---|
| **A1** | Ingestion & Trust | Sanitizes inbound logs, checks origin signature, and establishes log trust. | SHA-256 trust validation |
| **A2** | Normalizer | Map raw feeds to canonical schemas and resolves asset identifiers (e.g. CBSE Web Server). | Regex + asset database lookup |
| **A3** | Fingerprint Router | Route events to Fast Path (Redis) or Accelerated Path (FAISS) or drops into Full Loop. | Redis cache + FAISS cosine index |
| **A4** | Anomaly Detector | Evaluates event deviations against historical baseline profiles. | Isolation Forest + Z-Score scoring |
| **A5** | GNN Correlator | Builds connection subgraphs and calculates attack path and compromise probabilities. | Vectorized GAT + GraphSAGE + TGN |
| **A6** | Attribution & RAG | Queries MITRE ATT&CK database via semantic search to identify campaigns/actors. | STIX 2.1 mapping + LangChain RAG |
| **A7** | SOAR & Planner | Evaluates competing hypotheses using Bayesian reasoning and maps containment steps. | Competing Bayesian Hypotheses (ACH) |
| **A8** | Critic / Skeptic | Acts as an adversarial peer, challenging containment plans to prevent business disruption. | Challenger LLM agent |
| **A9** | Quarantine Verifier| Sandbox validator testing proposed scripts/actions before deployment. | Dual-agent execution sandbox |
| **A10** | Active Hunt | Performs contextual lookups against external feeds when local evidence is incomplete. | VirusTotal API connector |
| **A11** | Behavioral Watchdog| Monitors agent actions, CPU footprints, and pipeline state to prevent agent compromise. | Profile compliance checks |
| **A12** | Audit & Memory | Records all decisions and integrity changes in a secure ledger. | Cryptographically chained JSONL |
| **A13** | Federation | Publishes anonymized STIX 2.1 indicators of compromise (IOCs) to peer organizations. | STIX 2.1 IOC exporter |

---

## 4. GNN Ensemble Design (A5)

The GNN Correlator uses an ensemble of three models to evaluate the threat topology:
- **GAT (Graph Attention Network):** Analyzes node feature dimensions and computes dynamic attention weights between interconnected servers.
- **GraphSAGE:** Uses neighborhood aggregation to classify nodes as "Compromised" or "Clean" at scale, resolving training imbalance.
- **TGN (Temporal Graph Network):** Incorporates timestamps to identify speed-based lateral pivots and brute-force propagation.
