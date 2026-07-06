
<div align="center">

# 🛡️ KAVACH
### Hypothesis-Driven Investigation Operating System
**Final Complete Build Tickets — v3.3 FINAL**

*PS #7 — AI-Powered Cyber Resilience for Critical National Infrastructure*

| Status | Score |
|:---:|:---:|
| ✅ 66/66 Red Team Attacks Solved | **10 / 10** |
| ✅ 15/15 Requested Features Mapped | **10 / 10** |
| ✅ Digital Twin (Feature #5) — **Now Included** | **10 / 10** |

**19 tickets · 13 agents · 12 layers · 3 processing paths · 1 kill switch**

</div>

---

## 📖 Table of Contents

| # | Ticket | Priority | Owner Track |
|---|--------|----------|-------------|
| 0 | [Project Setup & Repo Skeleton](#ticket-0) | Foundation | — |
| 1 | [The Three Core Objects](#ticket-1) | Foundation | — |
| 2 | [A2 — Normalizer & Context Agent](#ticket-2) | **MUST** | Person A — Spine |
| 3 | [A3 — Hash & Fingerprint Router](#ticket-3) | **MUST** | Person A — Spine |
| 4 | [A4 — Adaptive Anomaly Detector](#ticket-4) | **MUST** | Person A — Spine |
| 5 | [A6 — Attribution & RAG Agent](#ticket-5) | SHOULD | Person B — Muscles |
| 6 | [A7 — SOAR & Planner Agent](#ticket-6) | **MUST** | Person A — Spine |
| 7 | [A12 — Audit, Memory & Learning Agent](#ticket-7) | **MUST** | Person A — Spine |
| 8 | [A1 — Ingestion & Trust Agent](#ticket-8) | SHOULD | Person B — Muscles |
| 9 | [A10 — Active Hunt Agent](#ticket-9) | SHOULD | Person B — Muscles |
| 10 | [A11 — Behavioral Watchdog](#ticket-10) | SHOULD | Person B — Muscles |
| 11 | [A13 — Federation Agent](#ticket-11) | SHOULD | Person B — Muscles |
| 12 | [Self-Defense Layer Wiring (SD-0→8)](#ticket-12) | MUST core | Person B |
| 13 | [Simulated Agents — A5, A8, A9](#ticket-13) | SIMULATE | Person B |
| **13.5** | **[🆕 Digital Twin Lite — Attack Simulation](#ticket-135)** | **MUST** | **Person B** |
| 14 | [UI Layer — Dashboard, Timeline, Kill Switch](#ticket-14) | MUST | Person C — UI |
| 15 | [Benchmarking & Evaluation](#ticket-15) | MUST | Week 4 |
| 16 | [Business Impact & Cost Case](#ticket-16) | **MUST — 25% of judging** | Judging Prep |
| 17 | [5-Minute Demo Script](#ticket-17) | MUST | Judging Prep |
| 18 | [Judge Q&A Playbook](#ticket-18) | MUST | Judging Prep |

**How to use this file:**
- Each `## TICKET` is self-contained — it carries its own context, schemas, and acceptance criteria, so a coding agent doesn't need the whole document loaded.
- Paste tickets **in order**. Later tickets assume earlier ones exist (e.g. Ticket 3 assumes the Evidence Object schema from Ticket 1).
- Each ticket ends with **"Definition of Done"** — don't move on until the output satisfies it.
- Ordered by actual build dependency (Spine → Muscles → Simulate → Judging Prep), not by agent number.

---

<a id="ticket-0"></a>
## 🎫 TICKET 0 — Project Setup & Repo Skeleton

**Context:** KAVACH is a Hypothesis-Driven Investigation Operating System for cyber resilience. It has 13 agents (A1–A13) that pass three shared objects — Evidence, Hypothesis, Decision — through 12 layers. We're building the 30-day MVP scope: some agents fully built, some mocked, some simulated with visuals only.

**Task:**
Create a Python project skeleton:
```
kavach/
  agents/          # one module per agent: a1_ingest.py, a2_normalize.py, ...
  objects/         # shared schemas: evidence.py, hypothesis.py, decision.py
  stores/          # data store clients: redis_store.py, postgres_store.py, faiss_store.py, neo4j_store.py, es_store.py
  pipeline/        # orchestration: the master investigation loop
  ui/              # dashboard (Flask or React, decide based on team skill)
  benchmark/       # evaluation scripts
  data/            # sample CSVs, seed data
  tests/
  requirements.txt
  README.md
```
Use Python 3.11+. Set up `requirements.txt` with: `redis`, `psycopg2-binary`, `faiss-cpu`, `neo4j`, `elasticsearch`, `scikit-learn`, `pyod`, `torch`, `torch-geometric`, `langchain`, `requests`, `fastapi`, `uvicorn`, `networkx`.

**Definition of Done:** Repo skeleton exists, `pip install -r requirements.txt` succeeds, empty stub modules exist for every agent A1–A13.

---

<a id="ticket-1"></a>
## 🎫 TICKET 1 — The Three Core Objects (shared contract for everything else)

**Context:** Every agent in KAVACH reads/writes one of three objects. Get these schemas exactly right — every later ticket depends on them.

**Task:**
In `objects/`, create three Python dataclasses (or Pydantic models — prefer Pydantic for validation):

```json
// Evidence Object — objects/evidence.py
{
  "evidence_id": "EV-2026-004471",
  "timestamp": "2026-01-15T02:47:33Z",
  "source": "web_access_log",
  "asset_id": "CBSE-WebSvr-01",
  "normalized": { "src_ip": "185.23.147.82", "path": "/api/users", "method": "GET" },
  "content_fingerprint": "sha256:...",
  "behavior_embedding": [0.031, -0.114],
  "context": { "criticality": "HIGH", "mission": "exam_records", "time_of_day": "off_hours" },
  "confidence": 0.97,
  "uncertainty": 0.04,
  "provenance": "signature_engine_v2"
}
```
```json
// Hypothesis Object — objects/hypothesis.py
{
  "hypothesis_id": "H-2026-0031",
  "goal": "Remote Code Execution via Log4Shell",
  "supporting_evidence": ["EV-004471"],
  "contradicting_evidence": [],
  "confidence": 0.91,
  "uncertainty": 0.05,
  "confidence_decay_rate": 0.02,
  "mitre_chain": ["T1595", "T1190"],
  "mission_impact": "student_exam_records — CRITICAL",
  "state": "ACTIVE_INVESTIGATION",
  "competing_hypotheses": [{"goal": "False positive", "confidence": 0.06}],
  "world_model": {"industry": "education", "mission": "Examination Records", "criticality": "HIGH",
                   "safety_constraints": {"can_reboot": true, "auto_isolate_allowed": true}},
  "predicted_next_moves": [{"ttp": "T1003", "confidence": 0.76, "preventive_action": "block_lsass_access"}]
}
```
```json
// Decision Object — objects/decision.py
{
  "decision_id": "DEC-2026-000812",
  "hypothesis_id": "H-2026-0031",
  "action_taken": "BLOCK_IP + ISOLATE_ENDPOINT",
  "exact_hash": "sha256:...",
  "behavior_embedding_ref": "...",
  "human_reviewed": false,
  "reversible": true,
  "blast_radius_score": 0.42,
  "audit_chain_prev": "DEC-2026-000811"
}
```

Add a `confidence_decay()` method to Hypothesis (R3 #59 — implement exactly like this, not just as a mention):

```python
def confidence_decay(self, hours_since_update: float) -> float:
    """Decayed confidence per R3 #59."""
    lambda_decay = self.confidence_decay_rate  # e.g. 0.02 per hour
    return self.confidence * math.exp(-lambda_decay * hours_since_update)
```

**Definition of Done:** Three validated model classes exist, each with `to_json()`/`from_json()`, and confidence decay is unit-tested (assert decayed confidence is strictly lower than raw confidence after >0 hours, and approaches 0 as hours grows).

---

<a id="ticket-2"></a>
## 🎫 TICKET 2 — A2: Normalizer & Context Agent (Layer 2) · `BUILD PRIORITY: MUST`

**Context:** This is the entry point of the real pipeline (Layer 1/A1 is mocked with a simple pass-through for now — the full sanitizer comes in Ticket 8). A2 takes raw log rows and turns them into Evidence Objects.

**Task:**
Build `agents/a2_normalize.py`:
1. Accepts raw log dict/CSV row as input.
2. Normalizes into the `normalized` sub-schema (src_ip, path, method, etc. — adapt fields to your dataset, e.g. CICIDS 2017 columns).
3. Does basic NER: extract IP, user, process, domain, hash if present in raw text fields.
4. Looks up asset criticality from a simple `data/asset_inventory.json` (you create this — a JSON of asset_id → criticality/mission).
5. **OT Context Builder** — build it explicitly as its own function. It's mission-awareness (world_model safety_constraints in Ticket 1) and A7 (Ticket 6) depends on it to force Human Gate on unsafe assets:
   ```python
   def build_ot_context(raw_log: dict, asset_id: str) -> dict:
       return {
           "protocol": detect_ot_protocol(raw_log),        # Modbus, DNP3, S7, OPC-UA, or None for IT
           "device_type": classify_ot_device(raw_log),     # PLC, RTU, HMI, sensor, etc.
           "safety_critical": is_safety_critical(asset_id), # True for MRI, ventilator, power-grid relay
           "can_interrupt": can_allow_interruption(asset_id),   # False for life-safety systems
           "can_reboot": can_allow_reboot(asset_id),            # False for MRI, always-on OT
           "impact_if_compromised": compute_impact(asset_id),   # LOW/MEDIUM/HIGH/CRITICAL
       }
   ```
   `is_safety_critical`, `can_allow_reboot` etc. can read from `data/asset_inventory.json` — add these fields to that file's schema now.
6. **Indian Context (Feature #10)** — build as its own explicit function:
   ```python
   def build_indian_context() -> dict:
       return {
           "exam_season": is_exam_season(),          # CBSE board exams ~March, JEE ~January
           "govt_year_end": is_government_year_end(),  # on/around March 31
           "election_period": is_election_period(),    # heightened-alert window
           "holiday_period": is_national_holiday(),
       }
   ```
   Merge both dicts into the Evidence Object's `context` and `ot_context` fields. These flags should later adjust anomaly thresholds in A4 (Ticket 4) — e.g. a spike in exam-portal traffic during exam season is less anomalous than the same spike in June.
7. Computes `content_fingerprint` = SHA-256 of the normalized payload.
8. Outputs a fully-populated `Evidence Object` (behavior_embedding can be a zero-vector placeholder for now — real embeddings come in Ticket 4).

**Definition of Done:** Given a CICIDS 2017 CSV row, A2 outputs a valid Evidence Object with all required fields populated, including a real (not stubbed) `ot_context` and `indian_context` dict (embedding placeholder is still fine at this stage).

---

<a id="ticket-3"></a>
## 🎫 TICKET 3 — A3: Hash & Fingerprint Agent + the 3-Path Router (Layer 3) · `BUILD PRIORITY: MUST`

**Context:** This is KAVACH's core optimization: don't run the full expensive pipeline on every event. Check for exact/fuzzy matches first.

**Task:**
Build `agents/a3_fingerprint.py` and `stores/redis_store.py`:
1. `redis_store.py`: wraps a Redis client. Key = `content_fingerprint` (SHA-256), value = the last Decision Object JSON for that hash.
2. `a3_fingerprint.py`:
   - **Path 1 (Exact):** look up `evidence.content_fingerprint` in Redis. If hit → return the cached Decision immediately, log it as `< 2ms` path, done (skip everything else).
   - **Path 2 (Fuzzy):** if no exact hit, compute cosine similarity of `behavior_embedding` against a FAISS index (`stores/faiss_store.py` — build this too, using `faiss.IndexFlatIP` or similar). If cosine > 0.85 → return an accelerated/confirmed verdict.
   - **Path 3 (Novel):** if neither hits → pass the Evidence Object downstream to A4 (Ticket 4) for the full investigation.
3. Log every routing decision (which path, timing) — you'll need this for the demo later.

**Definition of Done:** Given the same Evidence twice, second call returns via Path 1 in under a few ms (measured). Given a near-duplicate Evidence, it returns via Path 2. A genuinely new Evidence routes to Path 3.

---

<a id="ticket-4"></a>
## 🎫 TICKET 4 — A4: Adaptive Anomaly Detector (Layer 4) · `BUILD PRIORITY: MUST`

**Context:** This is where Path 3 (novel evidence) starts real analysis. Also where real `behavior_embedding` gets computed for future fuzzy matching.

**Task:**
Build `agents/a4_anomaly.py`:
1. Train an **Isolation Forest** (from `pyod` or `sklearn`) on a baseline slice of CICIDS 2017 (normal traffic only).
2. On new Evidence: extract numeric features from `normalized` fields, run through Isolation Forest → `anomaly_score`.
3. Add a simple **LSTM-Autoencoder** (PyTorch) for temporal sequences per asset_id — reconstruction error becomes a second signal. (If time is short, stub with a rolling z-score baseline instead — document that as a scope cut.)
4. Compute the real `behavior_embedding` here (e.g. concatenate normalized numeric features + a small learned projection) and write it back onto the Evidence Object — this is what A3/FAISS will match against for future events.
5. Implement the **adaptive mode** switch: `Week 0-1: OBSERVE_ONLY` (log only, no downstream action) → `Week 1-2: SUPERVISED_HYBRID` → `Week 2+: AUTONOMOUS`. Make this a config flag, not a real calendar dependency, for demo purposes.
6. **Cross-Attention Fusion (Feature #3)** — this is a real differentiator; its attention weights are what light up the UI heatmap in Ticket 14:
   ```python
   import torch
   import torch.nn as nn

   # Stack the per-signal-type vectors: e.g. [dns_signal, auth_signal, process_signal, network_signal]
   signal_stack = torch.stack([dns_vec, auth_vec, process_vec, network_vec])  # shape: (num_signals, batch, dim)

   attn = nn.MultiheadAttention(embed_dim=embed_dim, num_heads=4, batch_first=False)
   attended, attn_weights = attn(signal_stack, signal_stack, signal_stack)

   fused_score = attended.mean(dim=0)  # final fused anomaly signal

   # attn_weights: export this to the Evidence/Hypothesis object so the UI can render
   # "given failed auth, how suspicious is PowerShell?" as a heatmap (Ticket 14)
   ```
7. Output: `anomaly_score`, `uncertainty`, `fused_score`, `attention_weights`, updated Evidence Object with real embedding.

**Definition of Done:** Isolation Forest trained and scoring; anomaly_score correlates with known-attack rows in CICIDS 2017 (attack rows score higher than benign rows on average). Cross-Attention module runs on at least 3–4 real signal types and produces attention weights you can print/plot — not just a single anomaly number.

---

<a id="ticket-5"></a>
## 🎫 TICKET 5 — A6: Attribution & RAG Agent (Layer 6, LLM-1) · `BUILD PRIORITY: SHOULD`

**Context:** This is where MITRE ATT&CK mapping and CVE reasoning happen, using RAG over threat-intel sources.

**Task:**
Build `agents/a6_attribution.py`:
1. Set up a FAISS-backed RAG index over: MITRE ATT&CK STIX 2.1 (from `github.com/mitre/cti`), a slice of NVD CVE JSON, and a small hand-written set of CERT-In advisory summaries.
2. Given an anomalous Evidence Object (from A4), retrieve top-k relevant MITRE techniques / CVEs via embedding similarity.
3. Call a local Llama 3.x 8B (via Ollama) with a system prompt like: *"You are a threat attribution analyst. Given this evidence and these retrieved MITRE techniques, identify the most likely TTP chain, cite technique IDs, and note your confidence."*
4. Implement trust-weighted source scoring: CERT-In=0.95, MITRE=0.90, NVD=0.85 — if two sources conflict, keep both citations but weight the higher-trust one more.
5. **Campaign Genome — sequence embedding, not a plain dict lookup (Feature #11).** Implement as an order-preserving sequence embedding with cosine similarity, so partial/reordered/noisy matches still score sensibly:
   ```python
   from typing import List, Dict

   def compute_genome_similarity(observed_ttps: List[str], known_campaigns: Dict[str, List[str]]) -> dict:
       # sequence_encoder should preserve order (e.g. a small RNN/positional-embedding average, or
       # a simple weighted-position bag-of-TTPs if time is short — just don't discard order entirely)
       observed_embedding = sequence_encoder(observed_ttps)  # 256-dim

       best_match, best_score, best_campaign_ttps = None, 0.0, None
       for campaign_name, campaign_ttps in known_campaigns.items():
           campaign_embedding = sequence_encoder(campaign_ttps)
           score = cosine_similarity(observed_embedding, campaign_embedding)
           if score > best_score:
               best_match, best_score, best_campaign_ttps = campaign_name, score, campaign_ttps

       if best_score > 0.85 and len(observed_ttps) < len(best_campaign_ttps):
           predicted_next = best_campaign_ttps[len(observed_ttps)]  # next TTP in the matched sequence
           return {"matched_campaign": best_match, "confidence": best_score, "predicted_next": predicted_next}
       return {"matched_campaign": None, "confidence": 0.0, "predicted_next": None}
   ```
   Seed `known_campaigns` with a handful of real MITRE-documented sequences (e.g. `APT41: [T1595, T1190, T1059]`) from the STIX data loaded in step 1.
6. Output: updates the Hypothesis Object's `mitre_chain`, adds `predicted_next_moves` and the genome match result from step 5.

**Definition of Done:** Given a seeded attack Evidence (e.g. simulated Log4Shell payload), A6 returns a MITRE technique chain with a citation, a next-move prediction, and a genome-similarity score (not just an exact-match hit/miss).

---

<a id="ticket-6"></a>
## 🎫 TICKET 6 — A7: SOAR & Planner Agent (Layer 7, LLM-2) · `BUILD PRIORITY: MUST`

**Context:** This is the decision brain — it decides AUTONOMOUS vs. HUMAN_GATE vs. MONITOR, and creates the Decision Object.

**Task:**
Build `agents/a7_soar.py`:
1. Implement the formulas exactly:
   ```
   Risk = Likelihood × Impact × Exposure × Confidence
   Blast Radius = Σ (Reachability_to_Crown_Jewel × Criticality × Propagation_Probability)
   ```
   For the 30-day build, `Reachability` and `Propagation_Probability` can come from a simple static asset-graph lookup (JSON), not a full GNN — document it as a scope cut vs. the full A5 GNN.
2. Implement the Bayesian update for competing hypotheses:
   ```
   P(H₁|E) = P(E|H₁) × P(H₁) / Σ P(E|Hᵢ) × P(Hᵢ)
   ```
3. Implement the decision rule exactly:
   ```
   IF P(H₁) > 0.70 AND P(H₁) > 2×P(H₂) → AUTO-RESPOND
   ELSE IF P(H₁) > 0.50 → HUMAN GATE
   ELSE → MONITOR
   ```
4. Check the Hypothesis's `world_model.safety_constraints` — if `can_reboot=false` or it's an OT/SCADA asset, force HUMAN GATE regardless of confidence.
5. **Counter-Evidence Collection (R3 #48)** — populate the `evidence_against` field so contradicting evidence actually pushes confidence down instead of only ever going up:
   ```python
   counter_evidence = []
   if hypothesis.asset_id in whitelist:
       counter_evidence.append({"type": "whitelist", "weight": 0.7})
       hypothesis.confidence *= 0.8  # penalty
   if hypothesis.source_ip in known_scanner_ips:
       counter_evidence.append({"type": "known_scanner", "weight": 0.6})
       hypothesis.confidence *= 0.85
   # extend with more checks as you find them: valid_cert, active_redteam_window, patch_testing_window, etc.
   hypothesis.evidence_against = counter_evidence
   ```
6. For the 30-day build, "playbook execution" can be a `print()`/log statement describing the action (mock SOAR) rather than a real firewall API call — an explicit, honest scope cut.
7. Output: a Decision Object with `blast_radius_score`, `action_taken`, `human_reviewed: false`, and the Hypothesis's populated `evidence_against`.

**Definition of Done:** Given a Hypothesis with confidence 0.91 and low blast radius, A7 outputs AUTONOMOUS action. Given confidence 0.91 but high blast radius, A7 outputs HUMAN_GATE. Given confidence 0.4, outputs MONITOR.

---

<a id="ticket-7"></a>
## 🎫 TICKET 7 — A12: Audit, Memory & Learning Agent (Layers 8–10) · `BUILD PRIORITY: MUST`

**Context:** Every decision must be logged immutably, and human corrections must feed back into the system.

**Task:**
Build `agents/a12_audit.py` and `stores/postgres_store.py`:
1. Append-only audit log table in PostgreSQL: each row = a Decision Object + a SHA-256 hash chained to the previous row's hash (`audit_chain_prev`). Verify tamper-evidence with a `verify_chain()` function that recomputes hashes.
2. A "Cognitive Memory" table: full Hypothesis Objects, permanent (for past-incident lookup).
3. **Trust-Weighted Human Feedback** — implement as an explicit formula and function:
   ```python
   SENIOR_WEIGHT = 0.9
   JUNIOR_WEIGHT = 0.3
   EXTERNAL_WEIGHT = 0.8
   CONSENSUS_THRESHOLD = 0.7  # weighted consensus required for high-impact corrections

   def apply_human_correction(decision_id, correction_type, analyst_role, analyst_id):
       weight = {"senior": SENIOR_WEIGHT, "junior": JUNIOR_WEIGHT}.get(analyst_role, EXTERNAL_WEIGHT)

       # High-impact corrections (e.g. overriding an already-executed autonomous action)
       # require weighted consensus across reviewers before they take effect
       if is_high_impact(correction_type):
           consensus = get_weighted_consensus(decision_id, correction_type)  # sum of weights of agreeing reviewers
           if consensus < CONSENSUS_THRESHOLD:
               return {"status": "PENDING_CONSENSUS", "current_score": consensus}

       # Apply correction: update decision hash, chain a new audit entry, queue shadow deployment
       ...
   ```
   - On REVOKE: mark decision reversed, recompute `Effective_Weight = Base_Weight × Analyst_Seniority_Score`, and if effective weight/impact crosses `CONSENSUS_THRESHOLD`, mark for "shadow deployment" (a flag/log for the 30-day build — real EWC retraining is roadmap, say so explicitly).
4. Implement `Decayed_Confidence = Confidence × exp(-λ × hours_since_last_update)` as a scheduled recompute (can be triggered manually via a script for demo purposes) — this reuses the `confidence_decay()` method from Ticket 1, don't reimplement it here.
5. **🆕 Shadow Deployment Promotion Check** — before any shadow model is promoted to live, gate it on a real metric comparison, not a vibe check:
   ```python
   def should_promote_shadow_model(shadow_results: dict, live_results: dict) -> bool:
       metrics = ["precision", "recall", "f1"]
       for m in metrics:
           if shadow_results.get(m, 0) < live_results.get(m, 0) * 0.95:
               return False
       return True
   ```
   Wire this into the shadow-deployment flag from step 3 — a shadow model only replaces the live one if `should_promote_shadow_model()` returns `True`.

**Definition of Done:** A Decision written to Postgres, chain-verified. A human correction updates the Hypothesis and the audit log with a new chained entry. Confidence decay is demonstrable via script. `should_promote_shadow_model()` is unit-tested with at least one promote and one reject case.

---

<a id="ticket-8"></a>
## 🎫 TICKET 8 — A1: Ingestion & Trust Agent (Layer 1) · `BUILD PRIORITY: SHOULD`

**Context:** This wraps the front door — sanitization and source trust scoring. Build after the spine (Tickets 2–7) works end to end, then insert this in front of A2.

**Task:**
Build `agents/a1_ingest.py`:
1. Regex-based sanitizer: strip common injection patterns (`${jndi:`, script tags, SQL injection markers, hidden unicode chars).
2. Source trust table: `{"CERT-In": 0.95, "MITRE": 0.90, "NVD": 0.85, "vendor": 0.75, "unknown": 0.00}`. Unknown sources get quarantined (routed to a separate queue, not into A2).
3. Simple OT protocol tag detector: if raw log contains Modbus/DNP3/S7 signatures, tag `ot_context.protocol`.
4. Output: sanitized raw record + `trust_score`, ready for A2.

**Definition of Done:** A crafted injection payload gets stripped/flagged before reaching A2. An "unknown" source gets quarantined, not processed.

---

<a id="ticket-9"></a>
## 🎫 TICKET 9 — A10: Active Hunt Agent (Layer 5.5) · `BUILD PRIORITY: SHOULD`

**Context:** This agent actively goes and looks for corroborating evidence instead of waiting passively — a key Red Team fix ("passive system" criticism).

**Task:**
Build `agents/a10_hunt.py`:
1. Trigger condition: `anomaly_score > 0.7 AND no open hypothesis matches`.
2. Call the real **VirusTotal API** (free tier) for IP/hash/domain reputation lookups on entities extracted from the Evidence.
3. Optionally call **Shodan API** for exposed-service lookups (only if API key available — otherwise stub with a documented "roadmap" note).
4. Wrap all external calls in a simple retry + timeout (this is also a defense point — see Ticket 12, SD-3).
5. Output: a new Evidence Object representing the hunt result (e.g. "VT: 47/90 engines flagged malicious"), fed back into the Hypothesis's `supporting_evidence`.

**Definition of Done:** Given a known-malicious test IP/hash, A10 returns a real VirusTotal verdict and it's attached as new supporting evidence on the Hypothesis.

---

<a id="ticket-10"></a>
## 🎫 TICKET 10 — A11: Behavioral Watchdog (SD-6) · `BUILD PRIORITY: SHOULD`

**Context:** Monitors all other agents for role/behavior drift — a self-defense agent, but simple enough to build for real (not simulated).

**Task:**
Build `agents/a11_watchdog.py`:
1. Define a "role profile" per agent (allowed actions, expected call frequency, expected output schema).
2. After each agent call in the pipeline, check its output against its role profile (e.g. A3 should never write a Decision directly; A7 should never call an external network API).
3. On violation: log + `print()` a suspend/escalate warning (real automated suspension can be a stretch goal — logging alone is a fine scope cut for 30 days).

**Definition of Done:** Feeding a deliberately malformed agent output (e.g. A3 producing a fake Decision) triggers a logged Watchdog alert.

---

<a id="ticket-11"></a>
## 🎫 TICKET 11 — A13: Federation Agent (Layer 6, parallel to A6) · `BUILD PRIORITY: SHOULD`

**Context:** Simulated cross-org intelligence sharing. Explicitly label this as simulated in the UI and to judges.

**Task:**
Build `agents/a13_federation.py` and `stores/federation_store.py` (simple JSON file or Postgres table = DS7):
1. When a Hypothesis is confirmed APT (confidence > 0.85), anonymize its IOC (strip internal IPs/PII, keep hash/TTP sequence) and write it as a STIX-2.1-shaped JSON record to the Federation Store.
2. On new Evidence ingestion (in A1 or A2), check the Federation Store for a matching IOC. If found, boost confidence by `+0.05 to +0.15` (peer confirmation).
3. Run this as **two local processes** (or two federation_store instances) to genuinely simulate "org A" and "org B" exchanging intel — this makes the simulation demo-able and honest.
4. **🆕 Federation Privacy — enforce PII stripping in code, not just as a design intention.** Every IOC exported to the Federation Store must pass through an explicit anonymizer:
   ```python
   # Federation — Anonymization
   PII_FIELDS = ["src_ip", "user", "asset_id", "internal_domain", "hostname", "email"]

   def anonymize_ioc(evidence: Evidence, hypothesis: Hypothesis) -> dict:
       raw_ioc = hypothesis.to_dict()
       for field in PII_FIELDS:
           raw_ioc.pop(field, None)
       # Keep: TTP sequence, behavior_hash, confidence, kill_chain_stage
       return raw_ioc
   ```
   Call `anonymize_ioc()` as the *only* path by which data reaches `federation_store.write()` — no other function should write to the Federation Store directly.

**Definition of Done:** Confirming an APT hypothesis in "Org A" process populates the Federation Store; ingesting the same IOC in "Org B" process shows a measurable confidence boost. A unit test confirms `anonymize_ioc()` output contains none of the `PII_FIELDS` keys.

---

<a id="ticket-12"></a>
## 🎫 TICKET 12 — Self-Defense Layer Wiring (SD-0 to SD-8) · `BUILD PRIORITY: MUST for SD-0/1/7/8, SHOULD for rest`

**Context:** These aren't a separate agent — they're checks wrapped around the agents you already built. Wire them in now that Tickets 1–11 exist.

**Task:**
1. **SD-0/SD-1** (already mostly in A1 from Ticket 8) — confirm regex + trust scoring runs before anything touches A2.
2. **SD-2** (Dual-LLM sandbox) — for the 30-day build, simulate with a single LLM call that runs twice with different system prompts (processor + verifier), not two separate models. Document this as the scope cut.
3. **SD-3** (resource guardian) — wrap every LLM/external-API call (A6, A7, A8, A10) in a hard timeout + max-token limit + simple circuit breaker (if 3 consecutive timeouts, disable that call path and alert).
4. **SD-4** (poisoning/worm defense) — add a basic write-authorization check: only A12 can write to the audit table; only A2 can create new Evidence Objects; enforce this in code, not just convention.
5. **SD-5** (output judge) — before any agent output leaves the pipeline (goes to UI or external API), run a secrets/PII scanner over it:
   ```python
   # SD-5: Output Judge — Secrets/PII Scanner
   PATTERNS = {
       "api_key": r'[A-Za-z0-9_\-]{32,64}',
       "aws_key": r'AKIA[0-9A-Z]{16}',
       "pii_phone": r'\d{10}',
       "pii_email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
       "credential_password": r'password\s*[:=]\s*\S+',
   }

   def scan_output(output_text: str) -> dict:
       findings = {}
       for name, pattern in PATTERNS.items():
           if re.search(pattern, output_text, re.IGNORECASE):
               findings[name] = True
       return {"blocked": len(findings) > 0, "findings": findings}
   ```
   Wire `scan_output()` in as a hard gate — any UI/external-facing agent response calls it first; if `blocked: True`, the response is withheld and logged.
6. **SD-7** (forensics) — confirm every rejection (from SD-0 through SD-6) also gets logged to the A12 audit chain, not just successful actions.
7. **SD-8** (Kill Switch) — build this exactly, not just conceptually. It's the single most judge-tested feature, so make it a real, working endpoint with a real global flag check in every autonomous action:
   ```python
   AUTONOMY_FROZEN = False
   MAX_AUTONOMY_SECONDS = 300  # 5-minute max-autonomy timer

   @app.post("/emergency-stop")
   async def emergency_stop():
       global AUTONOMY_FROZEN
       AUTONOMY_FROZEN = True
       log_event("KILL_SWITCH_ACTIVATED", source="dashboard")
       return {"status": "EMERGENCY_STOP_ACTIVE", "timestamp": datetime.now().isoformat()}

   @app.post("/emergency-stop/release")
   async def release_emergency_stop(approver: str):
       # Requires an explicit approver — logs who released it, for the audit chain
       global AUTONOMY_FROZEN
       AUTONOMY_FROZEN = False
       log_event("KILL_SWITCH_RELEASED", source=approver)
       return {"status": "EMERGENCY_STOP_RELEASED"}

   # Every autonomous action (A7, A10, A13) must call through this guard first:
   async def execute_action(action):
       if AUTONOMY_FROZEN:
           raise KillSwitchException("Autonomous actions frozen by emergency stop")
       # ... proceed with the real action
   ```
   Wire the 300-second max-autonomy timer as a background task: if the flag has been `True` for over `MAX_AUTONOMY_SECONDS` without a `/release` call, it simply stays frozen — fail-safe by construction, don't add any auto-release-on-timeout logic (that would be fail-open, which defeats the point).

**Definition of Done:** Hitting `/emergency-stop` stops A7/A10/A13 from executing any further autonomous action immediately (verify with a test that calls `execute_action` right after and expects `KillSwitchException`), and this is logged to the audit chain. A crafted injection payload is blocked before A2 and the block is audited. `scan_output()` blocks at least one crafted secret-leak test case.

---

<a id="ticket-13"></a>
## 🎫 TICKET 13 — Simulated Agents: A5 (GNN), A8 (Critic), A9 (Dual-LLM Quarantine) · `BUILD PRIORITY: SIMULATE`

**Context:** These are honestly scoped as "simulate with visuals" for the 30-day build — don't over-engineer them, but make the simulation good enough to demo and defend under questioning.

**Task:**
1. **A5 (GNN):** Build a small seeded graph (25–40 nodes) in NetworkX/PyTorch Geometric representing a scripted attack path (e.g. entry point → lateral move → crown jewel). Train a small **real GAT** on this seeded graph so attention weights genuinely light up the path (a real small GAT is more defensible than a hardcoded animation). Render with Cytoscape.js in the UI.
1a. **Predictive Attack Topology — 1-hop lookahead (Feature #6).** Given the compromised node the attacker currently occupies, use the Infrastructure Graph (DS3) plus the GAT's attention weights to rank the most likely next hop(s):
   ```python
   def predict_next_hop(current_node: str, graph, gat_attention_weights: dict, top_k: int = 2) -> list:
       neighbors = graph.neighbors(current_node)
       # Score each neighbor by a mix of graph reachability and GAT attention on the edge
       scored = [
           (n, gat_attention_weights.get((current_node, n), 0.0) * graph[current_node][n].get("criticality_weight", 1.0))
           for n in neighbors
       ]
       scored.sort(key=lambda x: x[1], reverse=True)
       return scored[:top_k]  # e.g. [("DB-01", 0.81), ("Auth-01", 0.44)]
   ```
   Feed the result into the Hypothesis Object's `predicted_next_moves` (already in the schema from Ticket 1) and render it in the UI (Ticket 14) as a dashed edge from the current node to the predicted next hop, with predicted-but-not-yet-observed nodes visually distinct (e.g. greyed out / dashed) from confirmed compromised nodes.
2. **A8 (Critic):** Implement as a real second LLM call (same Llama instance, different system prompt): *"You are a skeptical security analyst. Given this hypothesis and evidence, find counter-evidence: is the source IP whitelisted? Is this a known scanner? Could this be a red-team exercise? Rate how likely this is a false positive."* This can be fully real, not just simulated — it's cheap to implement for real.
3. **A9 (Dual-LLM Quarantine):** For the demo, show a diagram (not live code) of how untrusted input would be processed by an isolated LLM instance and independently verified by a second — label clearly as "described, not live-coded" in the pitch.

**Definition of Done:** A5 shows real attention weights highlighting a real attack path on a real (if small) graph. `predict_next_hop()` returns a ranked list of plausible next nodes for at least one seeded scenario, and it's visually distinguishable in the UI from confirmed compromise. A8 is live and returns genuine counter-evidence reasoning. A9 has a clear one-slide diagram ready.

---

<a id="ticket-135"></a>
## 🆕 🎫 TICKET 13.5 — Digital Twin Lite (Attack Simulation) · `BUILD PRIORITY: MUST`

> **Why this ticket exists:** PS #7 explicitly lists **"Cyber Resilience Digital Twin"** as one of the 5 original build options merged into KAVACH, and it's Feature #5 in the 15-feature list. Without a dedicated ticket, this was fully absent from the build plan — a judge asking *"what did you build for the Digital Twin?"* would have had no real answer beyond "the sun graph." This closes that gap directly, and it reuses the same seeded graph as Ticket 13, so it's a high-ROI, low-extra-effort addition.

**Context:** The Digital Twin is a virtual clone of the infrastructure — network topology, software versions, user roles, data flows — that exists purely for simulation and red-team testing. For the hackathon, this is a lightweight version: a seeded NetworkX graph plus a "Simulate Attack" button that shows KAVACH detecting a scripted APT campaign as it propagates.

**Task:**

1. Build `agents/digital_twin.py` (or `stores/digital_twin.py`) reusing the same graph as Ticket 13's A5:

   ```python
   # agents/digital_twin.py

   import networkx as nx
   from typing import List

   class DigitalTwin:
       """
       Lightweight simulation of the CBSE infrastructure.
       For demo purposes only — not a live topology discovery.
       """
       def __init__(self):
           self.graph = self._build_seeded_graph()
           self.attack_path = self._seed_attack_path()
           self.compromised_nodes: List[str] = []

       def _build_seeded_graph(self) -> nx.Graph:
           """25-40 node graph: WebSvr → AppSrv → DB → CrownJewel"""
           G = nx.Graph()
           # Add nodes with attributes: type, criticality, ip, software
           G.add_node("WebSvr-01", type="web_server", criticality="HIGH", ip="203.94.1.10")
           G.add_node("AppSrv-03", type="app_server", criticality="HIGH", ip="10.0.1.20")
           G.add_node("DB-01", type="database", criticality="CRITICAL", ip="10.0.1.30")
           G.add_node("CrownJewel-ExamDB", type="crown_jewel", criticality="CRITICAL", ip="10.0.1.40")
           # Add edges with relationship: trust, authentication, network
           G.add_edge("WebSvr-01", "AppSrv-03", relationship="http", weight=0.9)
           G.add_edge("AppSrv-03", "DB-01", relationship="sql", weight=0.8)
           G.add_edge("DB-01", "CrownJewel-ExamDB", relationship="replication", weight=1.0)
           return G

       def simulate_attack(self, start_node: str = "WebSvr-01") -> List[str]:
           """Simulate APT progression through the graph."""
           path = [start_node]
           current = start_node
           while current != "CrownJewel-ExamDB":
               # Follow the highest-weight edge
               neighbors = list(self.graph.neighbors(current))
               if not neighbors:
                   break
               next_node = max(neighbors, key=lambda n: self.graph[current][n].get("weight", 0))
               path.append(next_node)
               current = next_node
           return path  # ["WebSvr-01", "AppSrv-03", "DB-01", "CrownJewel-ExamDB"]

       def render_path(self, path: List[str]) -> dict:
           """Return node colors for UI: green/clean → orange/suspicious → red/compromised"""
           return {node: "red" if node in path else "green" for node in self.graph.nodes}
   ```

2. Feed the Digital Twin's simulated attack Evidence through the **real** pipeline (A2 → A3 → A4 → ... → A7) so KAVACH's actual detection logic — not a scripted animation — is what flags each hop. This is what makes the demo defensible: judges see real hypothesis generation reacting to the simulated attack, not a canned video.

3. **Add to Dashboard (Ticket 14):**
   - A **"Digital Twin"** tab or panel, clearly labeled *"Simulation — for red-team testing"*.
   - A **"Simulate Attack"** button that calls `simulate_attack()`.
   - A graph visualization with color-coded nodes (green → orange/suspicious → red/compromised), reusing the Cytoscape.js renderer from Ticket 13/14.
   - A small timeline strip showing KAVACH's detection firing at each hop (WebSvr detected at T+2s, AppSrv at T+9s, etc.).

**Definition of Done:** Clicking "Simulate Attack" animates an attack path through the graph in the correct order (WebSvr → AppSrv → DB → CrownJewel), each hop is independently detected by the real pipeline (not hardcoded), and the UI clearly labels this as simulation.

---

<a id="ticket-14"></a>
## 🎫 TICKET 14 — UI Layer: Dashboard, Timeline, Kill Switch, RBAC

**Context:** This is Person C's track — ties everything above into something judges can see and interact with.

**Task:**
Build a React (or Flask + HTMX if the team is more comfortable) dashboard with:
1. **Explainable timeline** — scrubbable, T-0 to T+43s, each event clickable to show the underlying Evidence/Hypothesis.
2. **Predictive attack topology** — Cytoscape.js graph showing compromised → predicted paths, blocked paths marked. (Shared component with the Digital Twin tab from Ticket 13.5.)
3. **Human Gate panel** — shows pending Decision Objects awaiting HUMAN_GATE, with CONFIRM / REVOKE / MODIFY / ESCALATE buttons that call the A12 correction endpoint (Ticket 7).
4. **Kill Switch button** — big, obvious, calls the SD-8 `/emergency-stop` endpoint (Ticket 12), shows "EMERGENCY STOP – ACTIVE" status.
5. **Role-based views (RBAC):** SOC Analyst (hypotheses+actions), Reviewer (corrections+policy), CISO (exec dashboard+compliance), SysAdmin (agent health+kill switch). Simple role flag is fine — full auth system is out of scope.
6. **CERT-In compliance — a real report template, not just a countdown widget.** Build the actual auto-drafted report so judges can see the artifact, not just a clock. Generate a report (Markdown or PDF) with these fields, populated from the Decision/Hypothesis/Audit objects:
   - Incident ID, detection timestamp, affected asset(s) and criticality
   - IOCs (IP, hash, domain) and MITRE TTPs involved
   - Timeline of detection → investigation → decision → containment (reuse the explainable timeline data)
   - Actions taken (autonomous + human-gated), whether reversed
   - 6-hour countdown status (time remaining / deadline met or missed)
   - DPDP (Digital Personal Data Protection Act) notification field — even if just a placeholder line, include it explicitly since it's a named compliance feature
   Auto-generate this on Hypothesis confirmation; show a "Draft CERT-In Report" button in the UI that renders it.
7. **Chatbot widget:** simple text box wired to A6's LLM for "explain this hypothesis" / "what if" queries.
8. **Digital Twin tab** (Ticket 13.5) — "Simulate Attack" button and color-coded attack-path graph, clearly labeled as simulation.

**Definition of Done:** A full incident (from CSV ingestion through to Decision) is visible end-to-end in the UI, the Kill Switch works live, the Digital Twin tab runs a full simulated attack live, and at least 2 of the 4 RBAC views are distinguishable.

---

<a id="ticket-15"></a>
## 🎫 TICKET 15 — Benchmarking & Evaluation

**Context:** Week 4 — you need real, honestly-reported numbers.

**Task:**
1. Download CICIDS 2017, hold out a test split.
2. Write `benchmark/benchmark.py --dataset CICIDS2017 --mode full` that runs the full pipeline (Tickets 2–7) over the held-out set and records: Precision, Recall, F1, MTTD, MTTR, MITRE-attribution accuracy (against your seeded scenarios), automation coverage.
3. Write `benchmark/report.py` that outputs `benchmark_results.json` and a simple markdown/HTML summary table.
4. Compare against pass bars: Recall ≥ 0.70, FPR ≤ 0.10, MTTD ≤ 60s, MTTR ≤ 90s, MITRE accuracy ≥ 80%, Automation coverage ≥ 75%. Where you miss a bar, write one honest sentence explaining the gap and the roadmap fix — don't hide it.

**Definition of Done:** `benchmark_results.json` exists with real numbers from a real run, and there's a one-paragraph honest write-up of any missed targets.

---

<a id="ticket-16"></a>
## 🎫 TICKET 16 — Business Impact & Cost Case (for Pitch Deck) · `BUILD PRIORITY: MUST`

> ⭐ **Business Impact is 25% of judging weight for PS #7** — don't leave this to the last night.

**Task:**
Create `docs/business_impact.md` with:
1. **Cost of status quo:** AIIMS Delhi ransomware (2-week downtime) ₹50–100 crore; CBSE data breach (2024) ₹20–50 crore; average ransomware recovery ₹10–20 crore (IBM Cost of a Data Breach Report 2024); CERT-In's 1.59M incidents/year — systemic cost ₹10,000+ crore/year across government entities.
2. **Cost of KAVACH:** ~₹50 lakh/year total — compute (3-node Kubernetes + GPU) ₹8–10 lakh, storage (8 data stores, 90-day retention) ₹5–7 lakh, maintenance (3-person SOC augmentation) ₹30–40 lakh.
3. **ROI calculation:** `(10,000 − 0.5) / 0.5 × 100 ≈ 20,000x` return. One prevented AIIMS-style outage pays for KAVACH for 100+ years.
4. **CERT-In compliance value:** the 6-hour breach-reporting SLA that almost no government entity currently meets — frame KAVACH's auto-drafted report (Ticket 14) as directly closing this gap.
5. **One paragraph for the pitch deck**, verbatim-ready:
   > "A single AIIMS-style ransomware outage costs ₹100 crore. KAVACH costs ₹50 lakh per year. The ROI is 20,000x. We're not asking for budget — we're asking to stop bleeding money."

**Definition of Done:** `docs/business_impact.md` exists with all numbers and sources cited, and the pitch paragraph is ready to paste into slides.

---

<a id="ticket-17"></a>
## 🎫 TICKET 17 — 5-Minute Demo Script · `BUILD PRIORITY: MUST`

**Context:** A rehearsed, timed demo sequence. No architecture slides during the demo itself — everything shown should be live (or the pre-recorded backup of the same live sequence).

**Task:**
Create `docs/demo_script.md` with this exact timed sequence:

| Time | Beat | What to Show |
|------|------|----------------|
| 0:00–0:30 | The Problem | "This is CBSE Web Server. In 2026, attackers hit it. We're showing how KAVACH stops the same attack in 43 seconds." |
| 0:30–1:00 | The Attack | Inject a Log4Shell payload into the dashboard; show the log appearing |
| 1:00–1:30 | Fast Path | SHA-256 exact match → <2ms → "KNOWN MALICIOUS" verdict appears instantly |
| 1:30–2:00 | Novel Variant | Change port 443→8443; SHA-256 misses → FAISS finds 92% similarity (~16ms) → "SIMILAR – ACCELERATED" |
| 2:00–2:45 | Full Investigation | Novel attack (no match) → Active Hunt → VirusTotal result → Hypothesis (H1=APT 91%, H2=Admin 6%) → Critic challenges → Risk=0.826, Blast=0.73 → Human Gate triggered |
| 2:45–3:30 | Explainable Timeline | Scrubbable T-0 → DNS → PowerShell → Lateral Move → Hypothesis → Decision, each event clickable |
| 3:30–4:00 | Human-in-the-Loop | Human Gate panel "ISOLATE_HOST?" → APPROVE → Decision Object created, audit log updated |
| 4:00–4:30 | Kill Switch | "If the AI goes rogue, we hit this." Click → all autonomous actions freeze instantly → "EMERGENCY STOP – ACTIVE" |
| 4:30–5:00 | The Close | "43 seconds from detection to containment. That's the difference between weeks of downtime and a contained incident." |

*Optional stretch beat, if time allows before 4:00:* a quick 15-second cut to the **Digital Twin tab** (Ticket 13.5) — "Simulate Attack" button, path animates, KAVACH flags it in the twin before it reaches the crown jewel. Cut if running long; the core 9-beat script above is the priority.

Also record a **pre-recorded backup video** of this exact sequence (unlisted link) in case the live demo fails — the team clicks through it while narrating over it.

**Definition of Done:** `docs/demo_script.md` exists, the backup video is recorded, and the team has rehearsed the live version at least twice against the real running system (not mocked screens).

---

<a id="ticket-18"></a>
## 🎫 TICKET 18 — Judge Q&A Playbook · `BUILD PRIORITY: MUST`

**Context:** Every well-prepared team has rehearsed answers to the hardest, most predictable questions.

**Task:**
Create `docs/qa_playbook.md` with these answers, ready to say without notes:

| If asked… | Say… |
|-----------|------|
| "How is KAVACH different from a SIEM?" | "A SIEM processes alerts. KAVACH investigates hypotheses — it hunts, generates competing explanations, challenges itself with a Skeptic Agent, predicts next moves, and learns permanently." |
| "What's your actual novel contribution?" | "Context-Aware Decision Fingerprinting — every observation becomes a layered fingerprint (content → behavior → decision), matched against human-verified memory before any model inference runs, and every new decision becomes permanent, correctable memory." |
| "Is this GNN real or simulated?" | "Real — GAT only, on a 25–40 node seeded graph with a scripted attack path. Attention weights actually drive what highlights on screen." |
| "Why only 1 LLM instead of 5?" | "Production would use 5 separate fine-tuned instances to avoid self-bias. For a 30-day build, prompt-level separation gets the same separation-of-concerns story without 40GB of VRAM." |
| "Is the federation real?" | "No — explicitly simulated. A second local process exchanges a genome match and verdict. The production answer is the STIX/TAXII design already in our architecture doc." |
| "Does this system retrain itself?" | "Vault updates from human corrections change future fingerprint lookups immediately. The underlying ML models (Isolation Forest, GAT) don't retrain live in this build — that's the EWC/RLHF stack documented as roadmap." |
| "Is this connected to CERT-In?" | "No — it's an export mapping from our audit log to CERT-In's 6-hour breach-reporting field format. It demonstrates compliance-readiness, not a live regulatory integration." |
| "How do you handle OT/SCADA?" | "OT Context Builder tags protocol, device_type, safety_criticality, can_interrupt, can_reboot. If can_reboot=false, the Human Gate is forced regardless of confidence. We never hard-stop a live process." |
| **🆕 "What did you build for the Digital Twin?"** | **"A lightweight NetworkX twin of the CBSE infrastructure — WebSvr → AppSrv → DB → CrownJewel — with a live 'Simulate Attack' button. The simulated traffic runs through our real detection pipeline, not a scripted animation, so you're watching KAVACH actually detect the attack at each hop inside the twin, before it reaches the crown jewel."** |

**Definition of Done:** All 9 answers exist in `docs/qa_playbook.md`, and every team member can deliver each one from memory, without reading.

---

## 🗺️ Build Order Summary

```
Ticket 0    → Repo skeleton
Ticket 1    → Evidence / Hypothesis / Decision objects (everything else depends on this)
Ticket 2    → A2 Normalizer               ┐
Ticket 3    → A3 Hash/Fingerprint router  │  THE SPINE — build in this exact order,
Ticket 4    → A4 Anomaly Detector         │  Person A owns this, nothing else works without it
Ticket 6    → A7 SOAR & Decision          │
Ticket 7    → A12 Audit & Memory          ┘
Ticket 5    → A6 Attribution & RAG        ┐  MUSCLES — Person B, can start once
Ticket 8    → A1 Ingestion & Trust        │  the spine produces real Evidence Objects
Ticket 9    → A10 Active Hunt             │
Ticket 10   → A11 Watchdog                │
Ticket 11   → A13 Federation              ┘
Ticket 12   → Self-Defense wiring (SD-0..8) — wire in once agents exist
Ticket 13   → A5/A8/A9 simulated agents   — Person B, can run in parallel with Ticket 12
Ticket 13.5 → 🆕 Digital Twin Lite         — Person B, reuses Ticket 13's graph, build right after
Ticket 14   → UI layer                     — Person C, starts skeleton in parallel with Muscles
Ticket 15   → Benchmarking                 — Week 4, once the spine + muscles are stable
Ticket 16   → Business Impact / Cost Case ┐  JUDGING PREP — Week 4, don't leave these to the
Ticket 17   → Demo Script + backup video  │  last night. 25%+ of your score depends on these
Ticket 18   → Judge Q&A Playbook          ┘  three, not on any additional code.
```

---

## ✅ Pre-Submission Checklist

| Category | Item | Done? |
|---|---|:---:|
| Core Objects | Evidence / Hypothesis / Decision schemas + confidence decay | ☐ |
| Spine | A2 → A3 → A4 → A7 → A12 running end-to-end on real CSV data | ☐ |
| Muscles | A6 RAG, A1 ingest, A10 hunt, A11 watchdog, A13 federation | ☐ |
| Self-Defense | SD-0 through SD-8, kill switch live and audited | ☐ |
| Simulated | A5 GAT (real, small), A8 Critic (real), A9 diagram ready | ☐ |
| **Digital Twin** | **Ticket 13.5 — "Simulate Attack" wired to real pipeline** | ☐ |
| UI | Timeline, topology graph, Human Gate, Kill Switch, RBAC, CERT-In report, chatbot, Digital Twin tab | ☐ |
| Benchmarks | Real numbers from a real CICIDS 2017 run, honest gap write-up | ☐ |
| Judging Prep | Business impact doc + pitch paragraph | ☐ |
| Judging Prep | Demo script rehearsed twice + backup video recorded | ☐ |
| Judging Prep | Q&A playbook — all 9 answers memorized by every team member | ☐ |

---

<div align="center">

### 🏆 Final One-Line Pitch

*"KAVACH is to traditional SIEM what an AI detective is to a log viewer — it doesn't process events, it investigates hypotheses. It hunts actively, generates competing Bayesian explanations, challenges itself with a Skeptic Agent, predicts attacker moves before execution, simulates attacks in a live Digital Twin, shares intelligence via federation, respects mission-aware world models, and maintains a cryptographic kill-switch — compressing detection-to-response from weeks to minutes while satisfying all 66 Red Team attacks."*

**66/66 Red Team attacks solved · 15/15 features mapped · 10/10 with Digital Twin included**

</div>

---

**Gap-fill note:** this version folds in every previously-implied-or-missing detail — confidence decay (Ticket 1), OT Context Builder + Indian Context (Ticket 2), Cross-Attention Fusion (Ticket 4), sequence-embedding Campaign Genome (Ticket 5), Counter-Evidence Collection (Ticket 6), Trust-Weighted Feedback + consensus + Shadow Deployment Promotion Check (Ticket 7), Federation PII anonymization (Ticket 11), an explicit Kill Switch endpoint + SD-5 secrets scanner (Ticket 12), 1-hop Predictive Attack Topology (Ticket 13), the **Digital Twin Lite (new Ticket 13.5)**, a real CERT-In report template (Ticket 14), plus Tickets 16–18 for judging prep.
