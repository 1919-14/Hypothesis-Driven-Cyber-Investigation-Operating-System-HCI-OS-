"""
agents/a6_attribution.py
A6: Attribution & RAG Agent (Layer 6, LLM-1) -- HCI-OS

RAG over MITRE ATT&CK + NVD CVE + CERT-In advisories.
Campaign Genome: sequence embedding + cosine similarity.
LLM: Llama 3.x 8B via Ollama (fallback to mock if unavailable).
Trust weights: CERT-In=0.95, MITRE=0.90, NVD=0.85
"""

import hashlib
import json
import logging
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from objects.evidence import Evidence
from objects.hypothesis import Hypothesis, PredictedMove

logger = logging.getLogger("A6_Attribution")
logging.basicConfig(level=logging.INFO)

_DATA = Path(__file__).parent.parent / "data"
TRUST = {"CERT-In": 0.95, "MITRE": 0.90, "NVD": 0.85}
W_ATTRIBUTION, W_GENOME = 0.6, 0.4
GENOME_THRESHOLD = 0.70
GENOME_DIM = 64
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 10

# ── RAG Index ─────────────────────────────────────────────────────────────────

def _load_docs() -> List[Dict[str, Any]]:
    docs = []
    for fname, source in [
        ("mitre_stix.json", "MITRE"),
        ("nvd_cves.json", "NVD"),
        ("cert_in_advisories.json", "CERT-In"),
    ]:
        try:
            with open(_DATA / fname, encoding="utf-8") as f:
                items = json.load(f)
            for item in items:
                item.setdefault("source", source)
                item.setdefault("trust_weight", TRUST[source])
                parts = [
                    item.get("name", ""), item.get("title", ""),
                    item.get("description", ""),
                    " ".join(item.get("ttp_chain", [])),
                    item.get("india_context", ""),
                ]
                item["_text"] = " ".join(p for p in parts if p)
                docs.append(item)
        except FileNotFoundError:
            logger.warning("A6: %s not found", fname)
    return docs


def _hash_embed(texts: List[str], dim: int = 384) -> "np.ndarray":
    vecs = np.zeros((len(texts), dim), dtype=np.float32)
    for i, text in enumerate(texts):
        for j, ch in enumerate(text[:dim]):
            vecs[i, j % dim] += ord(ch) / 128.0
        n = np.linalg.norm(vecs[i])
        if n > 0:
            vecs[i] /= n
    return vecs


def build_rag_index(force: bool = False):
    import faiss
    idx_path = str(_DATA / "rag_index.faiss")
    meta_path = str(_DATA / "rag_metadata.json")

    if not force and Path(idx_path).exists():
        try:
            index = faiss.read_index(idx_path)
            with open(meta_path, encoding="utf-8") as f:
                meta = json.load(f)
            logger.info("A6: Loaded RAG index (%d vectors)", index.ntotal)
            return index, meta
        except Exception as e:
            logger.warning("A6: Load failed (%s) — rebuilding", e)

    docs = _load_docs()
    if not docs:
        return faiss.IndexFlatIP(384), []

    texts = [d["_text"] for d in docs]
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        vecs = model.encode(texts, normalize_embeddings=True).astype(np.float32)
    except Exception as e:
        logger.warning("A6: SentenceTransformer failed (%s) — hash fallback", e)
        vecs = _hash_embed(texts, 384)

    index = faiss.IndexFlatIP(vecs.shape[1])
    index.add(vecs)
    _DATA.mkdir(exist_ok=True)
    faiss.write_index(index, idx_path)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(docs, f, default=str)
    logger.info("A6: Built RAG index (%d vectors)", index.ntotal)
    return index, docs


def retrieve(evidence: Evidence, index, metadata: List[Dict], k: int = 5):
    if index is None or index.ntotal == 0:
        return []
    n = evidence.normalized
    ctx = evidence.context
    query = (
        f"Attack {n.get('method','')} to {n.get('path','')} "
        f"from {n.get('src_ip','')} targeting {ctx.get('mission','')} "
        f"criticality {ctx.get('criticality','')} "
        f"OT {ctx.get('ot_context',{}).get('protocol','')}"
    )
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        qv = model.encode([query], normalize_embeddings=True).astype(np.float32)
    except Exception:
        qv = _hash_embed([query], index.d)

    D, I = index.search(qv, min(k, index.ntotal))
    results = []
    for idx, sim in zip(I[0], D[0]):
        if idx >= 0:
            doc = dict(metadata[idx])
            doc["similarity_score"] = float(sim)
            results.append(doc)
    return results


# ── Trust-Weighted Conflict Resolution ────────────────────────────────────────

def resolve_attribution(docs: List[Dict], llm_group: str, llm_conf: float) -> Dict:
    scores: Dict[str, float] = {}
    for doc in docs:
        g = doc.get("attribution")
        if not g or g == "Unknown":
            continue
        w = doc.get("trust_weight", 0.85) * doc.get("similarity_score", 0.5)
        scores[g] = scores.get(g, 0.0) + w
    if llm_group and llm_group != "Unknown":
        scores[llm_group] = scores.get(llm_group, 0.0) + 0.80 * llm_conf

    if not scores:
        return {"primary": {"group": llm_group or "Unknown", "confidence": llm_conf}, "secondary": None}

    total = sum(scores.values())
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    norm = [(g, round(s / total, 3)) for g, s in ranked]
    return {
        "primary": {"group": norm[0][0], "confidence": norm[0][1]},
        "secondary": {"group": norm[1][0], "confidence": norm[1][1]} if len(norm) > 1 else None,
    }


# ── Campaign Genome ────────────────────────────────────────────────────────────

def _get_ttp_pos_vec(ttp: str, pos: int, dim: int = GENOME_DIM) -> np.ndarray:
    key = f"{ttp}_pos_{pos}"
    h = hashlib.sha256(key.encode()).digest()
    state = np.random.RandomState(int.from_bytes(h[:4], "big"))
    vec = state.normal(0, 1, dim).astype(np.float32)
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def _seq_embed(chain: List[str], dim: int = GENOME_DIM) -> np.ndarray:
    if not chain:
        return np.zeros(dim, dtype=np.float32)
    vec = np.zeros(dim, dtype=np.float32)
    for pos, ttp in enumerate(chain):
        pw = 1.0 / (1.0 + pos)
        vec += pw * _get_ttp_pos_vec(ttp, pos, dim)
    n = np.linalg.norm(vec)
    return (vec / n).astype(np.float32) if n > 0 else vec


def match_campaign_genome(chain: List[str], campaigns: Dict, threshold: Optional[float] = None) -> Optional[Dict]:
    if not chain or not campaigns:
        return None
    thresh = threshold if threshold is not None else GENOME_THRESHOLD
    obs = _seq_embed(chain)
    best_sim, best_name = -1.0, None
    for name, data in campaigns.items():
        sim = float(np.dot(obs, _seq_embed(data.get("ttp_sequence", []))))
        if sim > best_sim:
            best_sim, best_name = sim, name

    if best_sim < thresh:
        return None

    camp_seq = campaigns[best_name]["ttp_sequence"]
    predicted = None
    prevent = None
    if len(chain) < len(camp_seq):
        for i, t in enumerate(camp_seq):
            if chain[-1] == t and i + 1 < len(camp_seq):
                predicted = camp_seq[i + 1]
                prevent = campaigns[best_name].get("preventive_actions", {}).get(predicted)
                break
        if not predicted:
            predicted = camp_seq[len(chain)]
            prevent = campaigns[best_name].get("preventive_actions", {}).get(predicted)

    return {
        "matched_campaign": best_name,
        "confidence": round(best_sim, 4),
        "predicted_next": predicted,
        "preventive_action": prevent,
    }


# ── LLM Call + Fallback ───────────────────────────────────────────────────────

_MOCKS = {
    "exam_portal": {"mitre_chain": ["T1595", "T1190", "T1059", "T1003"], "confidence": 0.85,
                    "reasoning": "APT41 pattern vs CBSE (CIAD-2026-0041)", "attribution_group": "APT41"},
    "power_management": {"mitre_chain": ["T1566", "T1078", "T1021", "T1486", "T1489"], "confidence": 0.80,
                         "reasoning": "OT ransomware pattern (CIAD-2024-0034)", "attribution_group": "RansomwareGroup"},
    "default": {"mitre_chain": ["T1595", "T1190", "T1059"], "confidence": 0.65,
                "reasoning": "Generic exploit pattern", "attribution_group": "Unknown"},
}


def _call_llm(evidence: Evidence, docs: List[Dict]) -> Dict:
    snippets = [
        f"[{d.get('source')} trust={d.get('trust_weight',0.85):.2f}] "
        f"{d.get('name', d.get('title',''))}: {d.get('description','')[:180]}"
        for d in docs[:4]
    ]
    ev_summary = json.dumps({
        "asset_id": evidence.asset_id, "source": evidence.source,
        "normalized": dict(list(evidence.normalized.items())[:6]),
        "criticality": evidence.context.get("criticality"),
        "mission": evidence.context.get("mission"),
        "indian_context": evidence.context.get("indian_context", {}),
    }, indent=2)

    sys_p = ("You are a threat attribution analyst for India's critical infrastructure. "
             "Output ONLY valid JSON with keys: mitre_chain (list), confidence (float 0-1), "
             "reasoning (string), attribution_group (string).")
    usr_p = f"Evidence:\n{ev_summary}\n\nThreat Intel:\n" + "\n".join(snippets)

    try:
        import urllib.request
        payload = json.dumps({
            "model": "llama3",
            "prompt": f"<|system|>{sys_p}<|user|>{usr_p}<|assistant|>",
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 512},
        }).encode()
        req = urllib.request.Request(OLLAMA_URL, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as r:
            raw = json.loads(r.read()).get("response", "")
        s, e = raw.find("{"), raw.rfind("}") + 1
        if s >= 0 and e > s:
            parsed = json.loads(raw[s:e])
            if "mitre_chain" in parsed and "confidence" in parsed:
                return parsed
    except Exception as exc:
        logger.warning("A6: LLM call failed (%s) — mock fallback", exc)

    mission = evidence.context.get("mission", "")
    for key, mock in _MOCKS.items():
        if key in mission:
            return dict(mock)
    return dict(_MOCKS["default"])


# ── Module cache ──────────────────────────────────────────────────────────────
_rag_index = None
_rag_meta: List[Dict] = []
_campaigns: Dict[str, Dict] = {}


def _ensure_loaded():
    global _rag_index, _rag_meta, _campaigns
    if _rag_index is None:
        _rag_index, _rag_meta = build_rag_index()
    if not _campaigns:
        try:
            with open(_DATA / "known_campaigns.json", encoding="utf-8") as f:
                _campaigns = json.load(f)
        except FileNotFoundError:
            logger.warning("A6: known_campaigns.json missing")


# ── Main Entry Point ──────────────────────────────────────────────────────────

def process(evidence: Evidence, hypothesis: Hypothesis) -> Hypothesis:
    """
    Route anomalous Evidence through A6 and update the Hypothesis.

    Steps:
      1. Link evidence_id to hypothesis.supporting_evidence
      2. RAG retrieval (MITRE + NVD + CERT-In)
      3. LLM attribution (with fallback)
      4. Trust-weighted conflict resolution
      5. Campaign Genome matching + next-move prediction
      6. Combine confidence (0.6 × attribution + 0.4 × genome)
      7. Write back to Hypothesis fields
    """
    start = time.perf_counter()
    _ensure_loaded()

    # 1. Evidence linking
    if evidence.evidence_id not in hypothesis.supporting_evidence:
        hypothesis.supporting_evidence.append(evidence.evidence_id)

    # 2. Retrieval
    docs = retrieve(evidence, _rag_index, _rag_meta, k=5)

    # 3. LLM
    llm = _call_llm(evidence, docs)
    mitre_chain: List[str] = llm.get("mitre_chain", [])
    attr_conf: float = float(llm.get("confidence", 0.5))
    attr_group: str = llm.get("attribution_group", "Unknown")

    # 4. Conflict resolution
    attribution = resolve_attribution(docs, attr_group, attr_conf)

    # 5. Campaign Genome
    genome = match_campaign_genome(mitre_chain, _campaigns)
    genome_conf = genome["confidence"] if genome else 0.0

    # 6. Predicted next moves
    moves: List[PredictedMove] = []
    if genome and genome.get("predicted_next"):
        moves.append(PredictedMove(
            ttp=genome["predicted_next"],
            confidence=round(genome_conf * 0.9, 3),
            preventive_action=genome.get("preventive_action"),
        ))

    # 7. Combine confidence
    combined = round(min(1.0, max(0.0, W_ATTRIBUTION * attr_conf + W_GENOME * genome_conf)), 3)

    # 8. Write to Hypothesis
    hypothesis.mitre_chain = mitre_chain
    hypothesis.predicted_next_moves = moves
    hypothesis.campaign_genome = {
        **(genome or {}),
        "attribution": attribution,
        "llm_reasoning": llm.get("reasoning", ""),
        "retrieved_sources": len(docs),
    }
    hypothesis.confidence = combined
    hypothesis.uncertainty = round(1.0 - combined, 3)
    hypothesis.last_updated = datetime.now()
    hypothesis.add_timeline_event(
        time_str=datetime.now(timezone.utc).strftime("%H:%M:%S"),
        event=f"A6: {attribution['primary']['group']} | chain={mitre_chain} | conf={combined:.2f}",
        event_type="attribution",
    )

    ms = (time.perf_counter() - start) * 1000
    logger.info("A6: %s | %s | chain=%s | conf=%.3f | %.1fms",
                evidence.evidence_id, attribution["primary"]["group"], mitre_chain, combined, ms)
    return hypothesis
