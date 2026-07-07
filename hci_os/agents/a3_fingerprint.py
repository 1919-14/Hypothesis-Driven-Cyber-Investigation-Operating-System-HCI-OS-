"""
agents/a3_fingerprint.py
A3: Hash & Fingerprint Agent + 3-Path Router (Layer 3) -- HCI-OS

The performance engine of HCI-OS. Routes every Evidence object down
one of three paths to avoid unnecessary AI inference:

    Path 1 (Exact):  SHA-256 fingerprint hits Redis cache   --> <2ms
    Path 2 (Fuzzy):  FAISS cosine >= threshold              --> ~16ms
    Path 3 (Novel):  No match, full investigation pipeline  --> <1min

Key Design:
    - Path 2 adjusts confidence downward (x0.95) to reflect fuzzy uncertainty
    - Path 2 checks criticality match -- if criticality differs, falls back to Path 3
    - All routing decisions are logged as structured JSON for the demo dashboard
    - If Redis or FAISS fail, A3 degrades gracefully to Path 3 (never blocks)

Pipeline position: A2 (Normalizer) --> [A3] --> A4 (Anomaly) or cached Decision
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from objects.evidence import Evidence
from objects.decision import Decision
from stores.redis_store import RedisStore
from stores.faiss_store import FAISSStore

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("A3_Router")

# ─── Configuration ───────────────────────────────────────────────────────────
DEFAULT_FUZZY_THRESHOLD: float = 0.85
DEFAULT_FUZZY_CONFIDENCE_FACTOR: float = 0.95  # Reduce cached confidence for fuzzy matches
DEFAULT_REDIS_TTL: int = 30 * 24 * 60 * 60     # 30 days in seconds


class RoutingResult:
    """
    Structured result from the 3-Path Router.

    Attributes:
        path:             1, 2, or 3
        evidence_id:      ID of the routed Evidence
        decision:         The Decision object (Path 1/2) or None (Path 3)
        similarity_score: Cosine similarity (Path 2) or 1.0 (Path 1) or 0.0 (Path 3)
        timing_ms:        Wall-clock time for the routing decision in milliseconds
        fingerprint:      SHA-256 content fingerprint of the Evidence
        metadata:         Extra info (e.g., cache_hit_type, criticality_match)
    """

    def __init__(
        self,
        path: int,
        evidence_id: str,
        decision: Optional[Decision],
        similarity_score: float,
        timing_ms: float,
        fingerprint: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.path = path
        self.evidence_id = evidence_id
        self.decision = decision
        self.similarity_score = similarity_score
        self.timing_ms = timing_ms
        self.fingerprint = fingerprint
        self.metadata = metadata or {}

    def to_log_dict(self) -> Dict[str, Any]:
        """Structured JSON-serializable log entry for dashboard/demo."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "agent": "A3_router",
            "path": self.path,
            "path_label": {1: "EXACT", 2: "FUZZY", 3: "NOVEL"}[self.path],
            "evidence_id": self.evidence_id,
            "fingerprint": self.fingerprint,
            "similarity_score": round(self.similarity_score, 4),
            "timing_ms": round(self.timing_ms, 3),
            "decision_id": self.decision.decision_id if self.decision else None,
            "decision_action": self.decision.action_taken if self.decision else None,
            "metadata": self.metadata,
        }


class A3Router:
    """
    The 3-Path Router -- core performance engine of HCI-OS.

    Usage:
        router = A3Router()
        result = router.route(evidence)

        if result.path in (1, 2):
            # Use result.decision -- fast path
        else:
            # Pass evidence to A4 for full investigation
    """

    def __init__(
        self,
        redis_store: Optional[RedisStore] = None,
        faiss_store: Optional[FAISSStore] = None,
        fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD,
        confidence_factor: float = DEFAULT_FUZZY_CONFIDENCE_FACTOR,
        a4_callback: Optional[Callable[[Evidence], Optional[Decision]]] = None,
    ):
        """
        Initialize the 3-Path Router.

        Args:
            redis_store: Redis cache instance. Created automatically if None.
            faiss_store: FAISS index instance. Created automatically if None.
            fuzzy_threshold: Cosine similarity threshold for Path 2 (default 0.85).
            confidence_factor: Multiplier applied to cached confidence on fuzzy match (default 0.95).
            a4_callback: Optional callback to A4 for Path 3 processing.
                         Signature: (Evidence) -> Optional[Decision].
        """
        self.fuzzy_threshold = fuzzy_threshold
        self.confidence_factor = confidence_factor
        self.a4_callback = a4_callback

        # Initialize stores (with graceful fallbacks)
        self.redis = redis_store or RedisStore(use_memory_fallback=True)
        self.faiss = faiss_store or FAISSStore(auto_load=True)

        # Routing log (kept in memory; can be flushed to DB or file)
        self._routing_log: List[Dict[str, Any]] = []

        logger.info(
            "A3Router: Initialized (fuzzy_threshold=%.2f, confidence_factor=%.2f, "
            "redis=%s, faiss_size=%d)",
            self.fuzzy_threshold,
            self.confidence_factor,
            "memory" if self.redis.is_memory_mode else "redis",
            self.faiss.size,
        )

    # ─── Path 1: Exact Match ──────────────────────────────────────────────────

    def _try_exact_match(self, evidence: Evidence) -> Optional[Decision]:
        """
        Path 1: Look up the SHA-256 content_fingerprint in Redis.
        Returns the cached Decision if found, None otherwise.
        """
        try:
            cached_json = self.redis.get(evidence.content_fingerprint)
            if cached_json is not None:
                return Decision.from_json(cached_json)
        except Exception as exc:
            logger.warning("A3: Path 1 Redis lookup failed: %s -- falling through", exc)
        return None

    # ─── Path 2: Fuzzy Match ──────────────────────────────────────────────────

    def _try_fuzzy_match(
        self, evidence: Evidence
    ) -> Tuple[Optional[Decision], float, Dict[str, Any]]:
        """
        Path 2: Search FAISS for a semantically similar behavior embedding.

        Returns:
            (Decision or None, similarity_score, metadata_dict)

        Logic:
            1. Search FAISS for top-1 nearest neighbor
            2. If similarity >= threshold AND criticality matches --> return cached Decision
               with confidence adjusted downward by confidence_factor
            3. If criticality mismatches --> fall back to Path 3 (safety first)
        """
        meta: Dict[str, Any] = {}

        try:
            if self.faiss.size == 0:
                return None, 0.0, {"reason": "faiss_empty"}

            results = self.faiss.search(
                evidence.behavior_embedding,
                k=1,
                threshold=self.fuzzy_threshold,
            )

            if not results:
                return None, 0.0, {"reason": "no_results"}

            top = results[0]
            sim_score = top["similarity"]
            meta["similarity"] = round(sim_score, 4)
            meta["matched_index"] = top["index"]
            meta["matched_evidence_id"] = top["metadata"].get("evidence_id", "unknown")

            if not top["above_threshold"]:
                meta["reason"] = f"below_threshold ({sim_score:.4f} < {self.fuzzy_threshold})"
                return None, sim_score, meta

            # Context-aware safety check: if criticality differs, fall back to Path 3
            matched_criticality = top["metadata"].get("criticality")
            current_criticality = evidence.context.get("criticality")

            if matched_criticality and current_criticality:
                if matched_criticality != current_criticality:
                    meta["reason"] = (
                        f"criticality_mismatch ({current_criticality} vs {matched_criticality})"
                    )
                    meta["criticality_match"] = False
                    return None, sim_score, meta
                meta["criticality_match"] = True

            # Retrieve the cached decision for the matched fingerprint
            matched_fingerprint = top["metadata"].get("fingerprint")
            if matched_fingerprint:
                cached_json = self.redis.get(matched_fingerprint)
                if cached_json:
                    decision = Decision.from_json(cached_json)
                    # Adjust confidence downward for fuzzy match
                    adjusted_risk = min(
                        decision.risk_score * self.confidence_factor, 1.0
                    )
                    # Create a copy with adjusted risk to reflect fuzzy uncertainty
                    adjusted = decision.model_copy(
                        update={
                            "risk_score": round(adjusted_risk, 4),
                        }
                    )
                    meta["confidence_adjusted"] = True
                    meta["original_risk"] = decision.risk_score
                    meta["adjusted_risk"] = adjusted.risk_score
                    return adjusted, sim_score, meta
                else:
                    meta["reason"] = "similar_embedding_found_but_no_cached_decision"

            return None, sim_score, meta

        except Exception as exc:
            logger.warning("A3: Path 2 FAISS search failed: %s -- falling through", exc)
            return None, 0.0, {"reason": f"faiss_error: {exc}"}

    # ─── Path 3: Novel ────────────────────────────────────────────────────────

    def _handle_novel(self, evidence: Evidence) -> Optional[Decision]:
        """
        Path 3: Pass to A4 for full investigation.
        If a4_callback is registered, invoke it. Otherwise return None
        (the caller is expected to forward to A4).
        """
        if self.a4_callback:
            try:
                return self.a4_callback(evidence)
            except Exception as exc:
                logger.error("A3: A4 callback failed: %s", exc)
        return None

    # ─── Main Router ──────────────────────────────────────────────────────────

    def route(self, evidence: Evidence) -> RoutingResult:
        """
        Route an Evidence object through the 3-Path Router.

        Args:
            evidence: A validated Evidence object from A2.

        Returns:
            RoutingResult with path, decision, timing, and metadata.
        """
        start = time.perf_counter()

        # ── Path 1: Exact match ──────────────────────────────────────────
        decision = self._try_exact_match(evidence)
        if decision is not None:
            elapsed = (time.perf_counter() - start) * 1000
            result = RoutingResult(
                path=1,
                evidence_id=evidence.evidence_id,
                decision=decision,
                similarity_score=1.0,
                timing_ms=elapsed,
                fingerprint=evidence.content_fingerprint,
                metadata={"cache_hit": "exact", "redis_mode": "memory" if self.redis.is_memory_mode else "redis"},
            )
            self._log_routing(result)
            return result

        # ── Path 2: Fuzzy match ──────────────────────────────────────────
        fuzzy_decision, sim_score, fuzzy_meta = self._try_fuzzy_match(evidence)
        if fuzzy_decision is not None:
            elapsed = (time.perf_counter() - start) * 1000
            result = RoutingResult(
                path=2,
                evidence_id=evidence.evidence_id,
                decision=fuzzy_decision,
                similarity_score=sim_score,
                timing_ms=elapsed,
                fingerprint=evidence.content_fingerprint,
                metadata={"cache_hit": "fuzzy", **fuzzy_meta},
            )
            self._log_routing(result)
            return result

        # ── Path 3: Novel ────────────────────────────────────────────────
        novel_decision = self._handle_novel(evidence)
        elapsed = (time.perf_counter() - start) * 1000
        result = RoutingResult(
            path=3,
            evidence_id=evidence.evidence_id,
            decision=novel_decision,
            similarity_score=sim_score if sim_score > 0 else 0.0,
            timing_ms=elapsed,
            fingerprint=evidence.content_fingerprint,
            metadata={"cache_hit": "none", **fuzzy_meta} if fuzzy_meta else {"cache_hit": "none"},
        )
        self._log_routing(result)
        return result

    # ─── Cache Management ─────────────────────────────────────────────────────

    def cache_decision(
        self,
        evidence: Evidence,
        decision: Decision,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Cache a Decision for future exact + fuzzy lookups.

        Called after A7 produces a final decision for a novel event.
        This is how the cache is populated — without this, Paths 1/2
        would never have data.

        Args:
            evidence: The Evidence object that was investigated.
            decision: The Decision produced by A7.
            ttl_seconds: Optional TTL override.
        """
        # Cache in Redis (Path 1 key)
        self.redis.set(
            evidence.content_fingerprint,
            decision.to_json(),
            ttl_seconds=ttl_seconds,
        )

        # Add embedding to FAISS (Path 2 key)
        self.faiss.add(
            [evidence.behavior_embedding],
            metadata=[{
                "evidence_id": evidence.evidence_id,
                "fingerprint": evidence.content_fingerprint,
                "criticality": evidence.context.get("criticality"),
                "asset_id": evidence.asset_id,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }],
        )

        logger.info(
            "A3: Cached decision %s for fingerprint %s (FAISS index size: %d)",
            decision.decision_id,
            evidence.content_fingerprint[:16] + "...",
            self.faiss.size,
        )

    def save_index(self) -> bool:
        """Persist the FAISS index to disk."""
        return self.faiss.save()

    # ─── Logging ──────────────────────────────────────────────────────────────

    def _log_routing(self, result: RoutingResult) -> None:
        """Log a routing decision for demo/audit purposes."""
        log_entry = result.to_log_dict()
        self._routing_log.append(log_entry)
        logger.info(
            "A3: %s | path=%d (%s) | sim=%.4f | %s | %.3fms",
            result.evidence_id,
            result.path,
            {1: "EXACT", 2: "FUZZY", 3: "NOVEL"}[result.path],
            result.similarity_score,
            result.decision.decision_id if result.decision else "-> A4",
            result.timing_ms,
        )

    def get_routing_log(self) -> List[Dict[str, Any]]:
        """Return all routing decisions as a list of structured dicts."""
        return list(self._routing_log)

    def get_routing_stats(self) -> Dict[str, Any]:
        """Return aggregate routing statistics."""
        total = len(self._routing_log)
        if total == 0:
            return {"total": 0, "path_1": 0, "path_2": 0, "path_3": 0}

        p1 = sum(1 for r in self._routing_log if r["path"] == 1)
        p2 = sum(1 for r in self._routing_log if r["path"] == 2)
        p3 = sum(1 for r in self._routing_log if r["path"] == 3)

        timings = [r["timing_ms"] for r in self._routing_log]
        p1_timings = [r["timing_ms"] for r in self._routing_log if r["path"] == 1]
        p2_timings = [r["timing_ms"] for r in self._routing_log if r["path"] == 2]
        p3_timings = [r["timing_ms"] for r in self._routing_log if r["path"] == 3]

        def _avg(lst):
            return round(sum(lst) / len(lst), 3) if lst else 0.0

        return {
            "total": total,
            "path_1_exact": {"count": p1, "pct": round(p1 / total * 100, 1), "avg_ms": _avg(p1_timings)},
            "path_2_fuzzy": {"count": p2, "pct": round(p2 / total * 100, 1), "avg_ms": _avg(p2_timings)},
            "path_3_novel": {"count": p3, "pct": round(p3 / total * 100, 1), "avg_ms": _avg(p3_timings)},
            "avg_timing_ms": _avg(timings),
            "cache_hit_rate_pct": round((p1 + p2) / total * 100, 1),
        }


# ─── Module-Level Convenience (for pipeline integration) ─────────────────────

_default_router: Optional[A3Router] = None


def get_router(**kwargs) -> A3Router:
    """Get or create the module-level A3Router singleton."""
    global _default_router
    if _default_router is None:
        _default_router = A3Router(**kwargs)
    return _default_router


def process(evidence: Evidence) -> RoutingResult:
    """
    Module-level convenience function for pipeline integration.
    Matches the agent contract: process(evidence) -> result.
    """
    return get_router().route(evidence)


# ─── Smoke Test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from objects.evidence import Evidence

    print("=== A3 Router Smoke Test ===\n")

    # Create router with fresh stores
    router = A3Router(
        redis_store=RedisStore(use_memory_fallback=True),
        faiss_store=FAISSStore(auto_load=False),
    )

    # Create a test Evidence
    import hashlib
    norm = {"src_ip": "185.23.147.82", "dst_ip": "203.94.1.10", "method": "GET"}
    fp = hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()

    ev = Evidence.model_validate({
        "evidence_id": "EV-2026-TEST01",
        "timestamp": "2026-03-15T02:47:33Z",
        "source": "web_access_log",
        "asset_id": "CBSE-WebSvr-01",
        "normalized": norm,
        "content_fingerprint": fp,
        "behavior_embedding": [0.0],
        "context": {"criticality": "HIGH"},
        "confidence": 0.5,
        "uncertainty": 0.5,
        "provenance": "A2_normalizer",
    })

    # Test 1: Path 3 (novel - no cache)
    r1 = router.route(ev)
    print(f"Test 1 - Novel event:     Path={r1.path} (expected 3)  {r1.timing_ms:.3f}ms")
    assert r1.path == 3, f"Expected Path 3, got {r1.path}"

    # Create a Decision and cache it
    dec = Decision.model_validate({
        "decision_id": "DEC-2026-001",
        "hypothesis_id": "HYP-2026-001",
        "action_taken": "BLOCK_IP",
        "risk_score": 0.85,
        "blast_radius_score": 0.3,
    })
    router.cache_decision(ev, dec)

    # Test 2: Path 1 (exact match)
    r2 = router.route(ev)
    print(f"Test 2 - Exact hit:       Path={r2.path} (expected 1)  {r2.timing_ms:.3f}ms  decision={r2.decision.decision_id}")
    assert r2.path == 1, f"Expected Path 1, got {r2.path}"

    # Test 3: Different evidence, no match
    norm2 = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "method": "POST"}
    fp2 = hashlib.sha256(json.dumps(norm2, sort_keys=True).encode()).hexdigest()
    ev2 = Evidence.model_validate({
        "evidence_id": "EV-2026-TEST02",
        "timestamp": "2026-08-15T10:00:00Z",
        "source": "web_access_log",
        "asset_id": "CBSE-DB-01",
        "normalized": norm2,
        "content_fingerprint": fp2,
        "behavior_embedding": [0.1] * 256,
        "context": {"criticality": "CRITICAL"},
        "confidence": 0.5,
        "uncertainty": 0.5,
        "provenance": "A2_normalizer",
    })
    r3 = router.route(ev2)
    print(f"Test 3 - Different event: Path={r3.path} (expected 3)  {r3.timing_ms:.3f}ms")
    assert r3.path == 3, f"Expected Path 3, got {r3.path}"

    # Print stats
    stats = router.get_routing_stats()
    print(f"\n=== Routing Stats ===")
    print(json.dumps(stats, indent=2))
    print(f"\nAll A3 smoke tests passed!")
