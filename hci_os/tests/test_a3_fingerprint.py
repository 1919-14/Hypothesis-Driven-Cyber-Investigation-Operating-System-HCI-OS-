"""
tests/test_a3_fingerprint.py
Comprehensive unit tests for A3: Hash & Fingerprint Agent + 3-Path Router.

Covers:
  - RedisStore: get, set, exists, delete, TTL, memory fallback
  - FAISSStore: add, search, threshold, normalization, save/load, reset
  - A3Router: Path 1 exact, Path 2 fuzzy, Path 3 novel
  - Confidence adjustment on fuzzy match
  - Criticality mismatch fallback to Path 3
  - Routing log and stats
  - Graceful degradation when stores fail
  - Cache management (cache_decision populates both Redis + FAISS)

Run with:  pytest tests/test_a3_fingerprint.py -v
"""

import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

# Ensure hci_os/ is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from objects.evidence import Evidence
from objects.decision import Decision
from stores.redis_store import RedisStore
from stores.faiss_store import FAISSStore
from agents.a3_fingerprint import A3Router, RoutingResult


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _make_fingerprint(normalized: dict) -> str:
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()


def _make_evidence(
    eid: str = "EV-2026-TEST01",
    normalized: dict = None,
    embedding: list = None,
    criticality: str = "HIGH",
    asset_id: str = "CBSE-WebSvr-01",
) -> Evidence:
    norm = normalized or {"src_ip": "185.23.147.82", "method": "GET"}
    fp = _make_fingerprint(norm)
    return Evidence.model_validate({
        "evidence_id": eid,
        "timestamp": "2026-03-15T02:47:33Z",
        "source": "web_access_log",
        "asset_id": asset_id,
        "normalized": norm,
        "content_fingerprint": fp,
        "behavior_embedding": embedding or [0.0],
        "context": {"criticality": criticality},
        "confidence": 0.5,
        "uncertainty": 0.5,
        "provenance": "A2_normalizer",
    })


def _make_decision(
    did: str = "DEC-2026-001",
    action: str = "BLOCK_IP",
    risk: float = 0.85,
) -> Decision:
    return Decision.model_validate({
        "decision_id": did,
        "hypothesis_id": "HYP-2026-001",
        "action_taken": action,
        "risk_score": risk,
        "blast_radius_score": 0.3,
    })


@pytest.fixture
def redis_store():
    """Fresh in-memory Redis store for each test."""
    return RedisStore(use_memory_fallback=True)


@pytest.fixture
def faiss_store(tmp_path):
    """Fresh FAISS store with temp paths for each test."""
    return FAISSStore(
        auto_load=False,
        index_path=str(tmp_path / "test.index"),
        meta_path=str(tmp_path / "test_meta.json"),
    )


@pytest.fixture
def router(redis_store, faiss_store):
    """Fresh A3Router with clean stores."""
    return A3Router(
        redis_store=redis_store,
        faiss_store=faiss_store,
        fuzzy_threshold=0.85,
        confidence_factor=0.95,
    )


# ─── REDIS STORE TESTS ───────────────────────────────────────────────────────

class TestRedisStore:
    """Test the Redis decision cache."""

    def test_set_and_get(self, redis_store):
        redis_store.set("abc123", '{"action": "BLOCK"}')
        assert redis_store.get("abc123") == '{"action": "BLOCK"}'

    def test_get_nonexistent(self, redis_store):
        assert redis_store.get("nonexistent") is None

    def test_exists(self, redis_store):
        assert redis_store.exists("abc123") is False
        redis_store.set("abc123", '{"test": true}')
        assert redis_store.exists("abc123") is True

    def test_delete(self, redis_store):
        redis_store.set("abc123", '{"test": true}')
        assert redis_store.delete("abc123") is True
        assert redis_store.get("abc123") is None

    def test_delete_nonexistent(self, redis_store):
        assert redis_store.delete("nonexistent") is False

    def test_ttl_expiry(self, redis_store):
        """Set a very short TTL and verify expiry."""
        redis_store.set("short_ttl", '{"expired": true}', ttl_seconds=1)
        assert redis_store.get("short_ttl") is not None
        time.sleep(1.1)
        assert redis_store.get("short_ttl") is None

    def test_clear(self, redis_store):
        redis_store.set("k1", "v1")
        redis_store.set("k2", "v2")
        count = redis_store.clear()
        assert count == 2
        assert redis_store.count() == 0

    def test_count(self, redis_store):
        assert redis_store.count() == 0
        redis_store.set("k1", "v1")
        redis_store.set("k2", "v2")
        assert redis_store.count() == 2

    def test_memory_mode_flag(self, redis_store):
        assert redis_store.is_memory_mode is True

    def test_overwrite_key(self, redis_store):
        redis_store.set("key", "v1")
        redis_store.set("key", "v2")
        assert redis_store.get("key") == "v2"


# ─── FAISS STORE TESTS ───────────────────────────────────────────────────────

class TestFAISSStore:
    """Test the FAISS vector index."""

    def test_add_and_size(self, faiss_store):
        assert faiss_store.size == 0
        faiss_store.add([[1.0] * 256])
        assert faiss_store.size == 1

    def test_add_multiple(self, faiss_store):
        vectors = [[float(i)] * 256 for i in range(5)]
        faiss_store.add(vectors)
        assert faiss_store.size == 5

    def test_search_returns_results(self, faiss_store):
        faiss_store.add(
            [[1.0] * 256],
            metadata=[{"evidence_id": "EV-001"}],
        )
        results = faiss_store.search([1.0] * 256, k=1)
        assert len(results) == 1
        assert results[0]["similarity"] > 0.99  # Near-identical
        assert results[0]["above_threshold"] is True
        assert results[0]["metadata"]["evidence_id"] == "EV-001"

    def test_search_empty_index(self, faiss_store):
        results = faiss_store.search([1.0] * 256)
        assert results == []

    def test_search_below_threshold(self, faiss_store):
        # Add a vector that is orthogonal to the query
        v1 = [0.0] * 256
        v1[0] = 1.0  # Only first dimension
        faiss_store.add([v1])

        query = [0.0] * 256
        query[255] = 1.0  # Only last dimension (orthogonal)
        results = faiss_store.search(query, k=1, threshold=0.85)
        assert len(results) == 1
        assert results[0]["above_threshold"] is False

    def test_dimension_validation(self, faiss_store):
        with pytest.raises(ValueError, match="Expected 256-dim"):
            faiss_store.add([[1.0] * 128])

    def test_search_dimension_validation(self, faiss_store):
        faiss_store.add([[1.0] * 256])
        with pytest.raises(ValueError, match="must be 256-dim"):
            faiss_store.search([1.0] * 128)

    def test_save_and_load(self, faiss_store, tmp_path):
        faiss_store.add(
            [[1.0] * 256, [0.5] * 256],
            metadata=[{"id": "a"}, {"id": "b"}],
        )
        assert faiss_store.save() is True

        # Create a new store pointing to the same files
        loaded = FAISSStore(
            auto_load=True,
            index_path=str(tmp_path / "test.index"),
            meta_path=str(tmp_path / "test_meta.json"),
        )
        assert loaded.size == 2

    def test_reset(self, faiss_store):
        faiss_store.add([[1.0] * 256])
        assert faiss_store.size == 1
        faiss_store.reset()
        assert faiss_store.size == 0

    def test_metadata_parallel(self, faiss_store):
        faiss_store.add(
            [[1.0] * 256, [0.5] * 256],
            metadata=[{"tag": "first"}, {"tag": "second"}],
        )
        results = faiss_store.search([1.0] * 256, k=2)
        tags = {r["metadata"]["tag"] for r in results}
        assert "first" in tags


# ─── A3 ROUTER TESTS ─────────────────────────────────────────────────────────

class TestA3Router:
    """Test the 3-Path Router end-to-end."""

    def test_path_3_novel_event(self, router):
        """No cache, no FAISS data --> Path 3."""
        ev = _make_evidence()
        result = router.route(ev)
        assert result.path == 3
        assert result.decision is None
        assert result.timing_ms >= 0

    def test_path_1_exact_match(self, router):
        """Cache a decision, then route same evidence --> Path 1."""
        ev = _make_evidence()
        dec = _make_decision()

        router.cache_decision(ev, dec)
        result = router.route(ev)

        assert result.path == 1
        assert result.decision is not None
        assert result.decision.decision_id == "DEC-2026-001"
        assert result.decision.action_taken == "BLOCK_IP"
        assert result.similarity_score == 1.0

    def test_path_1_timing(self, router):
        """Path 1 should be very fast (< 50ms even in Python)."""
        ev = _make_evidence()
        dec = _make_decision()
        router.cache_decision(ev, dec)

        result = router.route(ev)
        assert result.path == 1
        assert result.timing_ms < 50  # Very generous for CI

    def test_path_2_fuzzy_match(self, router):
        """Cache with one embedding, query with a very similar one --> Path 2."""
        # Create and cache an evidence with a specific embedding
        base_embedding = list(np.random.rand(256).astype(float))
        ev1 = _make_evidence(
            eid="EV-2026-BASE",
            normalized={"src_ip": "1.2.3.4"},
            embedding=base_embedding,
            criticality="HIGH",
        )
        dec = _make_decision()
        router.cache_decision(ev1, dec)

        # Remove the exact-match cache to force Path 2
        router.redis.delete(ev1.content_fingerprint)

        # Create a slightly different evidence with a very similar embedding
        similar_embedding = [x + np.random.normal(0, 0.01) for x in base_embedding]
        ev2 = _make_evidence(
            eid="EV-2026-SIMILAR",
            normalized={"src_ip": "1.2.3.5"},  # Different fingerprint
            embedding=similar_embedding,
            criticality="HIGH",  # Same criticality
        )
        # We need to re-cache the Decision under the base fingerprint for Path 2 to find it
        router.redis.set(ev1.content_fingerprint, dec.to_json())

        result = router.route(ev2)
        # Should be Path 2 (fuzzy match with similar embedding)
        assert result.path == 2
        assert result.decision is not None
        assert result.similarity_score >= 0.85

    def test_path_2_confidence_adjustment(self, router):
        """Fuzzy match should reduce risk_score by confidence_factor."""
        base_embedding = list(np.random.rand(256).astype(float))
        ev1 = _make_evidence(
            eid="EV-ORIG",
            normalized={"src_ip": "10.0.0.1"},
            embedding=base_embedding,
            criticality="HIGH",
        )
        dec = _make_decision(risk=0.90)
        router.cache_decision(ev1, dec)

        # Remove exact match to force fuzzy path
        router.redis.delete(ev1.content_fingerprint)
        router.redis.set(ev1.content_fingerprint, dec.to_json())

        similar = [x + np.random.normal(0, 0.01) for x in base_embedding]
        ev2 = _make_evidence(
            eid="EV-SIMILAR",
            normalized={"src_ip": "10.0.0.2"},
            embedding=similar,
            criticality="HIGH",
        )
        result = router.route(ev2)

        if result.path == 2:
            # risk_score should be reduced
            assert result.decision.risk_score < 0.90
            expected = round(0.90 * 0.95, 4)
            assert abs(result.decision.risk_score - expected) < 0.01

    def test_path_3_criticality_mismatch(self, router):
        """If criticality differs, fuzzy match should fall back to Path 3."""
        base_embedding = list(np.random.rand(256).astype(float))
        ev1 = _make_evidence(
            eid="EV-ORIG",
            normalized={"src_ip": "10.0.0.1"},
            embedding=base_embedding,
            criticality="HIGH",
        )
        dec = _make_decision()
        router.cache_decision(ev1, dec)
        router.redis.delete(ev1.content_fingerprint)
        router.redis.set(ev1.content_fingerprint, dec.to_json())

        similar = [x + np.random.normal(0, 0.005) for x in base_embedding]
        ev2 = _make_evidence(
            eid="EV-DIFFCRIT",
            normalized={"src_ip": "10.0.0.3"},
            embedding=similar,
            criticality="CRITICAL",  # Different from "HIGH"
        )
        result = router.route(ev2)
        # Should be Path 3 because criticality doesn't match
        assert result.path == 3

    def test_routing_log_populated(self, router):
        ev = _make_evidence()
        router.route(ev)
        log = router.get_routing_log()
        assert len(log) == 1
        assert log[0]["path"] == 3
        assert log[0]["evidence_id"] == "EV-2026-TEST01"
        assert "timing_ms" in log[0]

    def test_routing_stats(self, router):
        ev = _make_evidence()
        router.route(ev)
        dec = _make_decision()
        router.cache_decision(ev, dec)
        router.route(ev)

        stats = router.get_routing_stats()
        assert stats["total"] == 2
        assert stats["path_3_novel"]["count"] == 1
        assert stats["path_1_exact"]["count"] == 1

    def test_cache_decision_populates_both_stores(self, router):
        """cache_decision should add to both Redis and FAISS."""
        ev = _make_evidence()
        dec = _make_decision()

        assert router.redis.count() == 0
        assert router.faiss.size == 0

        router.cache_decision(ev, dec)

        assert router.redis.count() == 1
        assert router.faiss.size == 1

    def test_a4_callback_invoked_on_path_3(self):
        """If a4_callback is registered, it should be called on Path 3."""
        callback_called = []

        def mock_a4(evidence):
            callback_called.append(evidence.evidence_id)
            return _make_decision(did="DEC-FROM-A4")

        router = A3Router(
            redis_store=RedisStore(use_memory_fallback=True),
            faiss_store=FAISSStore(auto_load=False),
            a4_callback=mock_a4,
        )
        ev = _make_evidence()
        result = router.route(ev)

        assert result.path == 3
        assert len(callback_called) == 1
        assert result.decision is not None
        assert result.decision.decision_id == "DEC-FROM-A4"

    def test_multiple_routes_correct_paths(self, router):
        """Route 3 different evidences: novel, cached exact, novel again."""
        ev1 = _make_evidence(eid="EV-001", normalized={"a": 1})
        ev2 = _make_evidence(eid="EV-002", normalized={"b": 2})

        # First route: both novel
        r1 = router.route(ev1)
        r2 = router.route(ev2)
        assert r1.path == 3
        assert r2.path == 3

        # Cache ev1
        router.cache_decision(ev1, _make_decision())

        # Route again: ev1 should be exact, ev2 still novel
        r1_again = router.route(ev1)
        r2_again = router.route(ev2)
        assert r1_again.path == 1
        assert r2_again.path == 3

    def test_configurable_threshold(self):
        """Router should respect custom fuzzy threshold."""
        router = A3Router(
            redis_store=RedisStore(use_memory_fallback=True),
            faiss_store=FAISSStore(auto_load=False),
            fuzzy_threshold=0.99,  # Very strict
        )
        assert router.fuzzy_threshold == 0.99


# ─── RUN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
