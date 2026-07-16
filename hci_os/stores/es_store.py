"""
stores/es_store.py
Elasticsearch Store — DS5: Raw Logs + Baselines + Replay Buffer

90-day rolling retention. Used by:
  A4  — baseline history for dual-baseline fusion
  A10 — SIEM prior-context lookup during Active Hunt

Dual-mode:
  LIVE     — elasticsearch Python client (requires ELASTICSEARCH_* env vars)
  FALLBACK — in-memory deque + append-only JSONL file (no ES install needed)
"""

from __future__ import annotations

import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("ElasticsearchStore")

# ── Optional ES client ────────────────────────────────────────────────────────
try:
    from elasticsearch import Elasticsearch
    _HAS_ES = True
except ImportError:
    _HAS_ES = False
    logger.warning("ElasticsearchStore: 'elasticsearch' package not installed — fallback mode only.")

# ── Paths ──────────────────────────────────────────────────────────────────────
_DATA_DIR     = Path(__file__).resolve().parent.parent / "data"
_FALLBACK_LOG = _DATA_DIR / "es_fallback_logs.jsonl"

# ── Constants ──────────────────────────────────────────────────────────────────
INDEX_PREFIX    = "hcios-logs"          # daily rollover: hcios-logs-2026.07.16
BUFFER_MAXLEN   = 10_000               # in-memory ring buffer size
DEFAULT_TIMEOUT = 5                    # seconds


# =============================================================================
# ELASTICSEARCH STORE
# =============================================================================

class ElasticsearchStore:
    """
    Dual-mode Elasticsearch store.

    LIVE mode:     Indexes every event into a daily ES index.
                   Supports full-text and structured queries.
    FALLBACK mode: Stores events in a thread-safe deque (max 10 000) and
                   appends them to data/es_fallback_logs.jsonl for persistence.
    """

    def __init__(
        self,
        hosts: Optional[List[str]] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        env_hosts = os.getenv("ELASTICSEARCH_HOSTS", "http://localhost:9200")
        self.hosts    = hosts    or env_hosts.split(",")
        self.user     = user     or os.getenv("ELASTICSEARCH_USER",     "")
        self.password = password or os.getenv("ELASTICSEARCH_PASSWORD", "")

        self.use_fallback    = True
        self.client: Optional[Any] = None
        self.fallback_buffer: deque = deque(maxlen=BUFFER_MAXLEN)

        # Ensure data directory exists
        _DATA_DIR.mkdir(parents=True, exist_ok=True)

        if _HAS_ES:
            try:
                kwargs: Dict[str, Any] = {"request_timeout": DEFAULT_TIMEOUT}
                if self.user and self.password:
                    kwargs["basic_auth"] = (self.user, self.password)
                self.client = Elasticsearch(self.hosts, **kwargs)
                if self.client.ping():
                    self.use_fallback = False
                    logger.info("ElasticsearchStore: Connected → %s", self.hosts)
                else:
                    logger.warning("ElasticsearchStore: ping() failed. Using fallback.")
                    self.client = None
            except Exception as exc:
                logger.warning("ElasticsearchStore: Connection failed (%s). Using fallback.", exc)
        else:
            logger.info("ElasticsearchStore: Running in JSONL fallback mode.")

    # ── Index name ─────────────────────────────────────────────────────────────

    @staticmethod
    def _today_index() -> str:
        return f"{INDEX_PREFIX}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

    # ── Write ──────────────────────────────────────────────────────────────────

    def index_log(self, log_dict: Dict[str, Any]) -> None:
        """
        Index a single log/event document.
        Automatically stamps @timestamp if missing.
        """
        if "@timestamp" not in log_dict:
            log_dict = {**log_dict, "@timestamp": datetime.now(timezone.utc).isoformat()}

        if self.use_fallback:
            self.fallback_buffer.append(log_dict)
            try:
                with open(_FALLBACK_LOG, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_dict, default=str) + "\n")
            except OSError as exc:
                logger.warning("ElasticsearchStore: Fallback write error: %s", exc)
            return

        try:
            self.client.index(index=self._today_index(), document=log_dict)
        except Exception as exc:
            logger.error("ElasticsearchStore: ES index error: %s", exc)
            # Degrade gracefully to fallback
            self.fallback_buffer.append(log_dict)

    def index_evidence(self, evidence_dict: Dict[str, Any]) -> None:
        """Convenience wrapper: index a normalised Evidence dict."""
        doc = {
            "evidence_id":   evidence_dict.get("evidence_id"),
            "asset_id":      evidence_dict.get("asset_id"),
            "source":        evidence_dict.get("source"),
            "anomaly_score": evidence_dict.get("anomaly_score", 0.0),
            "normalized":    evidence_dict.get("normalized", {}),
            "@timestamp":    evidence_dict.get("created_at",
                                datetime.now(timezone.utc).isoformat()),
        }
        self.index_log(doc)

    # ── Read ───────────────────────────────────────────────────────────────────

    def query_logs(
        self,
        query_body: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Execute an ES query and return matching docs.
        Falls back to returning the latest buffer entries.
        """
        if self.use_fallback:
            return list(self.fallback_buffer)[-limit:]

        body = query_body or {"query": {"match_all": {}}}
        try:
            res = self.client.search(index=f"{INDEX_PREFIX}-*", body=body, size=limit)
            return [hit["_source"] for hit in res["hits"]["hits"]]
        except Exception as exc:
            logger.error("ElasticsearchStore: Query failed: %s", exc)
            return list(self.fallback_buffer)[-limit:]

    def get_replay_buffer(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Return the most recent `limit` log entries for ML replay / retraining.
        Used by A4 to rebuild baseline distributions from recent traffic history.
        """
        if self.use_fallback:
            return list(self.fallback_buffer)[-limit:]

        body = {
            "query": {"match_all": {}},
            "sort":  [{"@timestamp": {"order": "desc"}}],
        }
        return self.query_logs(body, limit=limit)

    def search_by_asset(self, asset_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent logs for a specific asset (used by A10 Active Hunt)."""
        body = {
            "query": {"match": {"asset_id": asset_id}},
            "sort":  [{"@timestamp": {"order": "desc"}}],
        }
        return self.query_logs(body, limit=limit)

    def search_by_ip(self, ip: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return all log entries mentioning a specific IP (A10 SIEM context)."""
        body = {
            "query": {
                "multi_match": {
                    "query":  ip,
                    "fields": ["normalized.src_ip", "normalized.dst_ip", "normalized.*"],
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return self.query_logs(body, limit=limit)

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_log_count(self) -> int:
        if self.use_fallback:
            # Count lines in fallback file if it exists
            if _FALLBACK_LOG.exists():
                try:
                    with open(_FALLBACK_LOG, "r", encoding="utf-8") as f:
                        return sum(1 for _ in f)
                except OSError:
                    pass
            return len(self.fallback_buffer)

        try:
            res = self.client.count(index=f"{INDEX_PREFIX}-*")
            return res.get("count", 0)
        except Exception:
            return len(self.fallback_buffer)

    def status(self) -> Dict[str, Any]:
        return {
            "mode":      "live" if not self.use_fallback else "fallback",
            "log_count": self.get_log_count(),
            "buffer_len": len(self.fallback_buffer),
            "fallback_file": str(_FALLBACK_LOG),
        }


# =============================================================================
# MODULE-LEVEL SINGLETON
# =============================================================================

_store: Optional[ElasticsearchStore] = None


def get_store() -> ElasticsearchStore:
    """Return the module-level singleton (lazy init)."""
    global _store
    if _store is None:
        _store = ElasticsearchStore()
    return _store
