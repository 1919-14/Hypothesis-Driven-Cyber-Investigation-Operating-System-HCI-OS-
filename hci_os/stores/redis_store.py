"""
stores/redis_store.py
Redis Store — DS1: Hot Cache for HCI-OS Decision Lookups

Provides sub-millisecond exact-match lookups of cached Decisions
keyed by Evidence content_fingerprint (SHA-256).

Architecture:
    - Key format: "hcios:decision:<sha256_hex>"
    - Value: JSON-serialized Decision object
    - TTL: Configurable (default 30 days)
    - Fallback: If Redis is unavailable, operates in degraded mode
      using an in-memory dict (for hackathon / local dev)

Pipeline position: Used by A3 (Path 1 exact match)
"""

import json
import logging
import time
from datetime import timedelta
from typing import Any, Dict, Optional

logger = logging.getLogger("RedisStore")

# ─── Configuration ───────────────────────────────────────────────────────────
DEFAULT_TTL_SECONDS: int = 30 * 24 * 60 * 60  # 30 days
KEY_PREFIX: str = "hcios:decision:"


class RedisStore:
    """
    Redis-backed decision cache with automatic fallback to in-memory dict.

    In production, connects to a live Redis instance.
    In dev/hackathon mode, uses a thread-safe in-memory dictionary
    that behaves identically (get/set/exists/delete with TTL).
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        use_memory_fallback: bool = True,
    ):
        """
        Initialize the Redis store.

        Args:
            host: Redis host address.
            port: Redis port.
            db: Redis database number.
            password: Optional Redis password.
            ttl_seconds: Default TTL for cached entries (seconds).
            use_memory_fallback: If True, falls back to in-memory dict
                                 when Redis connection fails.
        """
        self.ttl_seconds = ttl_seconds
        self._redis_client = None
        self._memory_store: Dict[str, Dict[str, Any]] = {}  # key -> {value, expires_at}
        self._using_memory = False

        try:
            import redis as redis_lib
            self._redis_client = redis_lib.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=1,
            )
            # Test the connection
            self._redis_client.ping()
            logger.info("RedisStore: Connected to Redis at %s:%d (db=%d)", host, port, db)
        except Exception as exc:
            if use_memory_fallback:
                logger.warning(
                    "RedisStore: Redis unavailable (%s) -- falling back to in-memory cache. "
                    "This is acceptable for hackathon/dev but NOT for production.",
                    exc,
                )
                self._redis_client = None
                self._using_memory = True
            else:
                raise ConnectionError(f"Redis connection failed: {exc}") from exc

    @property
    def is_memory_mode(self) -> bool:
        """True if operating in degraded in-memory mode."""
        return self._using_memory

    def _make_key(self, fingerprint: str) -> str:
        """Build the full Redis key from a content_fingerprint."""
        return f"{KEY_PREFIX}{fingerprint}"

    # ─── Core Operations ──────────────────────────────────────────────────

    def get(self, fingerprint: str) -> Optional[str]:
        """
        Retrieve a cached Decision JSON by content fingerprint.

        Args:
            fingerprint: SHA-256 hex string (64 chars).

        Returns:
            JSON string of the Decision if found, None otherwise.
        """
        key = self._make_key(fingerprint)

        if self._using_memory:
            entry = self._memory_store.get(key)
            if entry is None:
                return None
            if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
                del self._memory_store[key]
                return None
            return entry["value"]

        try:
            return self._redis_client.get(key)
        except Exception as exc:
            logger.error("RedisStore.get failed: %s — returning None", exc)
            return None

    def set(
        self,
        fingerprint: str,
        decision_json: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """
        Cache a Decision JSON keyed by content fingerprint.

        Args:
            fingerprint: SHA-256 hex string.
            decision_json: Serialized Decision object.
            ttl_seconds: Optional override for TTL. Uses default if None.

        Returns:
            True if stored successfully, False on error.
        """
        key = self._make_key(fingerprint)
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds

        if self._using_memory:
            expires_at = time.time() + ttl if ttl > 0 else None
            self._memory_store[key] = {"value": decision_json, "expires_at": expires_at}
            return True

        try:
            self._redis_client.setex(key, ttl, decision_json)
            return True
        except Exception as exc:
            logger.error("RedisStore.set failed: %s", exc)
            return False

    def exists(self, fingerprint: str) -> bool:
        """
        Check if a fingerprint has a cached Decision.

        Args:
            fingerprint: SHA-256 hex string.

        Returns:
            True if a non-expired entry exists.
        """
        key = self._make_key(fingerprint)

        if self._using_memory:
            entry = self._memory_store.get(key)
            if entry is None:
                return False
            if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
                del self._memory_store[key]
                return False
            return True

        try:
            return bool(self._redis_client.exists(key))
        except Exception as exc:
            logger.error("RedisStore.exists failed: %s", exc)
            return False

    def delete(self, fingerprint: str) -> bool:
        """
        Remove a cached entry.

        Args:
            fingerprint: SHA-256 hex string.

        Returns:
            True if deleted, False if not found or on error.
        """
        key = self._make_key(fingerprint)

        if self._using_memory:
            return self._memory_store.pop(key, None) is not None

        try:
            return bool(self._redis_client.delete(key))
        except Exception as exc:
            logger.error("RedisStore.delete failed: %s", exc)
            return False

    def clear(self) -> int:
        """
        Clear ALL HCI-OS decision cache entries.
        Returns count of deleted keys.
        """
        if self._using_memory:
            count = len(self._memory_store)
            self._memory_store.clear()
            return count

        try:
            keys = self._redis_client.keys(f"{KEY_PREFIX}*")
            if keys:
                return self._redis_client.delete(*keys)
            return 0
        except Exception as exc:
            logger.error("RedisStore.clear failed: %s", exc)
            return 0

    def count(self) -> int:
        """Return the number of cached entries."""
        if self._using_memory:
            # Purge expired entries first
            now = time.time()
            expired = [
                k for k, v in self._memory_store.items()
                if v["expires_at"] is not None and now > v["expires_at"]
            ]
            for k in expired:
                del self._memory_store[k]
            return len(self._memory_store)

        try:
            return len(self._redis_client.keys(f"{KEY_PREFIX}*"))
        except Exception as exc:
            logger.error("RedisStore.count failed: %s", exc)
            return 0
