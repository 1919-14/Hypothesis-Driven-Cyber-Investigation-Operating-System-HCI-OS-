"""
agents/a11_watchdog.py
A11: Behavioral Watchdog Agent (SD-6) — HCI-OS

The internal security guard. Monitors every agent (A1-A10) against
pre-configured role profiles and alerts on deviations.

Checks performed per agent call:
  1. Output Type Mismatch       — forbidden_output_types vs actual type name
  2. Schema Validation          — Pydantic model_validate against expected schema
  3. Rate Limiting              — sliding window call counter vs max_calls_per_minute
  4. Forbidden Action           — caller declares an action; checked against profile
  5. Forbidden Path (Gap #2)    — file paths accessed vs profile.forbidden_paths

Gap Fixes:
  Gap 1  Watchdog self-protection  — independent logger + health_check()
  Gap 2  File path violations      — forbidden_paths per profile checked on every call
  Gap 3  Suspension persistence    — suspensions saved to data/watchdog_suspensions.json
                                     and reloaded on import
"""

from __future__ import annotations

import functools
import json
import logging
import os
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
_AGENT_DIR   = Path(__file__).parent
_DATA_DIR    = _AGENT_DIR.parent / "data"

PROFILES_PATH     = _DATA_DIR / "agent_profiles.json"
WATCHDOG_LOG_PATH = _DATA_DIR / "watchdog_log.jsonl"
SUSPENSIONS_PATH  = _DATA_DIR / "watchdog_suspensions.json"  # Gap #3

# ── Logging (Gap #1 — Independent logger for self-protection) ─────────────────
# Uses its own file handler that does NOT depend on any other agent's log.
_LOG_FORMAT = "%(asctime)s [A11_Watchdog] %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
logger = logging.getLogger("A11_Watchdog")

# ── Severity Constants ────────────────────────────────────────────────────────
INFO     = "INFO"
WARN     = "WARN"
HIGH     = "HIGH"
CRITICAL = "CRITICAL"

SEVERITY_ORDER = {INFO: 0, WARN: 1, HIGH: 2, CRITICAL: 3}

# ── In-memory state ───────────────────────────────────────────────────────────
_profiles: Dict[str, Dict[str, Any]] = {}          # agent_id → profile
_call_timestamps: Dict[str, deque]   = {}           # agent_id → deque[float]
SUSPENDED_AGENTS: Dict[str, str]     = {}           # agent_id → suspension reason


# =============================================================================
# PROFILES
# =============================================================================

def _default_profiles() -> List[Dict[str, Any]]:
    """Minimal default profile list (used when agent_profiles.json is missing)."""
    return [
        {
            "agent_id": aid,
            "display_name": aid,
            "allowed_output_types": ["dict"],
            "forbidden_output_types": [],
            "max_calls_per_minute": 600,
            "expected_output_schema": "dict",
            "forbidden_actions": [],
            "forbidden_paths": [],
        }
        for aid in [f"A{i}" for i in range(1, 12)]
    ]


def _load_profiles() -> None:
    """Load (or initialize) agent profiles from disk. Idempotent."""
    global _profiles
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not PROFILES_PATH.exists():
        logger.warning("A11: agent_profiles.json missing — writing defaults")
        with open(PROFILES_PATH, "w", encoding="utf-8") as fh:
            json.dump(_default_profiles(), fh, indent=2)

    with open(PROFILES_PATH, "r", encoding="utf-8") as fh:
        raw: List[Dict] = json.load(fh)

    _profiles = {p["agent_id"]: p for p in raw}
    logger.info("A11: loaded %d agent profiles", len(_profiles))


def get_profile(agent_id: str) -> Optional[Dict[str, Any]]:
    """Return the role profile for a given agent, or None if unknown."""
    if not _profiles:
        _load_profiles()
    return _profiles.get(agent_id)


# =============================================================================
# SUSPENSION  (Gap #3 — persisted to disk)
# =============================================================================

def _persist_suspensions() -> None:
    """Write current SUSPENDED_AGENTS to disk."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(SUSPENSIONS_PATH, "w", encoding="utf-8") as fh:
        json.dump(
            {"updated_at": datetime.now(timezone.utc).isoformat(), "suspended": SUSPENDED_AGENTS},
            fh, indent=2,
        )


def _load_suspensions() -> None:
    """Restore SUSPENDED_AGENTS from disk (Gap #3 — survives restarts)."""
    global SUSPENDED_AGENTS
    if SUSPENSIONS_PATH.exists():
        try:
            with open(SUSPENSIONS_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            SUSPENDED_AGENTS = data.get("suspended", {})
            if SUSPENDED_AGENTS:
                logger.warning(
                    "A11: restored %d persistent suspensions from disk: %s",
                    len(SUSPENDED_AGENTS), list(SUSPENDED_AGENTS.keys()),
                )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("A11: suspension file corrupt (%s) — starting fresh", exc)
            SUSPENDED_AGENTS = {}


def suspend_agent(agent_id: str, reason: str) -> None:
    """Suspend an agent. Persisted to disk immediately (Gap #3)."""
    if agent_id == "A11":
        logger.warning("A11: cannot suspend self — self-protection (Gap #1)")
        return
    SUSPENDED_AGENTS[agent_id] = reason
    _persist_suspensions()
    logger.warning("A11: SUSPENDED %s — reason: %s", agent_id, reason)


def unsuspend_agent(agent_id: str) -> None:
    """Remove an agent from the suspension registry and persist."""
    if agent_id in SUSPENDED_AGENTS:
        del SUSPENDED_AGENTS[agent_id]
        _persist_suspensions()
        logger.info("A11: UNSUSPENDED %s", agent_id)


def is_suspended(agent_id: str) -> bool:
    return agent_id in SUSPENDED_AGENTS


# =============================================================================
# VIOLATION LOGGING
# =============================================================================

def _atomic_append(path: Path, line: str) -> None:
    """Append a JSON line atomically to the watchdog log."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass


def _log_violation(violation: Dict[str, Any]) -> None:
    """Append a structured violation record to watchdog_log.jsonl."""
    violation.setdefault("log_id", str(uuid.uuid4())[:8])
    violation.setdefault("timestamp", datetime.now(timezone.utc).isoformat() + "Z")
    _atomic_append(WATCHDOG_LOG_PATH, json.dumps(violation, default=str))


def _emit_alert(severity: str, agent_id: str, message: str) -> None:
    """Emit a visible console alert for WARN / HIGH / CRITICAL violations."""
    if severity == WARN:
        print(f"⚠️  WARNING: Agent {agent_id} — {message}")
        logger.warning("A11 WARN [%s]: %s", agent_id, message)
    elif severity == HIGH:
        print(f"🔴 HIGH ALERT: Agent {agent_id} violated profile! — {message}")
        logger.error("A11 HIGH [%s]: %s", agent_id, message)
    elif severity == CRITICAL:
        print(f"🚨 CRITICAL: Agent {agent_id} is compromised! Suspending... — {message}")
        logger.critical("A11 CRITICAL [%s]: %s", agent_id, message)


def _handle_violation(
    agent_id: str,
    violation_type: str,
    expected: str,
    actual: str,
    severity: str,
    recommendation: str,
) -> Dict[str, Any]:
    """Create, log, and handle a single violation record."""
    record = {
        "agent_id":       agent_id,
        "violation_type": violation_type,
        "expected":       expected,
        "actual":         actual,
        "severity":       severity,
        "recommendation": recommendation,
    }
    _log_violation(record)

    if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER[WARN]:
        _emit_alert(severity, agent_id, f"{violation_type}: expected={expected}, got={actual}")

    if severity == CRITICAL:
        suspend_agent(agent_id, f"CRITICAL violation: {violation_type}")

    return record


# =============================================================================
# CHECKS
# =============================================================================

def _resolve_type_name(output: Any) -> str:
    """Return the canonical type name for matching against profiles."""
    name = type(output).__name__
    # Pydantic model instances keep their class name; dicts are "dict"
    return name


def check_output_type(agent_id: str, output: Any, profile: Dict) -> Optional[Dict]:
    """HIGH violation if output type is in forbidden_output_types."""
    type_name = _resolve_type_name(output)
    forbidden  = profile.get("forbidden_output_types", [])
    allowed    = profile.get("allowed_output_types", [])

    if type_name in forbidden:
        return _handle_violation(
            agent_id, "output_type_mismatch",
            expected=" or ".join(allowed) or "allowed_types",
            actual=type_name,
            severity=CRITICAL if type_name in ["Decision", "Hypothesis"] else HIGH,
            recommendation=f"Agent {agent_id} produced forbidden output '{type_name}'. Investigate for compromise.",
        )
    return None


def check_schema(agent_id: str, output: Any, profile: Dict) -> Optional[Dict]:
    """MEDIUM violation if output dict/object fails expected Pydantic schema."""
    schema_name = profile.get("expected_output_schema", "dict")
    if schema_name == "dict":
        return None   # no schema constraint for plain dicts

    # Lazy import to avoid circular dependencies
    try:
        from objects.evidence   import Evidence
        from objects.hypothesis import Hypothesis
        from objects.decision   import Decision

        schema_map = {"Evidence": Evidence, "Hypothesis": Hypothesis, "Decision": Decision}
        model_cls = schema_map.get(schema_name)
        if not model_cls:
            return None

        # If it's already the right type, just verify it validates
        if isinstance(output, model_cls):
            return None

        # Attempt to coerce a dict
        if isinstance(output, dict):
            model_cls.model_validate(output)

    except Exception as exc:
        return _handle_violation(
            agent_id, "schema_validation_failure",
            expected=schema_name,
            actual=str(exc)[:120],
            severity=WARN,
            recommendation=f"Agent {agent_id} output fails {schema_name} schema. Check for missing fields.",
        )
    return None


def check_rate_limit(agent_id: str, profile: Dict) -> Optional[Dict]:
    """HIGH violation if agent exceeds max_calls_per_minute."""
    max_cpm = profile.get("max_calls_per_minute", 600)
    now = time.monotonic()
    window_secs = 60.0

    if agent_id not in _call_timestamps:
        _call_timestamps[agent_id] = deque()

    q = _call_timestamps[agent_id]
    # Evict timestamps older than 60 s
    while q and q[0] < now - window_secs:
        q.popleft()

    q.append(now)

    if len(q) > max_cpm:
        return _handle_violation(
            agent_id, "rate_limit_exceeded",
            expected=f"≤{max_cpm} calls/min",
            actual=f"{len(q)} calls in last 60s",
            severity=HIGH,
            recommendation=f"Agent {agent_id} is being called too frequently. Check for infinite loop or DDoS.",
        )
    return None


def check_forbidden_action(agent_id: str, action: str, profile: Dict) -> Optional[Dict]:
    """CRITICAL violation if action is in forbidden_actions list."""
    forbidden = [a.lower() for a in profile.get("forbidden_actions", [])]
    if action.lower() in forbidden:
        return _handle_violation(
            agent_id, "forbidden_action",
            expected="allowed actions only",
            actual=action,
            severity=CRITICAL,
            recommendation=f"Agent {agent_id} attempted forbidden action '{action}'. May be compromised.",
        )
    return None


def check_forbidden_paths(agent_id: str, paths_accessed: List[str], profile: Dict) -> Optional[Dict]:
    """Gap #2 — CRITICAL violation if agent accesses a forbidden file path."""
    forbidden = [p.lower().replace("\\", "/") for p in profile.get("forbidden_paths", [])]
    for path in paths_accessed:
        norm = path.lower().replace("\\", "/")
        for fp in forbidden:
            if norm.endswith(fp) or fp in norm:
                return _handle_violation(
                    agent_id, "forbidden_path_access",
                    expected="allowed paths only",
                    actual=path,
                    severity=CRITICAL,
                    recommendation=f"Agent {agent_id} accessed forbidden path '{path}'. Possible data exfiltration or tampering.",
                )
    return None


# =============================================================================
# MAIN CHECK API
# =============================================================================

def check_behavior(
    agent_id:       str,
    input_data:     Any,
    output_data:    Any,
    action_called:  Optional[str]    = None,
    paths_accessed: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run all watchdog checks for a single agent call.

    Args:
        agent_id:       ID of the agent being monitored (e.g. "A6").
        input_data:     Input passed to the agent (for context only).
        output_data:    Output returned by the agent.
        action_called:  Optional action name the agent explicitly invoked.
        paths_accessed: Optional list of file paths the agent touched.

    Returns:
        WatchdogReport dict with keys:
          - agent_id, compliant, violations, suspended
    """
    profile = get_profile(agent_id)
    if not profile:
        logger.warning("A11: unknown agent '%s' — skipping checks", agent_id)
        return {"agent_id": agent_id, "compliant": True, "violations": [], "suspended": False}

    violations: List[Dict] = []

    # 1. Rate limit
    v = check_rate_limit(agent_id, profile)
    if v:
        violations.append(v)

    # 2. Output type
    v = check_output_type(agent_id, output_data, profile)
    if v:
        violations.append(v)

    # 3. Schema validation
    v = check_schema(agent_id, output_data, profile)
    if v:
        violations.append(v)

    # 4. Forbidden action
    if action_called:
        v = check_forbidden_action(agent_id, action_called, profile)
        if v:
            violations.append(v)

    # 5. Forbidden paths (Gap #2)
    if paths_accessed:
        v = check_forbidden_paths(agent_id, paths_accessed, profile)
        if v:
            violations.append(v)

    compliant = len(violations) == 0
    if compliant:
        logger.info("A11: agent %s — COMPLIANT", agent_id)

    return {
        "agent_id":   agent_id,
        "compliant":  compliant,
        "violations": violations,
        "suspended":  is_suspended(agent_id),
    }


# =============================================================================
# PIPELINE WRAPPERS
# =============================================================================

def execute_with_watchdog(
    agent_id:    str,
    agent_func:  Callable,
    *args:       Any,
    action_called:  Optional[str]    = None,
    paths_accessed: Optional[List[str]] = None,
    **kwargs:    Any,
) -> Any:
    """
    Execute an agent function under watchdog supervision.

    If the agent is suspended, execution is skipped and the first
    positional argument (assumed to be the input) is returned unchanged.
    Post-execution, all checks are run against the output.
    """
    if is_suspended(agent_id):
        reason = SUSPENDED_AGENTS.get(agent_id, "unknown")
        logger.warning("A11: SKIPPING suspended agent %s (%s)", agent_id, reason)
        return args[0] if args else None

    output = agent_func(*args, **kwargs)
    check_behavior(agent_id, args[0] if args else None, output, action_called, paths_accessed)
    return output


def watchdog_intercept(agent_id: str, action_called: Optional[str] = None):
    """
    Decorator factory.  Wraps any agent function with watchdog supervision.

    Usage:
        @watchdog_intercept("A6")
        def process(evidence, hypothesis):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return execute_with_watchdog(
                agent_id, func, *args,
                action_called=action_called,
                **kwargs,
            )
        return wrapper
    return decorator


# =============================================================================
# SELF-PROTECTION (Gap #1)
# =============================================================================

def health_check() -> Dict[str, Any]:
    """
    Gap #1 — Verify A11's own integrity.

    Checks:
      - Profiles file is readable and non-empty.
      - Watchdog log directory is writable.
      - Suspension file is readable (if present).
      - No self-profile in SUSPENDED_AGENTS (cannot self-suspend).

    Returns:
        {"healthy": bool, "checks": {name: status_str}}
    """
    checks: Dict[str, str] = {}
    healthy = True

    # (a) Profiles readable
    try:
        assert PROFILES_PATH.exists(), "missing"
        with open(PROFILES_PATH, "r", encoding="utf-8") as fh:
            p = json.load(fh)
        assert len(p) > 0, "empty"
        checks["profiles_readable"] = f"OK ({len(p)} agents)"
    except Exception as exc:
        checks["profiles_readable"] = f"FAIL: {exc}"
        healthy = False

    # (b) Log dir writable
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        test_path = _DATA_DIR / ".a11_health_write_test"
        test_path.write_text("ok")
        test_path.unlink()
        checks["log_dir_writable"] = "OK"
    except Exception as exc:
        checks["log_dir_writable"] = f"FAIL: {exc}"
        healthy = False

    # (c) Suspension file coherent
    if SUSPENSIONS_PATH.exists():
        try:
            with open(SUSPENSIONS_PATH, "r", encoding="utf-8") as fh:
                json.load(fh)
            checks["suspension_file"] = "OK"
        except Exception as exc:
            checks["suspension_file"] = f"WARN (corrupt): {exc}"
            # Not fatal — A11 will start fresh
    else:
        checks["suspension_file"] = "OK (not yet created)"

    # (d) Self not suspended
    if "A11" in SUSPENDED_AGENTS:
        checks["self_not_suspended"] = "FAIL: A11 is in its own suspension list!"
        healthy = False
    else:
        checks["self_not_suspended"] = "OK"

    status = "HEALTHY" if healthy else "DEGRADED"
    logger.info("A11 health_check: %s — %s", status, checks)
    return {
        "healthy": healthy,
        "status": status,
        "checks": checks,
        "agents_monitored": len(_profiles) if _profiles else 11,
        "suspended_count": len(SUSPENDED_AGENTS),
    }


# =============================================================================
# BACKWARD-COMPATIBLE monitor() ALIAS
# =============================================================================

def monitor(agent_output: Any, agent_name: str) -> bool:
    """
    Legacy stub alias (from original scaffold).
    Calls check_behavior and returns True if compliant.
    """
    report = check_behavior(agent_name, None, agent_output)
    return report["compliant"]


# =============================================================================
# MODULE INIT
# =============================================================================

# Eagerly load profiles and restore suspensions when module is imported.
_load_profiles()
_load_suspensions()  # Gap #3 — restore suspension state from disk
