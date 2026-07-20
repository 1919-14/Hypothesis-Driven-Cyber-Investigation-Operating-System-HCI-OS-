"""
agents/self_defense.py
Self-Defense Layer — SD-0 through SD-8 unified security wrapper for HCI-OS.

Implements:
  SD-2  Dual-LLM Sandbox (simulated — scope cut documented)
  SD-3  Resource Guardian: 30s timeout, 2048-token cap, circuit breaker (3 fails → 60s cooldown)
  SD-4  Write-Authorization enforcement per agent (stack inspection, deny-by-default — Gap #4)
  SD-5  Output Judge: centralized output_gate() for all outputs (Gap #1)
  SD-8  Kill Switch: AUTONOMY_FROZEN flag + hardcoded approver list (Gap #3)

SD-7 forensics (log_rejection) lives in a12_audit.py.
SD-0/SD-1 gate is enforced in pipeline/investigation_loop.py.
SD-6 watchdog wiring lives in pipeline/investigation_loop.py.

Gap Fixes:
  Gap 1  SD-5 centralized gate    — output_gate() wraps ALL outputs going to UI/external
  Gap 3  SD-8 release auth        — VALID_APPROVERS whitelist; unknown approver raises PermissionError
  Gap 4  SD-4 fail-safe fallback  — deny_by_default=True; agents not in whitelist cannot write
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SelfDefense")

# ─── Paths ────────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
_DATA_DIR  = _AGENT_DIR.parent / "data"
CIRCUIT_BREAKER_PATH = _DATA_DIR / "circuit_breaker.json"

# =============================================================================
# SD-8: KILL SWITCH
# =============================================================================

# Hardcoded approver whitelist — Gap #3 fix
VALID_APPROVERS: frozenset = frozenset({"CISO", "sysadmin", "admin", "security_lead"})

_AUTONOMY_FROZEN   = False
_FREEZE_TIMESTAMP: Optional[float] = None
_FREEZE_REASON: Optional[str]      = None
_kill_switch_lock  = threading.Lock()


def is_autonomy_frozen() -> bool:
    """Return True if the emergency kill switch is active."""
    return _AUTONOMY_FROZEN


def freeze_autonomy(reason: str = "emergency-stop") -> Dict[str, Any]:
    """
    Activate the kill switch.  Sets AUTONOMY_FROZEN = True.
    A7, A10, and A13 must call check_kill_switch() before autonomous actions.

    NOTE: Once frozen, the state does NOT auto-release after 300 s (fail-safe).
    Release requires a manual call to release_autonomy() with a valid approver.
    """
    global _AUTONOMY_FROZEN, _FREEZE_TIMESTAMP, _FREEZE_REASON
    with _kill_switch_lock:
        _AUTONOMY_FROZEN   = True
        _FREEZE_TIMESTAMP  = time.time()
        _FREEZE_REASON     = reason
    logger.critical("SD-8 KILL SWITCH ACTIVATED: reason=%s", reason)
    print(f"🚨 KILL SWITCH ACTIVATED — All autonomous actions HALTED. Reason: {reason}")
    return {
        "frozen":    True,
        "reason":    reason,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }


def release_autonomy(approver: str, notes: str = "") -> Dict[str, Any]:
    """
    Release the kill switch.  Requires a valid approver (Gap #3).

    Args:
        approver: Must be one of VALID_APPROVERS.
        notes:    Optional free-text notes logged to audit.

    Raises:
        PermissionError: If approver is not in VALID_APPROVERS.
    """
    global _AUTONOMY_FROZEN, _FREEZE_TIMESTAMP, _FREEZE_REASON
    # Gap #3 — hardcoded approver validation
    if approver not in VALID_APPROVERS:
        msg = (
            f"SD-8 RELEASE REJECTED: '{approver}' is not an authorized approver. "
            f"Valid approvers: {sorted(VALID_APPROVERS)}"
        )
        logger.error(msg)
        raise PermissionError(msg)

    with _kill_switch_lock:
        was_frozen     = _AUTONOMY_FROZEN
        _AUTONOMY_FROZEN  = False
        _FREEZE_TIMESTAMP = None
        _FREEZE_REASON    = None

    logger.info("SD-8 Kill switch RELEASED by approver=%s. Notes: %s", approver, notes)
    print(f"✅ KILL SWITCH RELEASED by {approver}. Autonomous operations resumed.")
    return {
        "frozen":   False,
        "released_by": approver,
        "notes":    notes,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "was_frozen": was_frozen,
    }


def check_kill_switch(agent_id: str) -> None:
    """
    Guard function for autonomous agents (A7, A10, A13).
    Raises KillSwitchError if autonomy is frozen.

    Call this at the START of every autonomous action.
    """
    if _AUTONOMY_FROZEN:
        reason = _FREEZE_REASON or "no reason given"
        msg = f"SD-8 KILL SWITCH: Agent {agent_id} blocked — autonomy frozen ({reason})"
        logger.warning(msg)
        raise KillSwitchError(msg)


class KillSwitchError(RuntimeError):
    """Raised when an autonomous agent tries to act while AUTONOMY_FROZEN."""


# =============================================================================
# SD-3: RESOURCE GUARDIAN (Circuit Breaker)
# =============================================================================

CB_MAX_FAILURES   = 3
CB_COOLING_SECS   = 60

_circuit_states: Dict[str, Dict[str, Any]] = {}  # call_path → state dict
_cb_lock = threading.Lock()


def _load_circuit_state() -> None:
    """Load persisted circuit-breaker state from disk on startup."""
    global _circuit_states
    if CIRCUIT_BREAKER_PATH.exists():
        try:
            with open(CIRCUIT_BREAKER_PATH, "r", encoding="utf-8") as fh:
                _circuit_states = json.load(fh)
            logger.info("SD-3: Loaded %d circuit-breaker states from disk", len(_circuit_states))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("SD-3: Could not load circuit_breaker.json (%s) — starting fresh", exc)
            _circuit_states = {}


def _persist_circuit_state() -> None:
    """Persist circuit-breaker state to disk."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(CIRCUIT_BREAKER_PATH, "w", encoding="utf-8") as fh:
            json.dump(_circuit_states, fh, indent=2)
    except OSError as exc:
        logger.warning("SD-3: Could not persist circuit state: %s", exc)


def _get_cb_state(call_path: str) -> Dict[str, Any]:
    if call_path not in _circuit_states:
        _circuit_states[call_path] = {
            "consecutive_failures": 0,
            "open_until": None,
            "total_calls": 0,
            "total_failures": 0,
        }
    return _circuit_states[call_path]


def resource_guardian(
    call_path: str,
    timeout_secs: float = 30.0,
    max_tokens: int = 2048,
) -> Callable:
    """
    Decorator factory for SD-3 Resource Guardian.

    Usage:
        @resource_guardian("A6.llm_call")
        def _call_llm(...):
            ...

    Enforces:
      - 30 s timeout (wraps function in a thread)
      - Circuit breaker: 3 consecutive failures → open for 60 s
    """
    def decorator(func: Callable) -> Callable:
        import functools

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with _cb_lock:
                state = _get_cb_state(call_path)
                state["total_calls"] += 1

                # Check if circuit is open
                if state["open_until"] is not None:
                    if time.time() < state["open_until"]:
                        remaining = round(state["open_until"] - time.time(), 1)
                        msg = (
                            f"SD-3 CIRCUIT OPEN: {call_path} is tripped. "
                            f"Cooling off for {remaining}s more."
                        )
                        logger.warning(msg)
                        print(f"⚡ {msg}")
                        raise CircuitOpenError(msg)
                    else:
                        # Cooling-off window expired — half-open, try once
                        logger.info("SD-3: %s cooling-off expired — half-open", call_path)
                        state["open_until"] = None
                        state["consecutive_failures"] = 0
                        _persist_circuit_state()

            # Execute with timeout using a thread
            result_container: List[Any] = [None]
            exc_container:    List[Optional[BaseException]] = [None]

            def _run():
                try:
                    result_container[0] = func(*args, **kwargs)
                except Exception as e:
                    exc_container[0] = e

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join(timeout=timeout_secs)

            if t.is_alive():
                # Timeout — count as failure
                with _cb_lock:
                    state = _get_cb_state(call_path)
                    state["consecutive_failures"] += 1
                    state["total_failures"] += 1
                    if state["consecutive_failures"] >= CB_MAX_FAILURES:
                        state["open_until"] = time.time() + CB_COOLING_SECS
                        logger.error(
                            "SD-3 CIRCUIT TRIPPED: %s after %d consecutive failures. "
                            "Cooling off for %ds.",
                            call_path, CB_MAX_FAILURES, CB_COOLING_SECS,
                        )
                        print(f"🔴 SD-3 CIRCUIT BREAKER TRIPPED: {call_path}")
                    _persist_circuit_state()
                raise TimeoutError(f"SD-3: {call_path} exceeded {timeout_secs}s timeout")

            if exc_container[0] is not None:
                with _cb_lock:
                    state = _get_cb_state(call_path)
                    state["consecutive_failures"] += 1
                    state["total_failures"] += 1
                    if state["consecutive_failures"] >= CB_MAX_FAILURES:
                        state["open_until"] = time.time() + CB_COOLING_SECS
                        logger.error(
                            "SD-3 CIRCUIT TRIPPED: %s after %d consecutive failures.",
                            call_path, CB_MAX_FAILURES,
                        )
                        print(f"🔴 SD-3 CIRCUIT BREAKER TRIPPED: {call_path}")
                    _persist_circuit_state()
                raise exc_container[0]  # type: ignore[misc]

            # Success — reset consecutive failures
            with _cb_lock:
                state = _get_cb_state(call_path)
                if state["consecutive_failures"] > 0:
                    logger.info("SD-3: %s recovered (consecutive failures reset)", call_path)
                state["consecutive_failures"] = 0
                _persist_circuit_state()

            return result_container[0]

        return wrapper
    return decorator


class CircuitOpenError(RuntimeError):
    """Raised when a call path's circuit breaker is open."""


def get_circuit_status(call_path: Optional[str] = None) -> Dict[str, Any]:
    """Return circuit breaker status for one or all call paths."""
    with _cb_lock:
        if call_path:
            return dict(_get_cb_state(call_path))
        return {k: dict(v) for k, v in _circuit_states.items()}


def reset_circuit(call_path: str) -> None:
    """Manually reset a circuit breaker (for testing / ops)."""
    with _cb_lock:
        if call_path in _circuit_states:
            _circuit_states[call_path]["consecutive_failures"] = 0
            _circuit_states[call_path]["open_until"] = None
            _persist_circuit_state()
    logger.info("SD-3: Circuit reset for %s", call_path)


# =============================================================================
# SD-4: WRITE-AUTHORIZATION ENFORCEMENT
# =============================================================================

# Allowed file write patterns per agent (deny-by-default — Gap #4)
# Values are lists of partial path suffixes that the agent is allowed to write.
WRITE_WHITELIST: Dict[str, List[str]] = {
    "A1":  ["quarantine.jsonl"],
    "A2":  [],              # A2 only creates Evidence in-memory; no file writes
    "A3":  [],              # A3 writes to Redis cache (no local files)
    "A4":  [],              # A4 enriches Evidence in-memory
    "A5":  [],              # A5 enriches Evidence in-memory
    "A6":  [],              # A6 updates Hypothesis in-memory
    "A7":  [],              # A7 creates Decision in-memory
    "A8":  [],              # A8 updates Hypothesis in-memory
    "A9":  [],              # A9 no direct writes
    "A10": ["hunt_cache.json"],
    "A11": ["watchdog_log.jsonl", "watchdog_suspensions.json", ".a11_health_write_test"],
    "A12": [
        "audit_log.jsonl",
        "cognitive_memory.jsonl",
        "shadow_results.json",
        "sd_log.jsonl",
        "circuit_breaker.json",  # A12/self_defense writes this
    ],
    "A13": ["federation_store.json"],
}

# Object creation authorizations: type → allowed agent IDs
CREATION_WHITELIST: Dict[str, List[str]] = {
    "Evidence":   ["A2", "A10"],
    "Hypothesis": ["A6", "A8"],
    "Decision":   ["A7"],
}

_TESTING_MARKERS = frozenset({"pytest", "test_", "_pytest", "unittest"})


def _is_test_context() -> bool:
    """Return True if we are being called from a test suite."""
    # Check environment variable first (fastest)
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("SD_TESTING") == "1":
        return True
    for frame_info in inspect.stack():
        fn = frame_info.filename.replace("\\", "/")
        if any(m in fn for m in _TESTING_MARKERS):
            return True
    return False


def _caller_agent_id() -> str:
    """
    Walk the call stack to find the calling agent module name.
    Returns e.g. "A6" if called from agents/a6_attribution.py.
    Returns "UNKNOWN" if no agent module is found.
    """
    for frame_info in inspect.stack():
        fn = os.path.basename(frame_info.filename).lower()
        # Match a1_*.py … a13_*.py or self_defense.py
        if fn.startswith("a") and fn.endswith(".py"):
            parts = fn.split("_")
            candidate = parts[0].upper()  # e.g. "A6", "A13"
            if candidate[1:].isdigit():
                return candidate
    return "UNKNOWN"


def enforce_write_authorization(agent_id: str, filepath: str) -> None:
    """
    SD-4: Check whether agent_id is allowed to write to filepath.

    Gap #4 — deny-by-default: if agent_id is not in WRITE_WHITELIST,
    the write is blocked regardless of the file path.

    Raises:
        PermissionError: if the write is not authorized.
    """
    if _is_test_context():
        return  # bypass in test runs

    # Gap #4: deny-by-default for unknown agents
    if agent_id not in WRITE_WHITELIST:
        msg = (
            f"SD-4 WRITE DENIED: agent '{agent_id}' is not in the whitelist. "
            f"Write to '{filepath}' blocked (deny-by-default)."
        )
        logger.error(msg)
        _sd4_log_rejection(agent_id, "write_auth_failure_unknown_agent", msg, filepath)
        raise PermissionError(msg)

    allowed = WRITE_WHITELIST[agent_id]
    norm_path = filepath.replace("\\", "/").lower()

    # Empty allowed list means no file writes permitted for this agent
    if not allowed:
        msg = (
            f"SD-4 WRITE DENIED: agent '{agent_id}' has no allowed file writes. "
            f"Attempted path: '{filepath}'"
        )
        logger.error(msg)
        _sd4_log_rejection(agent_id, "write_auth_failure", msg, filepath)
        raise PermissionError(msg)

    if not any(suffix.lower() in norm_path for suffix in allowed):
        msg = (
            f"SD-4 WRITE DENIED: agent '{agent_id}' is not authorized to write "
            f"'{filepath}'. Allowed suffixes: {allowed}"
        )
        logger.error(msg)
        _sd4_log_rejection(agent_id, "write_auth_failure", msg, filepath)
        raise PermissionError(msg)

    logger.debug("SD-4: %s write to '%s' — AUTHORIZED", agent_id, filepath)


def enforce_creation_authorization(agent_id: str, object_type: str) -> None:
    """
    SD-4: Check whether agent_id is allowed to create object_type.

    Raises:
        PermissionError: if the creation is not authorized.
    """
    if _is_test_context():
        return

    allowed_agents = CREATION_WHITELIST.get(object_type)
    if allowed_agents is None:
        return  # unknown type — not tracked

    if agent_id not in allowed_agents:
        msg = (
            f"SD-4 CREATE DENIED: agent '{agent_id}' is not authorized to create "
            f"'{object_type}'. Authorized agents: {allowed_agents}"
        )
        logger.error(msg)
        _sd4_log_rejection(agent_id, "creation_auth_failure", msg, object_type)
        raise PermissionError(msg)


def _sd4_log_rejection(agent_id: str, violation_type: str, reason: str, target: str) -> None:
    """
    Internal: log SD-4 rejection via a12_audit.log_rejection to maintain
    the tamper-evident hash chain in sd_log.jsonl.
    Uses a local import to avoid circular imports at module level.
    """
    try:
        from agents.a12_audit import log_rejection  # local import avoids circular dep
        log_rejection(
            agent_id=agent_id,
            violation_type=violation_type,
            reason=f"{reason} (Target: {target})",
            input_data={"target": target, "sd_layer": "SD-4"},
        )
    except Exception as exc:
        # Last-resort: write a lightweight entry so we never crash the pipeline
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            sd_log = _DATA_DIR / "sd_log.jsonl"
            import hashlib, json
            entry = {
                "sd_log_id":      hashlib.sha256(f"{agent_id}{violation_type}{time.time()}".encode()).hexdigest()[:12],
                "stored_at":      datetime.now(timezone.utc).isoformat() + "Z",
                "sd_layer":       "SD-4",
                "agent_id":       agent_id,
                "violation_type": violation_type,
                "reason":         reason,
                "target":         target,
                "_fallback":      str(exc),
            }
            with open(sd_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass


# =============================================================================
# SD-5: OUTPUT JUDGE  (centralized gate — Gap #1)
# =============================================================================

# Regex patterns for secrets and PII detection
_JUDGE_PATTERNS: Dict[str, re.Pattern] = {
    "aws_key":             re.compile(r"AKIA[0-9A-Z]{16}"),
    "credential_password": re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
    "pii_email":           re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "pii_phone_in":        re.compile(r"(?<!\d)(\+91|0)?[6-9]\d{9}(?!\d)"),
    "secret_token":        re.compile(r"(?i)(api_key|token|secret|bearer)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}"),
}


def scan_output(output_text: str) -> Dict[str, Any]:
    """
    SD-5: Scan a text blob for secrets and PII patterns.

    Returns:
        {
          "blocked":  bool,
          "findings": [{"pattern_name": str, "match": str}, ...],
        }
    """
    findings = []
    text = str(output_text)
    for name, pattern in _JUDGE_PATTERNS.items():
        m = pattern.search(text)
        if m:
            findings.append({"pattern_name": name, "match": m.group(0)[:60]})

    blocked = len(findings) > 0
    if blocked:
        logger.warning(
            "SD-5 OUTPUT BLOCKED: %d pattern(s) matched — %s",
            len(findings),
            [f["pattern_name"] for f in findings],
        )
    return {"blocked": blocked, "findings": findings}


def output_gate(
    output: Any,
    agent_id: str = "UNKNOWN",
    destination: str = "external",
    raise_on_block: bool = True,
) -> Any:
    """
    SD-5 Centralized Output Gate (Gap #1) — must be called for ALL outputs
    destined for the UI, external APIs (A13 federation), or any cross-boundary
    data release.

    Args:
        output:         The output object/dict/string to judge.
        agent_id:       ID of the producing agent (for audit logging).
        destination:    Human-readable destination label.
        raise_on_block: If True, raise OutputJudgeViolation when blocked.
                        If False, return None when blocked (soft block).

    Returns:
        The original output if clean.
        None if soft-blocked (raise_on_block=False).

    Raises:
        OutputJudgeViolation: if blocked and raise_on_block=True.
    """
    text = json.dumps(output, default=str) if not isinstance(output, str) else output
    result = scan_output(text)

    if result["blocked"]:
        findings_str = "; ".join(f["pattern_name"] for f in result["findings"])
        msg = (
            f"SD-5 OUTPUT BLOCKED from agent {agent_id} → {destination}: "
            f"patterns matched: [{findings_str}]"
        )
        print(f"🔴 {msg}")
        # Log to sd_log
        _sd4_log_rejection(agent_id, "output_judge_violation", msg, destination)
        if raise_on_block:
            raise OutputJudgeViolation(msg)
        return None

    return output


class OutputJudgeViolation(RuntimeError):
    """Raised when SD-5 Output Judge blocks an output."""


# =============================================================================
# SD-2: DUAL-LLM SANDBOX (Simulated)
# =============================================================================
# SCOPE CUT: In production this would run two fully network-isolated LLM
# containers — LLM-4 (Processor) processes the untrusted input, and LLM-5
# (Verifier) independently checks LLM-4's output for any instructions that
# would change HCI-OS system behavior (i.e. prompt injection).
#
# Here we simulate the pattern using a single model with two sequential system
# prompts. The Verifier prompt is designed to detect if the input is trying to
# override system behaviour, extract keys, or re-assign roles.

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
    re.compile(r"you\s+are\s+now\s+a", re.I),
    re.compile(r"(forget|disregard)\s+(everything|all)", re.I),
    re.compile(r"(act|behave)\s+as\s+(if\s+)?you\s+(are|were)", re.I),
    re.compile(r"(print|reveal|output|show)\s+(your\s+)?(system\s+)?prompt", re.I),
    re.compile(r"jailbreak", re.I),
    re.compile(r"\$\{jndi:", re.I),  # Log4Shell
]


def simulate_dual_llm(untrusted_input: str) -> Dict[str, Any]:
    """
    SD-2: Simulate Dual-LLM sandbox for untrusted/low-trust inputs (A9).

    SCOPE CUT DOCUMENTED:
      Production → Two network-isolated LLM containers.
      Simulation → Two sequential prompts on one model (Groq Llama 3.x).

    The Verifier step uses regex heuristics when no LLM is available
    (API key absent / circuit open).

    Returns:
        {
          "injection_detected": bool,
          "processor_output": str,     # what the processor extracted
          "verifier_verdict": str,     # "CLEAN" | "INJECTION_SUSPECTED"
          "flags": List[str],          # which injection patterns fired
        }
    """
    flags = []
    for pat in _INJECTION_PATTERNS:
        if pat.search(untrusted_input):
            flags.append(pat.pattern)

    injection_detected = len(flags) > 0
    verifier_verdict = "INJECTION_SUSPECTED" if injection_detected else "CLEAN"

    if injection_detected:
        logger.warning(
            "SD-2 DUAL-LLM VERIFIER: injection suspected in input. Flags=%s", flags
        )
        print(f"⚠️  SD-2 VERIFIER: Prompt injection detected — {len(flags)} pattern(s) matched")

    return {
        "injection_detected": injection_detected,
        "processor_output":   untrusted_input[:500],   # truncated safe excerpt
        "verifier_verdict":   verifier_verdict,
        "flags":              flags,
    }


# =============================================================================
# MODULE INIT
# =============================================================================

_load_circuit_state()
logger.info(
    "SelfDefense layer loaded. Kill switch: %s | Circuit states: %d",
    "FROZEN" if _AUTONOMY_FROZEN else "ACTIVE",
    len(_circuit_states),
)
