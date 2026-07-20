"""
agents/a12_audit.py
A12: Audit, Memory & Learning Agent (Layers 8–10) — HCI-OS

The memory and learning substrate of HCI-OS. Does four things:

  1. AUDIT  (L8) — Immutably logs every Decision with SHA-256 chaining.
               verify_chain() proves the log is tamper-evident.
  2. MEMORY  (L8/L10) — Stores full Hypothesis Objects in cognitive memory
                for future lookup (episodic memory).
  3. FEEDBACK (L9) — Trust-weighted human corrections with consensus gate.
               SENIOR=0.9, JUNIOR=0.3, EXTERNAL=0.8.
               High-impact corrections (REVOKE/MODIFY/ESCALATE) require
               weighted consensus ≥ 0.7 before applying.
  4. LEARNING (L10) — Shadow deployment promotion: shadow model must be
               ≥95% of live on precision/recall/f1 before promotion.

Pipeline position: A7 (Decision) → [A12] → persisted + flagged for A3 cache update

Key Design Decisions:
  - Storage: JSONL files (data/audit_log.jsonl, data/cognitive_memory.jsonl)
    for hackathon simplicity. Identical API to a PostgreSQL implementation.
    Swap storage backend without changing agent logic.
  - confidence_decay(): reused directly from Hypothesis.confidence_decay()
    (Ticket 1). NOT reimplemented here.
  - SHA-256 chaining: each audit entry carries the hash of the previous entry,
    computed over the canonical JSON of that entry (excluding audit_hash field).
  - Atomic writes: each JSONL append is a single os.write() call to prevent
    torn writes from concurrent processes.
"""

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from objects.decision import Decision
from objects.hypothesis import Hypothesis

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("A12_Audit")

# ─── Paths ────────────────────────────────────────────────────────────────────
_AGENT_DIR = Path(__file__).parent
_DATA_DIR = _AGENT_DIR.parent / "data"

AUDIT_LOG_PATH: Path = _DATA_DIR / "audit_log.jsonl"
COGNITIVE_MEMORY_PATH: Path = _DATA_DIR / "cognitive_memory.jsonl"
SHADOW_RESULTS_PATH: Path = _DATA_DIR / "shadow_results.json"

# ─── Trust Weights ────────────────────────────────────────────────────────────
SENIOR_WEIGHT: float = 0.9
JUNIOR_WEIGHT: float = 0.3
EXTERNAL_WEIGHT: float = 0.8
UNKNOWN_WEIGHT: float = 0.5

ROLE_WEIGHTS: Dict[str, float] = {
    "SENIOR": SENIOR_WEIGHT,
    "JUNIOR": JUNIOR_WEIGHT,
    "EXTERNAL": EXTERNAL_WEIGHT,
    "UNKNOWN": UNKNOWN_WEIGHT,
}

# Corrections that require weighted consensus before applying
HIGH_IMPACT_CORRECTIONS = {"REVOKE", "MODIFY", "ESCALATE"}
CONSENSUS_THRESHOLD: float = 0.7

# Shadow promotion threshold
SHADOW_PROMOTION_THRESHOLD: float = 0.95


# =============================================================================
# UTILITY HELPERS
# =============================================================================

def _ensure_data_dir() -> None:
    """Create data/ directory if it doesn't exist."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)


def _compute_entry_hash(entry: Dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of an audit entry.

    The 'audit_hash' field is excluded from the hash computation
    (same pattern as Decision.compute_hash()) to avoid self-reference.
    """
    data = {k: v for k, v in entry.items() if k != "audit_hash"}
    canonical = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _atomic_append(path: Path, line: str) -> None:
    """
    Atomically append a single line to a JSONL file.
    Opens in append mode; each call writes exactly one JSON line + newline.
    """
    _ensure_data_dir()
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """
    Read all lines from a JSONL file. Returns empty list if file doesn't exist.
    Skips blank lines and malformed JSON lines with a warning.
    """
    if not path.exists():
        return []
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed line %d in %s: %s", lineno, path.name, exc)
    return entries


# =============================================================================
# AUDIT LOG (Layer 8)
# =============================================================================

def log_decision(decision: Decision, extra_context: Optional[Dict[str, Any]] = None) -> str:
    """
    Append a Decision to the immutable SHA-256-chained audit log.

    Each entry includes:
      - Full Decision fields (serialized via to_json())
      - audit_chain_prev: hash of the previous entry
      - audit_hash: hash of this entry (excluding audit_hash itself)
      - stored_at: UTC timestamp

    Args:
        decision: The Decision object produced by A7.
        extra_context: Optional extra fields (e.g., agent_id, pipeline_run_id).

    Returns:
        audit_hash of the newly appended entry.
    """
    # Build the entry dict
    decision_data = json.loads(decision.to_json())

    # Get the previous entry's hash for chaining
    prev_hash = _get_last_audit_hash()

    entry: Dict[str, Any] = {
        "audit_id": str(uuid.uuid4()),
        "stored_at": datetime.now(timezone.utc).isoformat() + "Z",
        "audit_chain_prev": prev_hash,
        **decision_data,
    }
    if extra_context:
        entry["context"] = extra_context

    # Compute and attach the hash of this entry
    entry["audit_hash"] = _compute_entry_hash(entry)

    _atomic_append(AUDIT_LOG_PATH, json.dumps(entry, default=str))

    # Dual-write to MySQL
    try:
        from stores import mysql_store
        mysql_store.save_decision({
            "decision_id": entry.get("decision_id"),
            "hypothesis_id": entry.get("hypothesis_id"),
            "action_taken": entry.get("action_taken"),
            "risk_score": entry.get("risk_score"),
            "blast_radius_score": entry.get("blast_radius_score"),
            "proposed_by": entry.get("proposed_by", "A7-SOAR"),
            "human_reviewed": False,
            "status": "pending",
            **entry
        })
    except Exception as exc:
        logger.warning("A12: Failed to dual-write decision to MySQL (%s)", exc)

    logger.info(
        "A12 AUDIT: logged decision=%s  audit_hash=%s...",
        entry.get("decision_id", "?"),
        entry["audit_hash"][:12],
    )
    return entry["audit_hash"]


def _get_last_audit_hash() -> Optional[str]:
    """Return the audit_hash of the last entry in the audit log, or None."""
    entries = _read_jsonl(AUDIT_LOG_PATH)
    if entries:
        return entries[-1].get("audit_hash")
    return None


def verify_chain(audit_log_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Verify the integrity of the SHA-256 audit chain.

    Reads every entry from the log in order, recomputes each entry's hash,
    and checks that:
      1. Each entry's stored audit_hash matches the recomputed hash.
      2. Each entry's audit_chain_prev matches the previous entry's audit_hash.

    Returns:
        {
          "valid": bool,
          "entries_checked": int,
          "first_tampered_index": int | None,
          "first_tampered_audit_id": str | None,
          "message": str,
        }
    """
    path = audit_log_path or AUDIT_LOG_PATH
    entries = _read_jsonl(path)

    if not entries:
        return {
            "valid": True,
            "entries_checked": 0,
            "first_tampered_index": None,
            "first_tampered_audit_id": None,
            "message": "Audit log is empty — chain is trivially valid.",
        }

    prev_hash: Optional[str] = None

    for idx, entry in enumerate(entries):
        stored_hash = entry.get("audit_hash")
        recomputed_hash = _compute_entry_hash(entry)

        # Check: stored hash matches recomputed hash
        if stored_hash != recomputed_hash:
            msg = (
                f"TAMPERED: Entry {idx} (audit_id={entry.get('audit_id', '?')}) "
                f"stored_hash={stored_hash} != recomputed={recomputed_hash}"
            )
            logger.error("A12 verify_chain: %s", msg)
            return {
                "valid": False,
                "entries_checked": idx + 1,
                "first_tampered_index": idx,
                "first_tampered_audit_id": entry.get("audit_id"),
                "message": msg,
            }

        # Check: chain_prev matches previous hash
        chain_prev = entry.get("audit_chain_prev")
        if chain_prev != prev_hash:
            msg = (
                f"BROKEN CHAIN: Entry {idx} (audit_id={entry.get('audit_id', '?')}) "
                f"audit_chain_prev={chain_prev} but previous audit_hash={prev_hash}"
            )
            logger.error("A12 verify_chain: %s", msg)
            return {
                "valid": False,
                "entries_checked": idx + 1,
                "first_tampered_index": idx,
                "first_tampered_audit_id": entry.get("audit_id"),
                "message": msg,
            }

        prev_hash = stored_hash

    msg = f"Chain verified: {len(entries)} entries, all hashes match."
    logger.info("A12 verify_chain: %s", msg)
    return {
        "valid": True,
        "entries_checked": len(entries),
        "first_tampered_index": None,
        "first_tampered_audit_id": None,
        "message": msg,
    }


def get_audit_log(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return the audit log entries, newest first. Optional limit."""
    entries = _read_jsonl(AUDIT_LOG_PATH)
    entries = list(reversed(entries))
    if limit is not None:
        entries = entries[:limit]
    return entries


# =============================================================================
# COGNITIVE MEMORY (Layer 8 / Layer 10)
# =============================================================================

def store_hypothesis(hypothesis: Hypothesis, tags: Optional[List[str]] = None) -> str:
    """
    Store a full Hypothesis Object in cognitive memory (episodic memory).

    Each line in cognitive_memory.jsonl is the full Hypothesis JSON + metadata.

    Args:
        hypothesis: The Hypothesis to persist.
        tags: Optional list of tags for future keyword search.

    Returns:
        memory_id of the stored entry.
    """
    memory_id = str(uuid.uuid4())
    entry = {
        "memory_id": memory_id,
        "stored_at": datetime.now(timezone.utc).isoformat() + "Z",
        "tags": tags or [],
        **json.loads(hypothesis.to_json()),
    }
    _atomic_append(COGNITIVE_MEMORY_PATH, json.dumps(entry, default=str))

    # Dual-write to MySQL — use `entry` which is already the fully-serialized form
    try:
        from stores import mysql_store
        mysql_store.save_hypothesis(entry)
    except Exception as exc:
        logger.warning("A12: Failed to dual-write hypothesis to MySQL (%s)", exc)

    logger.info(
        "A12 MEMORY: stored hypothesis=%s  memory_id=%s",
        hypothesis.hypothesis_id,
        memory_id,
    )
    return memory_id


def recall_hypotheses(
    keyword: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """
    Retrieve past hypotheses from cognitive memory.

    Simple keyword search over hypothesis goal + tags (for hackathon).
    Production would use a FAISS index over hypothesis embeddings.

    Args:
        keyword: Optional string to match against goal, tags, mission_impact.
        state: Optional state filter (CONFIRMED, REJECTED, CONTAINED, ACTIVE_INVESTIGATION).
        limit: Maximum number of results to return.

    Returns:
        List of matching hypothesis memory entries, newest first.
    """
    # Attempt to load from MySQL database first (skip when running unit tests)
    import sys as _sys
    _in_pytest = "pytest" in _sys.modules or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    if not _in_pytest:
        try:
            from stores import mysql_store
            db_entries = mysql_store.get_hypotheses(limit=limit * 2)
            if db_entries:
                results = []
                for entry in db_entries:
                    if state and entry.get("state") != state:
                        continue
                    if keyword:
                        kw_lower = keyword.lower()
                        searchable = " ".join([
                            str(entry.get("goal", "")),
                            str(entry.get("mission_impact", "")),
                            " ".join(entry.get("tags", [])),
                            " ".join(entry.get("mitre_chain", [])),
                        ]).lower()
                        if kw_lower not in searchable:
                            continue
                    results.append(entry)
                    if len(results) >= limit:
                        break
                if results:
                    return results
        except Exception as exc:
            logger.warning("A12: Failed to recall hypotheses from MySQL (%s) — falling back to JSONL", exc)

    entries = _read_jsonl(COGNITIVE_MEMORY_PATH)
    entries = list(reversed(entries))  # newest first

    results = []
    for entry in entries:
        # State filter
        if state and entry.get("state") != state:
            continue
        # Keyword filter
        if keyword:
            kw_lower = keyword.lower()
            searchable = " ".join([
                str(entry.get("goal", "")),
                str(entry.get("mission_impact", "")),
                " ".join(entry.get("tags", [])),
                " ".join(entry.get("mitre_chain", [])),
            ]).lower()
            if kw_lower not in searchable:
                continue
        results.append(entry)
        if len(results) >= limit:
            break

    return results


def get_cognitive_memory_count() -> int:
    """Return total number of hypotheses stored in cognitive memory."""
    return len(_read_jsonl(COGNITIVE_MEMORY_PATH))


# =============================================================================
# CONFIDENCE DECAY (reused from Ticket 1 — NOT reimplemented)
# =============================================================================

def apply_confidence_decay(hypothesis: Hypothesis) -> float:
    """
    Compute decayed confidence for a hypothesis using the method from Ticket 1.

    This is NOT a reimplementation — it delegates directly to
    Hypothesis.confidence_decay() defined in objects/hypothesis.py.

    Args:
        hypothesis: The Hypothesis object.

    Returns:
        Decayed confidence float.
    """
    now = datetime.now()
    # Ensure both datetimes are naive for subtraction
    last_updated = hypothesis.last_updated
    if last_updated.tzinfo is not None:
        last_updated = last_updated.replace(tzinfo=None)
    hours_since_update = (now - last_updated).total_seconds() / 3600.0
    hours_since_update = max(0.0, hours_since_update)
    # Delegate to Ticket 1 implementation — do NOT reimplement here
    return hypothesis.confidence_decay(hours_since_update)


# =============================================================================
# HUMAN FEEDBACK & TRUST-WEIGHTED CORRECTIONS (Layer 9)
# =============================================================================

class CorrectionReview:
    """
    Tracks human reviews for a single decision.
    Used to compute weighted consensus for high-impact corrections.
    """

    def __init__(self):
        # {analyst_id: {"role": str, "weight": float, "correction_type": str}}
        self._reviews: Dict[str, Dict[str, Any]] = {}

    def add_review(self, analyst_id: str, role: str, correction_type: str) -> None:
        """Record a review from an analyst."""
        weight = ROLE_WEIGHTS.get(role.upper(), UNKNOWN_WEIGHT)
        self._reviews[analyst_id] = {
            "role": role.upper(),
            "weight": weight,
            "correction_type": correction_type.upper(),
        }

    def compute_consensus(self, target_correction_type: str) -> float:
        """
        Compute the weighted consensus for a target correction type.

        Consensus = sum(weights of reviewers agreeing on target_correction_type)
                  / sum(all reviewer weights)

        Returns value in [0, 1]. Higher = stronger consensus.
        """
        if not self._reviews:
            return 0.0
        agree_weight = sum(
            r["weight"]
            for r in self._reviews.values()
            if r["correction_type"] == target_correction_type.upper()
        )
        total_weight = sum(r["weight"] for r in self._reviews.values())
        if total_weight == 0:
            return 0.0
        return agree_weight / total_weight

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._reviews)


# In-memory store for pending reviews (cleared on restart — fine for hackathon demo)
# Key: decision_id, Value: CorrectionReview
_pending_reviews: Dict[str, CorrectionReview] = {}


def apply_human_correction(
    decision: Decision,
    correction_type: str,
    analyst_role: str,
    analyst_id: str,
    new_action: Optional[str] = None,
    extra_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Apply a human correction to a Decision, with trust-weighted consensus gate.

    Correction Types:
      CONFIRM    — Human agrees with AI decision (no change, just marks reviewed).
      REVOKE     — Human reverses an autonomous action.      [HIGH-IMPACT]
      MODIFY     — Human changes action (e.g., ISOLATE→MONITOR). [HIGH-IMPACT]
      ESCALATE   — Human escalates to CISO / CERT-In.       [HIGH-IMPACT]

    High-impact corrections (REVOKE/MODIFY/ESCALATE) require weighted consensus ≥ 0.7
    from all analysts who have weighed in on this decision.

    Args:
        decision:         The Decision object to correct.
        correction_type:  One of CONFIRM / REVOKE / MODIFY / ESCALATE.
        analyst_role:     SENIOR / JUNIOR / EXTERNAL / UNKNOWN.
        analyst_id:       Unique analyst identifier.
        new_action:       New action string (required for MODIFY).
        extra_notes:      Optional free-text notes.

    Returns:
        Dict with keys:
          - status: APPLIED / PENDING_CONSENSUS / REJECTED
          - consensus_score: float
          - corrected_decision: Decision | None
          - message: str
    """
    correction_type = correction_type.upper()
    analyst_role = analyst_role.upper()

    # Validate correction type
    valid_types = {"CONFIRM", "REVOKE", "MODIFY", "ESCALATE"}
    if correction_type not in valid_types:
        return {
            "status": "REJECTED",
            "consensus_score": 0.0,
            "corrected_decision": None,
            "message": f"Invalid correction_type '{correction_type}'. Must be one of {valid_types}.",
        }

    # CONFIRM — low-impact, apply immediately
    if correction_type == "CONFIRM":
        corrected = decision.model_copy(
            update={"human_reviewed": True, "reviewer_id": analyst_id}
        )
        _log_correction(decision, corrected, correction_type, analyst_id, analyst_role, extra_notes)
        return {
            "status": "APPLIED",
            "consensus_score": 1.0,
            "corrected_decision": corrected,
            "message": f"CONFIRM applied immediately by {analyst_id} ({analyst_role}).",
        }

    # HIGH-IMPACT — accumulate review, check consensus
    decision_id = decision.decision_id

    # Register this analyst's review
    if decision_id not in _pending_reviews:
        _pending_reviews[decision_id] = CorrectionReview()
    _pending_reviews[decision_id].add_review(analyst_id, analyst_role, correction_type)

    consensus_score = _pending_reviews[decision_id].compute_consensus(correction_type)
    weight = ROLE_WEIGHTS.get(analyst_role, UNKNOWN_WEIGHT)

    logger.info(
        "A12 FEEDBACK: decision=%s  type=%s  analyst=%s (%s, w=%.1f)  consensus=%.2f / %.1f",
        decision_id, correction_type, analyst_id, analyst_role, weight,
        consensus_score, CONSENSUS_THRESHOLD,
    )

    if consensus_score < CONSENSUS_THRESHOLD:
        return {
            "status": "PENDING_CONSENSUS",
            "consensus_score": round(consensus_score, 4),
            "corrected_decision": None,
            "message": (
                f"Consensus {consensus_score:.2f} < threshold {CONSENSUS_THRESHOLD}. "
                f"Awaiting more reviewers. ({analyst_id} ({analyst_role}, w={weight:.1f}) recorded.)"
            ),
        }

    # Consensus reached — apply correction
    corrected = _apply_correction_logic(decision, correction_type, analyst_id, new_action)
    _log_correction(decision, corrected, correction_type, analyst_id, analyst_role, extra_notes)

    # Clear pending reviews for this decision
    _pending_reviews.pop(decision_id, None)

    return {
        "status": "APPLIED",
        "consensus_score": round(consensus_score, 4),
        "corrected_decision": corrected,
        "message": (
            f"{correction_type} applied after consensus {consensus_score:.2f} ≥ {CONSENSUS_THRESHOLD}."
        ),
    }


def _apply_correction_logic(
    decision: Decision,
    correction_type: str,
    analyst_id: str,
    new_action: Optional[str],
) -> Decision:
    """Apply the actual correction logic and return a new versioned Decision."""
    now = datetime.now(timezone.utc)

    if correction_type == "REVOKE":
        corrected = decision.model_copy(
            update={
                "decision_id": f"{decision.decision_id}-REV",
                "action_taken": f"REVOKED:{decision.action_taken}",
                "human_reviewed": True,
                "reviewer_id": analyst_id,
                "reversed_at": now,
                "reversed_by": analyst_id,
                "version": decision.version + 1,
                "supersedes_decision_id": decision.decision_id,
            }
        )
    elif correction_type == "MODIFY":
        action = new_action or f"MODIFIED:{decision.action_taken}"
        corrected = decision.create_correction(action, analyst_id)
    elif correction_type == "ESCALATE":
        corrected = decision.model_copy(
            update={
                "decision_id": f"{decision.decision_id}-ESC",
                "action_taken": f"ESCALATED:{decision.action_taken}",
                "human_reviewed": True,
                "reviewer_id": analyst_id,
                "version": decision.version + 1,
                "supersedes_decision_id": decision.decision_id,
            }
        )
    else:
        corrected = decision.model_copy(
            update={"human_reviewed": True, "reviewer_id": analyst_id}
        )

    return corrected


def _log_correction(
    original: Decision,
    corrected: Decision,
    correction_type: str,
    analyst_id: str,
    analyst_role: str,
    notes: Optional[str],
) -> None:
    """Log a correction event to the audit log as a chained entry."""
    # Build a correction audit entry (not a full Decision but still chained)
    prev_hash = _get_last_audit_hash()
    entry: Dict[str, Any] = {
        "audit_id": str(uuid.uuid4()),
        "entry_type": "HUMAN_CORRECTION",
        "stored_at": datetime.now(timezone.utc).isoformat() + "Z",
        "audit_chain_prev": prev_hash,
        "original_decision_id": original.decision_id,
        "corrected_decision_id": corrected.decision_id,
        "correction_type": correction_type,
        "analyst_id": analyst_id,
        "analyst_role": analyst_role,
        "notes": notes or "",
    }
    entry["audit_hash"] = _compute_entry_hash(entry)
    _atomic_append(AUDIT_LOG_PATH, json.dumps(entry, default=str))

    logger.info(
        "A12 CORRECTION LOGGED: %s -> %s (%s by %s)",
        original.decision_id,
        corrected.decision_id,
        correction_type,
        analyst_id,
    )


# =============================================================================
# SHADOW DEPLOYMENT PROMOTION CHECK (Layer 10)
# =============================================================================

def should_promote_shadow_model(
    shadow_results: Dict[str, float],
    live_results: Dict[str, float],
) -> bool:
    """
    Determine if a shadow model should replace the live model.

    The shadow model is promoted ONLY if it achieves ≥95% of the live model's
    performance on ALL of: precision, recall, f1.

    This prevents:
      - Attacker poisoning (R1 #15): Adversarially crafted corrections that
        degrade model performance are caught here.
      - Catastrophic forgetting (R2 #35): Models that improved on new data
        but regressed on old data are rejected.

    Args:
        shadow_results: {"precision": float, "recall": float, "f1": float}
        live_results:   {"precision": float, "recall": float, "f1": float}

    Returns:
        True if shadow model should be promoted, False otherwise.
    """
    metrics = ["precision", "recall", "f1"]
    rejection_reasons = []

    for metric in metrics:
        shadow_val = shadow_results.get(metric, 0.0)
        live_val = live_results.get(metric, 0.0)
        threshold_val = live_val * SHADOW_PROMOTION_THRESHOLD

        if shadow_val < threshold_val:
            rejection_reasons.append(
                f"{metric}: shadow={shadow_val:.4f} < {SHADOW_PROMOTION_THRESHOLD*100:.0f}% "
                f"of live={live_val:.4f} (required ≥ {threshold_val:.4f})"
            )

    if rejection_reasons:
        logger.warning(
            "A12 SHADOW REJECTED: Model failed promotion check. Reasons: %s",
            "; ".join(rejection_reasons),
        )
        _log_shadow_result(shadow_results, live_results, promoted=False, reasons=rejection_reasons)
        return False

    logger.info(
        "A12 SHADOW PROMOTED: All metrics ≥ %.0f%% of live. "
        "precision=%.4f recall=%.4f f1=%.4f",
        SHADOW_PROMOTION_THRESHOLD * 100,
        shadow_results.get("f1", 0),
        shadow_results.get("precision", 0),
        shadow_results.get("recall", 0),
    )
    _log_shadow_result(shadow_results, live_results, promoted=True, reasons=[])
    return True


def _log_shadow_result(
    shadow_results: Dict[str, float],
    live_results: Dict[str, float],
    promoted: bool,
    reasons: List[str],
) -> None:
    """Persist shadow deployment evaluation result to shadow_results.json."""
    _ensure_data_dir()
    record = {
        "evaluated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "promoted": promoted,
        "shadow_results": shadow_results,
        "live_results": live_results,
        "threshold": SHADOW_PROMOTION_THRESHOLD,
        "rejection_reasons": reasons,
    }
    # Append to a list in the JSON file
    if SHADOW_RESULTS_PATH.exists():
        try:
            with open(SHADOW_RESULTS_PATH, "r", encoding="utf-8") as fh:
                history = json.load(fh)
        except (json.JSONDecodeError, ValueError):
            history = []
    else:
        history = []
    history.append(record)
    with open(SHADOW_RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump(history, fh, indent=2, default=str)


def get_shadow_promotion_history() -> List[Dict[str, Any]]:
    """Return all shadow model evaluation records."""
    if not SHADOW_RESULTS_PATH.exists():
        return []
    try:
        with open(SHADOW_RESULTS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, ValueError):
        return []


# =============================================================================
# A12 AGENT CLASS (main entry point)
# =============================================================================

class A12AuditAgent:
    """
    Main A12 Audit, Memory & Learning agent.

    Combines all four functions:
      1. log_decision()       — immutable audit logging
      2. store_hypothesis()   — cognitive memory
      3. apply_human_correction() — trust-weighted feedback
      4. should_promote_shadow_model() — shadow deployment gate

    Usage:
        agent = A12AuditAgent()

        # After A7 produces a Decision:
        agent.log_decision(decision)

        # After A6 produces a Hypothesis:
        agent.store_hypothesis(hypothesis)

        # When a SOC analyst submits feedback:
        result = agent.apply_human_correction(decision, "REVOKE", "SENIOR", "analyst_001")

        # When a retrained model is ready:
        promoted = agent.should_promote_shadow_model(shadow_results, live_results)
    """

    def __init__(self):
        _ensure_data_dir()
        logger.info(
            "A12AuditAgent: Initialized "
            "(audit_log=%s, memory=%s)",
            AUDIT_LOG_PATH.name,
            COGNITIVE_MEMORY_PATH.name,
        )

    # ── Delegation methods (thin wrappers for the module-level functions) ──

    def log_decision(self, decision: Decision, extra_context: Optional[Dict] = None) -> str:
        return log_decision(decision, extra_context)

    def verify_chain(self) -> Dict[str, Any]:
        return verify_chain()

    def store_hypothesis(self, hypothesis: Hypothesis, tags: Optional[List[str]] = None) -> str:
        return store_hypothesis(hypothesis, tags)

    def recall_hypotheses(self, keyword: Optional[str] = None, state: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        return recall_hypotheses(keyword, state, limit)

    def apply_confidence_decay(self, hypothesis: Hypothesis) -> float:
        return apply_confidence_decay(hypothesis)

    def apply_human_correction(
        self,
        decision: Decision,
        correction_type: str,
        analyst_role: str,
        analyst_id: str,
        new_action: Optional[str] = None,
        extra_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        return apply_human_correction(
            decision, correction_type, analyst_role, analyst_id, new_action, extra_notes
        )

    def should_promote_shadow_model(
        self, shadow_results: Dict[str, float], live_results: Dict[str, float]
    ) -> bool:
        return should_promote_shadow_model(shadow_results, live_results)

    def get_stats(self) -> Dict[str, Any]:
        """Return quick stats for dashboard/demo."""
        audit_entries = _read_jsonl(AUDIT_LOG_PATH)
        memory_entries = _read_jsonl(COGNITIVE_MEMORY_PATH)
        chain_status = verify_chain()
        shadow_history = get_shadow_promotion_history()
        return {
            "audit_log_entries": len(audit_entries),
            "cognitive_memory_count": len(memory_entries),
            "chain_valid": chain_status["valid"],
            "shadow_promotions": sum(1 for r in shadow_history if r.get("promoted")),
            "shadow_rejections": sum(1 for r in shadow_history if not r.get("promoted")),
        }


# =============================================================================
# SD-7: FORENSIC REJECTION LOG (Self-Defense Audit Chain)
# =============================================================================

SD_LOG_PATH: Path = _DATA_DIR / "sd_log.jsonl"


def _get_last_sd_hash() -> Optional[str]:
    """Return the sd_chain_hash of the last SD log entry, or None."""
    entries = _read_jsonl(SD_LOG_PATH)
    if entries:
        return entries[-1].get("sd_chain_hash")
    return None


def log_rejection(
    agent_id: str,
    violation_type: str,
    reason: str,
    input_data: Any = None,
) -> str:
    """
    SD-7: Log a self-defense rejection event to the immutable sd_log.jsonl chain.

    Every rejection (SD-0 through SD-6) is recorded here with:
      - sd_chain_prev: hash of the previous SD log entry (immutable chain)
      - sd_chain_hash: hash of this entry
      - input_hash: SHA-256 of the input data (for traceability without leaking data)

    Args:
        agent_id:       Which agent triggered the rejection.
        violation_type: e.g. "quarantined_input", "write_auth_failure", "pii_leak",
                        "circuit_open", "kill_switch_blocked", "output_judge_violation".
        reason:         Human-readable explanation.
        input_data:     Raw input (hashed, never stored as plain text).

    Returns:
        sd_chain_hash of the newly appended entry.
    """
    _ensure_data_dir()

    # Hash the input for traceability (never store raw input in audit log)
    if input_data is not None:
        raw_bytes = json.dumps(input_data, default=str, sort_keys=True).encode()
        input_hash = hashlib.sha256(raw_bytes).hexdigest()
    else:
        input_hash = None

    prev_hash = _get_last_sd_hash()

    entry: Dict[str, Any] = {
        "sd_log_id":      str(uuid.uuid4()),
        "stored_at":      datetime.now(timezone.utc).isoformat() + "Z",
        "sd_layer":       "SD-7",
        "agent_id":       agent_id,
        "violation_type": violation_type,
        "reason":         reason,
        "input_hash":     input_hash,
        "sd_chain_prev":  prev_hash,
    }

    # Compute tamper-evident hash of this entry (excluding sd_chain_hash itself)
    canonical = json.dumps(
        {k: v for k, v in entry.items() if k != "sd_chain_hash"},
        sort_keys=True, default=str,
    )
    entry["sd_chain_hash"] = hashlib.sha256(canonical.encode()).hexdigest()

    _atomic_append(SD_LOG_PATH, json.dumps(entry, default=str))

    # Dual-write to MySQL
    try:
        from stores import mysql_store
        mysql_store.save_sd_log({
            "sd_log_id": entry.get("sd_log_id"),
            "sd_layer": "SD-7",
            "agent_id": agent_id,
            "violation_type": violation_type,
            "reason": reason,
            "input_hash": input_hash,
            "sd_chain_prev": prev_hash,
            "sd_chain_hash": entry.get("sd_chain_hash"),
        })
    except Exception as exc:
        logger.warning("A12: Failed to dual-write SD log to MySQL (%s)", exc)

    logger.info(
        "A12 SD-7: logged rejection agent=%s type=%s hash=%s...",
        agent_id, violation_type, entry["sd_chain_hash"][:12],
    )
    return entry["sd_chain_hash"]


def verify_sd_chain(sd_log_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    SD-7 Gap #2: Verify the integrity of the self-defense rejection log chain.

    Reads every SD log entry, recomputes hashes, and checks both:
      1. Each entry's sd_chain_hash matches recomputed hash.
      2. Each entry's sd_chain_prev matches previous entry's sd_chain_hash.

    Returns:
        {
          "valid": bool,
          "entries_checked": int,
          "first_tampered_index": int | None,
          "message": str,
        }
    """
    path = sd_log_path or SD_LOG_PATH
    entries = _read_jsonl(path)

    if not entries:
        return {
            "valid": True,
            "entries_checked": 0,
            "first_tampered_index": None,
            "message": "SD log is empty — chain trivially valid.",
        }

    prev_hash: Optional[str] = None
    for idx, entry in enumerate(entries):
        stored_hash = entry.get("sd_chain_hash")
        data = {k: v for k, v in entry.items() if k != "sd_chain_hash"}
        recomputed = hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str).encode()
        ).hexdigest()

        if stored_hash != recomputed:
            msg = (
                f"TAMPERED: SD entry {idx} (sd_log_id={entry.get('sd_log_id', '?')}) "
                f"hash mismatch: stored={stored_hash} recomputed={recomputed}"
            )
            logger.error("A12 verify_sd_chain: %s", msg)
            return {
                "valid": False,
                "entries_checked": idx + 1,
                "first_tampered_index": idx,
                "message": msg,
            }

        chain_prev = entry.get("sd_chain_prev")
        if chain_prev != prev_hash:
            msg = (
                f"BROKEN CHAIN: SD entry {idx} sd_chain_prev={chain_prev} "
                f"but previous sd_chain_hash={prev_hash}"
            )
            logger.error("A12 verify_sd_chain: %s", msg)
            return {
                "valid": False,
                "entries_checked": idx + 1,
                "first_tampered_index": idx,
                "message": msg,
            }

        prev_hash = stored_hash

    msg = f"SD chain verified: {len(entries)} entries, all hashes match."
    logger.info("A12 verify_sd_chain: %s", msg)
    return {
        "valid": True,
        "entries_checked": len(entries),
        "first_tampered_index": None,
        "message": msg,
    }


def startup_sd_chain_health_check() -> bool:
    """
    SD-7 Gap #2: Run verify_sd_chain at startup. Print a warning if tampered.
    Called automatically when this module is imported.
    Returns True if healthy, False if tampered/broken.
    """
    result = verify_sd_chain()
    if not result["valid"]:
        logger.critical(
            "A12 STARTUP: SD rejection log TAMPERED — %s", result["message"]
        )
        print(f"? SD AUDIT CHAIN INTEGRITY FAILURE: {result['message']}")
        return False
    if result["entries_checked"] > 0:
        logger.info(
            "A12 STARTUP: SD rejection log OK (%d entries verified)",
            result["entries_checked"],
        )
    return True


# =============================================================================
# MODULE-LEVEL CONVENIENCE (for pipeline integration)
# =============================================================================

_default_agent: Optional[A12AuditAgent] = None


def get_agent() -> A12AuditAgent:
    """Get or create the module-level A12 agent singleton."""
    global _default_agent
    if _default_agent is None:
        _default_agent = A12AuditAgent()
    return _default_agent


def process(decision: Decision, hypothesis: Optional[Hypothesis] = None) -> Dict[str, Any]:
    """
    Module-level convenience function for pipeline integration.
    Logs the decision and optionally stores the hypothesis.
    Returns a dict with audit_hash and memory_id.
    """
    agent = get_agent()
    audit_hash = agent.log_decision(decision)
    memory_id = None
    if hypothesis:
        memory_id = agent.store_hypothesis(hypothesis)
    return {"audit_hash": audit_hash, "memory_id": memory_id}


# SD-7 Gap #2: Run chain integrity check on module load.
# If sd_log.jsonl exists and is tampered, print a critical alert.
startup_sd_chain_health_check()


# =============================================================================
# SMOKE TEST
# =============================================================================

if __name__ == "__main__":
    import tempfile, shutil

    print("=== A12 Smoke Test ===\n")

    # Use temp dir so smoke test doesn't pollute real data files
    tmp = Path(tempfile.mkdtemp())
    import agents.a12_audit as a12_mod
    orig_audit = a12_mod.AUDIT_LOG_PATH
    orig_mem   = a12_mod.COGNITIVE_MEMORY_PATH
    orig_shad  = a12_mod.SHADOW_RESULTS_PATH
    a12_mod.AUDIT_LOG_PATH        = tmp / "audit_log.jsonl"
    a12_mod.COGNITIVE_MEMORY_PATH = tmp / "cognitive_memory.jsonl"
    a12_mod.SHADOW_RESULTS_PATH   = tmp / "shadow_results.json"

    try:
        agent = A12AuditAgent()

        # Create test decision
        dec = Decision.model_validate({
            "decision_id": "DEC-2026-SMOKE-01",
            "hypothesis_id": "H-2026-SMOKE-01",
            "action_taken": "BLOCK_IP",
            "risk_score": 0.82,
            "blast_radius_score": 0.41,
        })

        # 1. Log decision
        h1 = agent.log_decision(dec)
        print(f"1. Logged decision. audit_hash={h1[:12]}...")

        # Chain a second decision
        dec2 = Decision.model_validate({
            "decision_id": "DEC-2026-SMOKE-02",
            "hypothesis_id": "H-2026-SMOKE-02",
            "action_taken": "ISOLATE_ENDPOINT",
            "risk_score": 0.91,
            "blast_radius_score": 0.60,
        })
        h2 = agent.log_decision(dec2)
        print(f"2. Logged second decision. audit_hash={h2[:12]}...")

        # 2. Verify chain
        result = agent.verify_chain()
        print(f"3. Chain valid: {result['valid']}  ({result['entries_checked']} entries)")
        assert result["valid"], "Chain should be valid"

        # 3. Store hypothesis
        hyp = Hypothesis.model_validate({
            "goal": "APT41 RCE via Log4Shell on CBSE-WebSvr-01",
            "confidence": 0.91,
            "supporting_evidence": ["EV-001", "EV-002"],
            "mitre_chain": ["T1595", "T1190", "T1059"],
            "state": "CONFIRMED",
            "mission_impact": "student_exam_records - CRITICAL",
        })
        mid = agent.store_hypothesis(hyp, tags=["apt41", "log4shell", "cbse"])
        print(f"4. Stored hypothesis. memory_id={mid[:12]}...")

        # 4. Recall
        recalled = agent.recall_hypotheses(keyword="log4shell")
        print(f"5. Recalled {len(recalled)} hypothesis(es) by keyword 'log4shell'")
        assert len(recalled) == 1

        # 5. Confidence decay (reusing Ticket 1)
        decayed = agent.apply_confidence_decay(hyp)
        print(f"6. Confidence decay (0h elapsed): {decayed:.4f} (should equal {hyp.confidence})")

        # 6. Human correction - CONFIRM (immediate, no consensus needed)
        r = agent.apply_human_correction(dec, "CONFIRM", "SENIOR", "analyst_001")
        print(f"7. CONFIRM: status={r['status']}  consensus={r['consensus_score']}")
        assert r["status"] == "APPLIED"

        # 7. REVOKE — single junior analyst: consensus < 0.7 → PENDING
        r2 = agent.apply_human_correction(dec2, "REVOKE", "JUNIOR", "analyst_002")
        print(f"8. REVOKE (junior alone): status={r2['status']}  consensus={r2['consensus_score']:.3f}")
        assert r2["status"] == "PENDING_CONSENSUS"

        # Senior agrees → consensus reaches threshold
        r3 = agent.apply_human_correction(dec2, "REVOKE", "SENIOR", "analyst_003")
        print(f"9. REVOKE (senior joins): status={r3['status']}  consensus={r3['consensus_score']:.3f}")
        assert r3["status"] == "APPLIED"

        # 8. Shadow promotion
        live = {"precision": 0.85, "recall": 0.82, "f1": 0.83}
        good_shadow = {"precision": 0.87, "recall": 0.84, "f1": 0.85}
        bad_shadow  = {"precision": 0.70, "recall": 0.60, "f1": 0.65}
        assert agent.should_promote_shadow_model(good_shadow, live) is True
        assert agent.should_promote_shadow_model(bad_shadow, live)  is False
        print("10. Shadow promotion: good=PROMOTE, bad=REJECT ?")

        # 9. Stats
        stats = agent.get_stats()
        print(f"11. Stats: {stats}")
        assert stats["chain_valid"] is True
        assert stats["audit_log_entries"] >= 3  # dec, dec2, correction log entries

        print("\n=== All A12 smoke tests passed! ===")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        a12_mod.AUDIT_LOG_PATH        = orig_audit
        a12_mod.COGNITIVE_MEMORY_PATH = orig_mem
        a12_mod.SHADOW_RESULTS_PATH   = orig_shad
