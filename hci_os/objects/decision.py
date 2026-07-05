"""
objects/decision.py
Decision Object — Captures the action taken for a hypothesis.

This is the permanent record of what HCI-OS decided and why.
It's stored in the immutable audit log with SHA-256 chaining.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_serializer, ConfigDict
import hashlib
import json

class Decision(BaseModel):
    """A versioned, auditable decision."""
    
    # ─── Core Identity ──────────────────────────────────────────────────
    decision_id: str = Field(..., description="Unique ID, e.g., DEC-2026-000812")
    hypothesis_id: str = Field(..., description="Which hypothesis this decision relates to")
    created_at: datetime = Field(default_factory=datetime.now)
    
    # ─── Action ─────────────────────────────────────────────────────────
    action_taken: str = Field(
        ...,
        description="Action executed: BLOCK_IP, ISOLATE_ENDPOINT, REVOKE_SESSION, etc."
    )
    human_reviewed: bool = Field(default=False, description="Was this reviewed by a human?")
    reviewer_id: Optional[str] = Field(None, description="Analyst ID if human_reviewed=True")
    
    # ─── Reversibility ──────────────────────────────────────────────────
    reversible: bool = Field(default=True, description="Can this action be rolled back?")
    reversed_at: Optional[datetime] = Field(None, description="If reversed, when?")
    reversed_by: Optional[str] = Field(None, description="Who reversed it?")
    
    # ─── Risk Assessment ──────────────────────────────────────────────────
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Computed Risk = L×I×E×C")
    blast_radius_score: float = Field(..., ge=0.0, le=1.0, description="Graph-based blast radius")
    
    # ─── Audit Chain ────────────────────────────────────────────────────────
    audit_chain_prev: Optional[str] = Field(
        None,
        description="SHA-256 hash of the previous Decision Object. Forms immutable chain."
    )
    audit_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of this Decision Object (computed, not stored)."
    )
    
    # ─── Versioning ────────────────────────────────────────────────────
    version: int = Field(default=1, description="Version number. Incremented on correction.")
    supersedes_decision_id: Optional[str] = Field(
        None,
        description="If this is a correction, which Decision ID it supersedes."
    )
    
    # ─── Serialization ────────────────────────────────────────────────────
    def to_json(self) -> str:
        return self.model_dump_json(exclude_none=True, exclude={"audit_hash"})
    
    @classmethod
    def from_json(cls, json_str: str) -> "Decision":
        return cls.model_validate_json(json_str)
    
    # ─── Business Logic ──────────────────────────────────────────────────
    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of this Decision Object (excluding audit_hash).
        Chain linking: store previous hash in audit_chain_prev, set this as audit_hash.
        """
        # Exclude audit_hash to prevent self-reference
        data = self.model_dump(exclude={"audit_hash"})
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def chain(self, previous_decision: Optional["Decision"]) -> "Decision":
        """
        Chain this decision to a previous one.
        Returns a new Decision instance with audit_chain_prev set.
        """
        new_decision = self.model_copy()
        if previous_decision:
            new_decision.audit_chain_prev = previous_decision.compute_hash()
        else:
            new_decision.audit_chain_prev = None
        return new_decision
    
    def create_correction(self, new_action: str, reviewer_id: str) -> "Decision":
        """
        Create a corrected version of this decision.
        Used when a human marks a False Positive.
        """
        correction = self.model_copy()
        correction.decision_id = f"{self.decision_id}-CORR"
        correction.action_taken = new_action
        correction.human_reviewed = True
        correction.reviewer_id = reviewer_id
        correction.version = self.version + 1
        correction.supersedes_decision_id = self.decision_id
        return correction
    
    model_config = ConfigDict()

    @field_serializer('created_at', 'reversed_at')
    def serialize_datetimes(self, v: Optional[datetime]) -> Optional[str]:
        return v.isoformat() + "Z" if v is not None else None
