"""
objects/hypothesis.py
Hypothesis Object — HCI-OS's core investigation unit.

Instead of scoring events in isolation, HCI-OS maintains competing hypotheses
about what an attacker is trying to do. Every new piece of Evidence either
strengthens or weakens each hypothesis.
"""

from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, field_validator, field_serializer, ConfigDict
import math
import uuid

class CompetingHypothesis(BaseModel):
    """A single competing explanation within the main hypothesis."""
    goal: str = Field(..., description="Description of the alternate explanation")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Belief in this alternate")
    evidence_refs: List[str] = Field(default_factory=list, description="Evidence IDs supporting this alternate")

class PredictedMove(BaseModel):
    """A predicted next move by the attacker."""
    ttp: str = Field(..., description="MITRE ATT&CK technique ID, e.g., T1003")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this prediction")
    preventive_action: Optional[str] = Field(None, description="Action to block this move, e.g., block_lsass_access")

class WorldModel(BaseModel):
    """Mission-aware context for the target asset."""
    industry: str = Field(..., description="education, healthcare, power_grid, etc.")
    mission: str = Field(..., description="Exam Records, Patient Monitoring, Grid Stability, etc.")
    criticality: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    safety_constraints: Dict[str, bool] = Field(
        default_factory=lambda: {"can_reboot": True, "auto_isolate_allowed": True},
        description="Constraints: {'can_reboot': bool, 'auto_isolate_allowed': bool}"
    )

class Hypothesis(BaseModel):
    """A full investigation hypothesis with competing explanations."""
    
    # ─── Core Identity ──────────────────────────────────────────────────
    hypothesis_id: str = Field(
        default_factory=lambda: f"H-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}",
        description="Unique ID, e.g., H-2026-0031"
    )
    created_at: datetime = Field(default_factory=datetime.now)
    last_updated: datetime = Field(default_factory=datetime.now)
    
    # ─── Hypothesis Definition ─────────────────────────────────────────
    goal: str = Field(..., description="What the attacker is trying to do, e.g., RCE via Log4Shell")
    state: str = Field(
        default="ACTIVE_INVESTIGATION",
        description="ACTIVE_INVESTIGATION | CONFIRMED | REJECTED | CONTAINED"
    )
    
    # ─── Evidence Linking ──────────────────────────────────────────────
    supporting_evidence: List[str] = Field(
        default_factory=list,
        description="Evidence IDs that support this hypothesis"
    )
    contradicting_evidence: List[str] = Field(
        default_factory=list,
        description="Evidence IDs that contradict this hypothesis (populated by A8 Critic)"
    )
    
    # ─── Bayesian Confidence ────────────────────────────────────────────
    confidence: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Bayesian posterior probability P(H₁|E) that this hypothesis is correct"
    )
    uncertainty: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Uncertainty in this hypothesis (epistemic + aleatoric)"
    )
    confidence_decay_rate: float = Field(
        default=0.02,
        ge=0.0,
        le=1.0,
        description="Decay rate (λ) per hour. Stale evidence loses influence."
    )
    
    # ─── Competing Hypotheses ───────────────────────────────────────────
    competing_hypotheses: List[CompetingHypothesis] = Field(
        default_factory=list,
        description="Alternate explanations. Example: H2=Admin (0.06), H3=Backup (0.03), H4=RedTeam (0.01)"
    )
    
    # ─── MITRE & Prediction ─────────────────────────────────────────────
    mitre_chain: List[str] = Field(
        default_factory=list,
        description="Observed TTP chain, e.g., ['T1595', 'T1190', 'T1059']"
    )
    predicted_next_moves: List[PredictedMove] = Field(
        default_factory=list,
        description="Predicted next TTPs with preventive actions"
    )
    mission_impact: str = Field(
        default="",
        description="Human-readable impact: 'student_exam_records — CRITICAL'"
    )
    
    # ─── World Model ────────────────────────────────────────────────────
    world_model: Optional[WorldModel] = Field(
        None,
        description="Mission-aware context for the target asset. Drives safety constraints."
    )
    
    # ─── Campaign Genome ────────────────────────────────────────────────
    campaign_genome: Optional[Dict[str, Any]] = Field(
        None,
        description="Genome match result: {'matched_campaign': 'APT41', 'confidence': 0.87, 'predicted_next': 'T1003'}"
    )
    
    # ─── Timeline ──────────────────────────────────────────────────────
    timeline: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Chronological events: [{'time': '03:14:22', 'event': 'HTTP request to /cgi-bin/', 'type': 'observation'}]"
    )
    
    # ─── Validation ────────────────────────────────────────────────────
    @field_validator('state')
    @classmethod
    def validate_state(cls, v: str) -> str:
        allowed = {"ACTIVE_INVESTIGATION", "CONFIRMED", "REJECTED", "CONTAINED"}
        if v not in allowed:
            raise ValueError(f"state must be one of {allowed}")
        return v
    
    # ─── Serialization ────────────────────────────────────────────────────
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return self.model_dump_json(exclude_none=True)
    
    @classmethod
    def from_json(cls, json_str: str) -> "Hypothesis":
        """Deserialize from JSON string."""
        return cls.model_validate_json(json_str)
    
    # ─── Business Logic ──────────────────────────────────────────────────
    def confidence_decay(self, hours_since_update: float) -> float:
        """
        Compute decayed confidence per R3 #59.
        In a real APT investigation, old evidence becomes less valuable over time.
        This prevents stale hypotheses from persisting indefinitely.
        
        Example:
            hypothesis.confidence = 0.91
            hours_since_update = 4
            decay_rate = 0.02
            result = 0.91 * exp(-0.02 * 4) = 0.91 * exp(-0.08) = 0.91 * 0.923 = 0.84
        """
        if hours_since_update < 0:
            raise ValueError("hours_since_update cannot be negative")
        return self.confidence * math.exp(-self.confidence_decay_rate * hours_since_update)
    
    def add_timeline_event(self, time_str: str, event: str, event_type: str) -> None:
        """Append an event to the investigation timeline."""
        self.timeline.append({
            "time": time_str,
            "event": event,
            "type": event_type
        })
        self.last_updated = datetime.now()
    
    def get_primary_hypothesis(self) -> str:
        """Return the goal of the highest-confidence competing hypothesis (or self)."""
        if not self.competing_hypotheses:
            return self.goal
        # Add self as a candidate
        candidates = [{"goal": self.goal, "confidence": self.confidence}]
        candidates.extend([h.model_dump() for h in self.competing_hypotheses])
        best = max(candidates, key=lambda x: x["confidence"])
        return best["goal"]
    
    model_config = ConfigDict()

    @field_serializer('created_at', 'last_updated')
    def serialize_datetimes(self, v: datetime) -> str:
        return v.isoformat() + "Z"
