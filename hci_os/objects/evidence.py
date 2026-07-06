"""
objects/evidence.py
Evidence Object — The atomic unit of observation for HCI-OS.

Every log, network flow, or OT sensor reading is normalized into this schema.
It flows through all layers (A2 → A3 → A4 → ...) and is enriched at each step.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator, field_serializer, ConfigDict
import hashlib
import json

class Evidence(BaseModel):
    """Normalized evidence from a telemetry source."""
    
    # ─── Core Identity ──────────────────────────────────────────────────
    evidence_id: str = Field(..., description="Unique ID, e.g., EV-2026-004471")
    timestamp: datetime = Field(..., description="UTC timestamp of the event")
    source: str = Field(..., description="Source system: web_access_log, netflow, scada, auth, etc.")
    asset_id: str = Field(..., description="Target asset: CBSE-WebSvr-01, DB-01, etc.")
    
    # ─── Normalized Payload (Adapted to your dataset) ──────────────
    normalized: Dict[str, Any] = Field(
        ...,
        description="Normalized fields: {'src_ip', 'dst_ip', 'path', 'method', 'user_agent', 'status', 'bytes', 'protocol', ...}"
    )
    
    # ─── Fingerprints (Layer 3 Fast Path) ─────────────────────────────
    content_fingerprint: str = Field(
        ...,
        description="SHA-256 of the canonicalized normalized payload. Used for exact-match (Path 1)."
    )
    behavior_embedding: List[float] = Field(
        default_factory=lambda: [0.0] * 256,
        description="256-dim dense vector representing this event's behavior. Used for semantic/fuzzy match (Path 2)."
    )
    
    # ─── Context & Enrichment (Added by A2) ──────────────────────────
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Enriched context: {'criticality': 'HIGH', 'mission': 'exam_records', 'time_of_day': 'off_hours', 'indian_context': {...}, 'ot_context': {...}}"
    )
    
    # ─── Confidence & Uncertainty ──────────────────────────────────────
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Calibrated confidence (0-1) that this evidence is anomalous. Starts at 0.5, updated by A4/A6."
    )
    uncertainty: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Combined epistemic + aleatoric uncertainty (0-1). High = model doesn't know."
    )
    
    # ─── Provenance ────────────────────────────────────────────────────
    provenance: str = Field(
        default="ingestion",
        description="Which agent created/modified this: ingestion, A2, A4, A6, etc."
    )
    
    # ─── Validation ────────────────────────────────────────────────────
    @field_validator('content_fingerprint')
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        """Ensure content_fingerprint is a valid SHA-256 hex string."""
        if len(v) != 64:
            raise ValueError(f"Invalid SHA-256 hash length: {len(v)} (expected 64)")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("content_fingerprint must be a hex string")
        return v
    
    @field_validator('behavior_embedding')
    @classmethod
    def validate_embedding_length(cls, v: List[float]) -> List[float]:
        """Ensure behavior_embedding is exactly 256 dimensions."""
        if len(v) != 256:
            # Allow stub initialization but warn
            if len(v) == 1 and v[0] == 0.0:
                return [0.0] * 256
            raise ValueError(f"behavior_embedding must be exactly 256 dimensions (got {len(v)})")
        return v
    
    # ─── Serialization ────────────────────────────────────────────────────
    def to_json(self) -> str:
        """Serialize to JSON string (for storage/transmission)."""
        return self.model_dump_json(exclude_none=True)
    
    @classmethod
    def from_json(cls, json_str: str) -> "Evidence":
        """Deserialize from JSON string."""
        return cls.model_validate_json(json_str)
    
    # ─── Business Logic ──────────────────────────────────────────────────
    def compute_content_fingerprint(self) -> str:
        """
        Compute SHA-256 of the canonicalized normalized payload.
        Call this before setting content_fingerprint.
        """
        canonical = json.dumps(self.normalized, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    model_config = ConfigDict()

    @field_serializer('timestamp')
    def serialize_timestamp(self, v: datetime) -> str:
        iso = v.isoformat()
        # Normalize UTC offset representations to 'Z' suffix
        if iso.endswith("+00:00"):
            return iso[:-6] + "Z"
        if v.tzinfo is None:
            return iso + "Z"
        return iso
