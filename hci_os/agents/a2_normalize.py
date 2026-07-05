"""
A2: Normalizer & Context Agent (Layer 2)
Normalizes raw logs into Evidence Objects with OT/Indian context.
Indian context: exam season (CBSE Mar/JEE Jan), Govt year-end (Mar 31), election period.
"""


def process(raw_data: dict) -> dict:
    """Normalize raw log into an Evidence Object."""
    # TODO: Implement in Ticket 2
    return {"evidence_id": "EV-0001", "context": {}}
