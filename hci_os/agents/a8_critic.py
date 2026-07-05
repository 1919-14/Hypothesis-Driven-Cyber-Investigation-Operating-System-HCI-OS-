"""
A8: Critic / Skeptic Agent (Layer 7, LLM-3)
Challenges hypotheses, finds counter-evidence, runs counterfactuals.
Uses SEPARATE LLM instance (no shared bias with LLM-1/LLM-2).
Challenges: counter-evidence check, counterfactual ("what must be true for FP?"),
            adversarial simulation ("could attacker fake this?").
SIMULATED in MVP — described in slides, shown with diagram.
LLM-3: Llama 3.x 8B (vanilla) via Ollama.
"""


def process(hypothesis: dict) -> dict:
    """Find evidence against the hypothesis and return critic verdict."""
    # TODO: Implement in Ticket 13
    return hypothesis
