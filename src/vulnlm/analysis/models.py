"""Model registry — the four tiers, pinned.

A Python dict rather than a YAML file: there are four entries, they change once
(when the Qwen tag question resolves), and this way they are type-checked and
serialize into RunMeta.config_snapshot for free. No parser, no dependency, no
second schema to keep in sync.

Rules that make RQ4 answerable, and are easy to break by editing this file:
  - ONE dense family across S/M/L. Mixing Qwen/Mistral/Llama would measure
    training recipe, not scale.
  - ONE quantization (Q4_K_M) across S/M/L, or quantization co-varies with size
    and becomes an uncontrolled confound.
  - No MoE in the ladder: ~3B active parameters is not comparable to a dense
    32B on a parameter-count axis.
"""

from vulnlm.schema import ModelSpec

# UNVERIFIED: confirm these Ollama tags exist and pull cleanly before Phase 2.
# If any rung is missing, move the whole ladder to Qwen2.5-Coder 7B/14B/32B —
# older, but complete and fully dense. A missing rung breaks the ladder; a
# slightly dated family does not.
MODELS: dict[str, ModelSpec] = {
    "S": ModelSpec(
        model_id="S",
        tag="qwen3-coder:7b-instruct-q4_K_M",
        quantization="Q4_K_M",
        backend="gpu",  # local, RX 6650 XT 8 GB
    ),
    "M": ModelSpec(
        model_id="M",
        tag="qwen3-coder:14b-instruct-q4_K_M",
        quantization="Q4_K_M",
        backend="gpu",  # rented 24 GB
    ),
    "L": ModelSpec(
        model_id="L",
        tag="qwen3-coder:32b-instruct-q4_K_M",
        quantization="Q4_K_M",
        backend="gpu",  # rented 24 GB
    ),
    "A": ModelSpec(
        model_id="A",
        tag="claude-sonnet-5",
        backend="api",
    ),
}
