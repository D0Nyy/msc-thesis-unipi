"""Model registry — the four tiers, pinned.

A Python dict rather than a YAML file: there are four entries, they are now
settled, and this way they are type-checked and serialize into
RunMeta.config_snapshot for free. No parser, no dependency, no second schema to
keep in sync.

Rules that make RQ4 answerable, and are easy to break by editing this file:
  - ONE dense family across S/M/L. Mixing Qwen/Mistral/Llama would measure
    training recipe, not scale.
  - ONE quantization (Q4_K_M) across S/M/L, or quantization co-varies with size
    and becomes an uncontrolled confound.
  - No MoE in the ladder: ~3B active parameters is not comparable to a dense
    32B on a parameter-count axis.
"""

from vulnlm.schema import ModelSpec

# VERIFIED 2026-07-27 against the Ollama library registry.
#
# The ladder is Qwen2.5-Coder, not Qwen3-Coder. Qwen3-Coder publishes only
# 30b-a3b and 480b-a35b — both MoE, and therefore both excluded by the no-MoE
# rule above. There is no dense Qwen3-Coder rung at any size, so the fallback
# was taken in full rather than per-rung. Qwen2.5-Coder is a complete, fully
# dense 7B/14B/32B family at a single quantization, which is what RQ4 needs;
# being a generation older is the cheaper price.
#
# Context window is 32K on every rung (Qwen3-Coder's 256K does not apply here).
# Expect a non-trivial context_overflow rate at tier S — protocol §8.2 treats
# that as a reportable result, not an error.
#
# Digests are pinned because the tag alone is insufficient provenance, and at
# the L rung it is actively misleading: Ollama publishes no
# `32b-instruct-q4_K_M` tag. The bare `:32b` IS the instruct build at q4_K_M
# (20 GB, digest b92d6a0bd47e — distinct from `32b-base`'s 9218192e3d91), but
# the tag string says none of that. Verify the digest after pulling; if it has
# moved, the registry was re-tagged and the run is not comparable to earlier
# ones.
MODELS: dict[str, ModelSpec] = {
    "S": ModelSpec(
        model_id="S",
        tag="qwen2.5-coder:7b-instruct-q4_K_M",
        digest="dae161e27b0e",  # 4.7 GB
        quantization="Q4_K_M",
        backend="gpu",  # local, RX 6650 XT 8 GB
    ),
    "M": ModelSpec(
        model_id="M",
        tag="qwen2.5-coder:14b-instruct-q4_K_M",
        digest="9ec8897f747e",  # 9.0 GB — exceeds the 8 GB local card
        quantization="Q4_K_M",
        backend="gpu",  # rented 24 GB
    ),
    "L": ModelSpec(
        model_id="L",
        # No `32b-instruct-q4_K_M` tag exists; see the note above.
        tag="qwen2.5-coder:32b",
        digest="b92d6a0bd47e",  # 20 GB
        quantization="Q4_K_M",
        backend="gpu",  # rented 24 GB
    ),
    "A": ModelSpec(
        model_id="A",
        tag="claude-sonnet-5",
        backend="api",
    ),
}
