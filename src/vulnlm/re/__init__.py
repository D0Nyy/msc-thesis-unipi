"""Stage 1 — recover code, then normalise it.

Ghidra (C/C++ -> F2), ILSpy (C#), Vineflower (Java), pycdc (Python .pyc), and
plain source for F0.

Scrubbing and chunking live here too. The protocol presents normalisation as
part of Stage 1 rather than a fourth stage, so the code follows suit. Note that scrubbing also applies to F0, which was never
decompiled — uniformity across tiers is the whole point.

Emits: Chunk records.
"""
