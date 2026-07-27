"""Stage 3 — reporting. Deterministic renderers over records.jsonl.

SARIF 2.1.0 is the predefined machine-readable format; Markdown is the human
view for supervisor checkpoints. Both are pure functions of the records and add
no information the model did not supply. Anything beyond these two (HTML, PDF)
is pandoc's job, not ours.

Sibling of `eval` — reads the same file, does not depend on it.
"""
