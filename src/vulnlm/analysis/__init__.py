"""Stage 2 — LLM analysis.

One code path drives every model tier through an OpenAI-compatible interface.
Identical prompt, chunking, scrubbing, temperature and schema across all models.

MUST NEVER import GroundTruth. If this stage can see the label, the experiment
is dead.

Emits: AnalysisRecord rows, appended to results/raw/<run_id>/.
"""
