"""Scoring. The only place ground truth and model output are allowed to meet.

Detection P/R/F1, CWE-classification accuracy, localisation, outcome rates,
calibration (ECE), and the same metrics over the static-analyser baselines.

A bug here does not crash — it produces plausible wrong numbers that end up in
the thesis. This is the one module worth testing.
"""
