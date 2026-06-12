#!/usr/bin/env python3
"""Lightweight script heuristic shared by the Fase 1 tooling.

detect_script(text) -> "cyrillic" | "latin" | "other"

Counts letters per script and returns the dominant one; ties resolve in the
order cyrillic > latin > other (the corpus is ~72% Cyrillic, so when a mixed
text is balanced the Cyrillic reading is the safer bucket). Texts with no
letters at all are "other".

This is intentionally NOT language identification — it only buckets metrics
and dataset stats by writing system (roadmap F1.11 "por idioma"). One shared
implementation so build_dataset.py stats and train_baseline.py eval splits
can never disagree.
"""

CYRILLIC_RANGES = (
    ("Ѐ", "ӿ"),  # Cyrillic
    ("Ԁ", "ԯ"),  # Cyrillic Supplement
)


def detect_script(text: str) -> str:
    """Bucket text as cyrillic / latin / other by dominant letter script."""
    if not text:
        return "other"
    cyr = lat = other = 0
    for ch in text:
        if not ch.isalpha():
            continue
        if any(lo <= ch <= hi for lo, hi in CYRILLIC_RANGES):
            cyr += 1
        elif ch.isascii():
            lat += 1
        else:
            other += 1
    if cyr == lat == other == 0:
        return "other"
    best = max(cyr, lat, other)
    if cyr == best:
        return "cyrillic"
    if lat == best:
        return "latin"
    return "other"
