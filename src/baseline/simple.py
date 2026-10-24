"""Simple baselines required by the R21 protocol."""
from __future__ import annotations

import numpy as np

from src.graph.build import FrequencyDB, Trace

UI_HEAVY = {
    "winword", "excel", "powerpnt", "outlook", "acrobat", "acrord32",
    "iexplore", "chrome", "firefox", "mspaint", "notepad", "wordpad", "wmplayer",
}
INTERPRETERS = {
    "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "certutil", "wmic", "bitsadmin",
}


def rule_predict(trace: Trace, instance: int) -> int:
    names = trace.family_names(instance)
    root = str(trace.instances.loc[instance, "name"])
    return int(root in UI_HEAVY and bool(names & INTERPRETERS))


def whitelist_fractions(
    trace: Trace,
    instances: list[int],
    db: FrequencyDB,
    support_cutoff: float,
) -> dict[int, float]:
    """Fraction of graph edges that are not covered by the benign whitelist."""
    fractions = {}
    for instance in instances:
        graph = trace.edges(instance)
        total = len(graph)
        if not total:
            fractions[int(instance)] = 0.0
            continue
        novel = 0
        for src, rel, dst in zip(graph.src, graph.rel, graph.dst):
            key = trace.edge_key(int(src), int(rel), int(dst))
            support = db.edge_counts.get(key, 0) / max(1, db.n)
            if support < support_cutoff:
                novel += 1
        fractions[int(instance)] = novel / total
    return fractions


def whitelist_decisions(
    trace: Trace,
    instances: list[int],
    db: FrequencyDB,
    support_cutoff: float,
    fraction_threshold: float = 0.0,
) -> dict[int, int]:
    fractions = whitelist_fractions(trace, instances, db, support_cutoff)
    return {i: int(value > fraction_threshold) for i, value in fractions.items()}


def calibrate_whitelist(
    trace: Trace,
    val_instances: list[int],
    db: FrequencyDB,
    support_cutoff: float = 0.03,
    target_fpr: float = 0.05,
) -> tuple[float, float, dict]:
    """Whitelist at p=3% (paper), with a fraction threshold set on benign val."""
    fractions = whitelist_fractions(trace, val_instances, db, support_cutoff)
    values = np.asarray(list(fractions.values()), dtype=float)
    threshold = float(np.quantile(values, 1.0 - target_fpr)) if len(values) else 0.0
    fpr = float(np.mean(values > threshold)) if len(values) else 0.0
    return threshold, fpr, {"support_cutoff": support_cutoff, "val_fpr": fpr}


def anomaly_score_decisions(
    trace: Trace,
    instances: list[int],
    min_log_rarity: dict[int, float],
    threshold: float,
) -> dict[int, int]:
    return {int(i): int(min_log_rarity.get(int(i), 0.0) < threshold) for i in instances}
