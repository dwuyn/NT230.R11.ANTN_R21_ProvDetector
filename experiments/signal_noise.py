"""Which provenance signals separate malicious from benign instances?

Uses cached top-K paths (no retraining) and the benign frequency DB.  Reports
feature distributions, single-feature AUROC, and the share of common (noisy)
edges in malicious vs benign graphs.
"""
from __future__ import annotations

import pickle
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from src.experiment import _split
from src.graph.build import FrequencyDB, Trace
from src.ingest.schema import Scenario

CACHE = Path("experiments/results/cache")
SEED = 20261025
K = 20


def features(paths, db: FrequencyDB, trace: Trace) -> dict:
    if not paths:
        return {"n_paths": 0, "min_log": 0.0, "mean_log": 0.0, "start_edges": 0, "sockets": 0, "file_edges": 0, "mean_len": 0.0}
    logs = [p.log_rarity for p in paths]
    rels = Counter()
    sockets = 0
    files = 0
    for p in paths:
        for _src, rel, dst, _ts in p.edges:
            rels[int(rel)] += 1
            label = trace.node_label(dst)
            if label.startswith("S:"):
                sockets += 1
            elif label.startswith("F:"):
                files += 1
    return {
        "n_paths": len(paths),
        "min_log": float(np.min(logs)),
        "mean_log": float(np.mean(logs)),
        "start_edges": rels.get(0, 0),
        "sockets": sockets,
        "file_edges": files,
        "mean_len": float(np.mean([len(p.edges) for p in paths])),
    }


def common_edge_fraction(trace: Trace, instance: int, db: FrequencyDB, cutoff: float = 0.03) -> float:
    graph = trace.edges(instance)
    if not len(graph):
        return 0.0
    common = 0
    for src, rel, dst in zip(graph.src, graph.rel, graph.dst):
        key = trace.edge_key(int(src), int(rel), int(dst))
        if db.edge_counts.get(key, 0) / max(1, db.n) >= cutoff:
            common += 1
    return common / len(graph)


def main() -> int:
    benign_trace = Trace.load("data/clean", "WS12", Scenario.BENIGN)
    anomaly_trace = Trace.load("data/clean", "WS12", Scenario.ANOMALY)
    train_ids = [i for i in benign_trace.instance_ids if len(benign_trace.own_events(i).get("ts", []))]
    split = _split(train_ids, np.random.default_rng(SEED), 0.7, 0.15)
    db = FrequencyDB.build(benign_trace, split["train"])

    with (CACHE / f"WS12_WS12_k20_L5_seed{SEED}_benign.pkl").open("rb") as handle:
        benign_paths = pickle.load(handle)
    with (CACHE / f"WS12_WS12_k20_L5_seed{SEED}_anomaly.pkl").open("rb") as handle:
        anomaly_paths = pickle.load(handle)

    benign_ids = [i for i in benign_paths if benign_paths[i]]
    mal_ids = [i for i in anomaly_paths if anomaly_paths[i] and anomaly_paths[i][0].label == 1]
    benign_features = {i: features(benign_paths[i], db, benign_trace) for i in benign_ids}
    mal_features = {i: features(anomaly_paths[i], db, anomaly_trace) for i in mal_ids}

    names = ["n_paths", "min_log", "mean_log", "start_edges", "sockets", "file_edges", "mean_len"]
    lines = ["# Signal and noise analysis — WS12", "", f"Malicious instances: {len(mal_ids)}; benign test: {len(benign_ids)}.", "", "## Single-feature separation", "", "| Feature | Malicious median | Benign median | AUROC |", "|---|---|---|---|"]
    for name in names:
        mal_values = np.array([mal_features[i][name] for i in mal_ids], dtype=float)
        benign_values = np.array([benign_features[i][name] for i in benign_ids], dtype=float)
        y = np.r_[np.ones(len(mal_values)), np.zeros(len(benign_values))]
        x = np.r_[mal_values, benign_values]
        if name in ("min_log", "mean_log"):
            x = -x  # lower regularity = more anomalous
        auc = roc_auc_score(y, x) if len(set(y)) > 1 else 0.5
        lines.append(f"| {name} | {np.median(mal_values):.3f} | {np.median(benign_values):.3f} | {auc:.3f} |")

    lines += ["", "## Relation mix in selected paths", "", "| Relation | Malicious share | Benign share |", "|---|---|---|"]
    def rel_mix(features_map):
        totals = Counter()
        for value in features_map.values():
            for name in ("start_edges", "sockets", "file_edges"):
                totals[name] += value[name]
        return totals
    mal_mix, benign_mix = rel_mix(mal_features), rel_mix(benign_features)
    for label in ("start_edges", "sockets", "file_edges"):
        lines.append(f"| {label} | {mal_mix[label] / max(1, sum(mal_mix.values())):.3f} | {benign_mix[label] / max(1, sum(benign_mix.values())):.3f} |")

    mal_noise = [common_edge_fraction(anomaly_trace, i, db) for i in mal_ids]
    benign_noise = [common_edge_fraction(benign_trace, i, db) for i in benign_ids]
    lines += ["", "## Noise level (edges already seen in ≥3% of benign training instances)", "",
              f"- Malicious graphs: median {np.median(mal_noise):.3f} common edges (IQR {np.percentile(mal_noise,25):.3f}–{np.percentile(mal_noise,75):.3f}).",
              f"- Benign graphs: median {np.median(benign_noise):.3f} common edges (IQR {np.percentile(benign_noise,25):.3f}–{np.percentile(benign_noise,75):.3f}).",
              "", "`n_paths` is a coverage artifact (malicious graphs are larger), not a deployable feature. Malicious graphs are dominated by rare edges; the signal is not a single relation but the *combination* of a rare process chain (START) and rare file/socket sinks. Benign graphs retain a substantial common-edge core, which is why frequency-only baselines also work well.",
              "", "## Path overlap", "",
              "- Malicious selected paths with a signature also present in benign train: 0 (see `path-sanity.md`)."]
    out = Path("experiments/results/signal-noise.md")
    out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
