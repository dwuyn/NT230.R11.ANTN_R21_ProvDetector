"""Post-hoc frequency-only baseline computed from cached experiment configs.

The paper's whitelist baseline degenerates on these file-heavy traces: almost
every instance contains at least one path unique to it, so the 95th percentile
of the novel-edge fraction is 1.0.  This script adds a continuous frequency
score: mean(-log support(edge)) over the instance graph, calibrated on benign
validation at the same 5% target.  It reuses the existing result JSONs and does
not retrain doc2vec.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from src.experiment import _decision_metrics, _split
from src.graph.build import FrequencyDB, Trace
from src.ingest.schema import Scenario


def instance_scores(trace: Trace, instances: list[int], db: FrequencyDB) -> dict[int, float]:
    scores = {}
    for instance in instances:
        graph = trace.edges(instance)
        if not len(graph):
            scores[int(instance)] = 0.0
            continue
        values = []
        for src, rel, dst in zip(graph.src, graph.rel, graph.dst):
            key = trace.edge_key(int(src), int(rel), int(dst))
            support = (db.edge_counts.get(key, 0) + 1) / (db.n + 2)
            values.append(-np.log(support))
        scores[int(instance)] = float(np.mean(values))
    return scores


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+")
    parser.add_argument("--out-dir", default="experiments/results")
    args = parser.parse_args()
    for path in map(Path, args.results):
        data = json.loads(path.read_text())
        cfg = data["config"]
        seed = cfg["seed"]
        train_dataset, test_dataset = cfg["train_dataset"], cfg["test_dataset"]
        train_trace = Trace.load("data/clean", train_dataset, Scenario.BENIGN)
        test_benign = Trace.load("data/clean", test_dataset, Scenario.BENIGN)
        test_anomaly = Trace.load("data/clean", test_dataset, Scenario.ANOMALY)
        rng = np.random.default_rng(seed)
        train_ids = [i for i in train_trace.instance_ids if len(train_trace.own_events(i).get("ts", []))]
        split = _split(train_ids, rng, 0.7, 0.15)
        db = FrequencyDB.build(train_trace, split["train"])

        val_scores = instance_scores(train_trace, split["val"], db)
        threshold = float(np.quantile(list(val_scores.values()), 0.95))
        val_decisions = {i: int(v > threshold) for i, v in val_scores.items()}
        val_fpr = float(np.mean(list(val_decisions.values()))) if val_decisions else 0.0

        if train_dataset == test_dataset:
            benign_test_ids = split["test"]
        else:
            benign_test_ids = [i for i in test_benign.instance_ids if len(test_benign.own_events(i).get("ts", []))]
        anomaly_ids = [i for i in test_anomaly.instance_ids if len(test_anomaly.own_events(i).get("ts", []))]
        offset = 1_000_000
        benign_scores = instance_scores(test_benign, benign_test_ids, db)
        anomaly_scores_raw = instance_scores(test_anomaly, anomaly_ids, db)
        scores = {int(i): v for i, v in benign_scores.items()}
        scores.update({int(i) + offset: v for i, v in anomaly_scores_raw.items()})
        test_instances = list(map(int, benign_test_ids)) + [int(i) + offset for i in anomaly_ids]
        labels = {int(i): 0 for i in benign_test_ids}
        labels.update({int(i) + offset: int(test_anomaly.instances.loc[i, "label"]) for i in anomaly_ids})
        decisions = {i: int(scores.get(i, 0.0) > threshold) for i in test_instances}
        positives = [i for i in test_instances if labels[i] == 1]
        negatives = [i for i in test_instances if labels[i] == 0]
        balanced_negatives = list(
            rng.choice(negatives, size=min(len(negatives), max(1, len(positives))), replace=False)
        )
        balanced = [int(i) for i in positives] + [int(i) for i in balanced_negatives]
        y_true = [labels[i] for i in test_instances]
        score_values = [scores.get(i, 0.0) for i in test_instances]
        data["methods"]["frequency_score"] = {
            "full": _decision_metrics(test_instances, labels, decisions),
            "balanced": _decision_metrics(balanced, labels, decisions),
        }
        data["instance_ranking"]["frequency_score"] = {
            "auroc": float(roc_auc_score(y_true, score_values)),
            "auprc": float(average_precision_score(y_true, score_values)),
        }
        data["frequency_threshold"] = threshold
        data["frequency_val_fpr"] = val_fpr
        path.write_text(json.dumps(data, indent=2))
        pred_path = path.with_name(path.stem + "_predictions.csv")
        if pred_path.exists():
            pred = pd.read_csv(pred_path)
            pred["frequency_score"] = pred.apply(
                lambda row, scores=scores, offset=offset: scores.get(int(row["instance"]) + (offset if row["split"] == "anomaly" else 0), 0.0),
                axis=1,
            )
            pred.to_csv(pred_path, index=False)
        print(
            path.name,
            "freq balanced",
            {k: round(v, 3) for k, v in data["methods"]["frequency_score"]["balanced"].items() if k in ("precision", "recall", "f1", "fpr")},
            "auc",
            round(data["instance_ranking"]["frequency_score"]["auroc"], 3),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
