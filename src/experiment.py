"""End-to-end R21 experiment: rare paths -> doc2vec -> LOF -> instance decision."""
from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import average_precision_score, roc_auc_score
from tqdm import tqdm

from src.baseline.simple import (
    anomaly_score_decisions,
    calibrate_whitelist,
    rule_predict,
    whitelist_fractions,
)
from src.detect.detectors import NoveltyDetector
from src.detect.lof import aggregate_instances, path_threshold
from src.embed.doc2vec import PathEncoder
from src.graph.build import FrequencyDB, Trace
from src.ingest.schema import Scenario
from src.select.paths import SelectedPath, sample_paths, select_paths
from src.util.metrics import binary_metrics


def _split(instances: list[int], rng: np.random.Generator, train: float, val: float) -> dict[str, list[int]]:
    shuffled = list(instances)
    rng.shuffle(shuffled)
    n = len(shuffled)
    n_train = int(n * train)
    n_val = int(n * val)
    return {
        "train": shuffled[:n_train],
        "val": shuffled[n_train : n_train + n_val],
        "test": shuffled[n_train + n_val :],
    }


def _paths_with_cache(
    trace: Trace,
    instances: list[int],
    db: FrequencyDB,
    k: int,
    max_len: int,
    cache_path: Path | None,
    desc: str,
    mode: str = "rare",
    seed: int = 20261025,
) -> dict[int, list[SelectedPath]]:
    if cache_path is not None and cache_path.exists():
        with cache_path.open("rb") as handle:
            cached = pickle.load(handle)
        if set(cached) == set(instances):
            return cached
    result: dict[int, list[SelectedPath]] = {}
    import random

    for instance in tqdm(instances, desc=desc, unit="inst", leave=False):
        if mode == "random":
            rng = random.Random(seed + int(instance))
            result[int(instance)] = sample_paths(trace, int(instance), k=k, max_len=max_len, rng=rng)
        else:
            result[int(instance)] = select_paths(trace, int(instance), db, k=k, max_len=max_len)
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("wb") as handle:
            pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return result


def _flatten(paths_by_instance: dict[int, list[SelectedPath]]) -> tuple[list[list[str]], list[int], list[int]]:
    sentences, labels, instances = [], [], []
    for instance, paths in paths_by_instance.items():
        for path in paths:
            sentences.append(list(path.tokens))
            labels.append(path.label)
            instances.append(instance)
    return sentences, labels, instances


def _group_scores(instances: list[int], scores: np.ndarray) -> dict[int, np.ndarray]:
    grouped: dict[int, list[float]] = {}
    for instance, score in zip(instances, scores):
        grouped.setdefault(int(instance), []).append(float(score))
    return {instance: np.asarray(values) for instance, values in grouped.items()}


def _decision_metrics(
    test_instances: list[int],
    labels: dict[int, int],
    decisions: dict[int, int],
) -> dict:
    y_true = [labels[i] for i in test_instances]
    y_pred = [decisions.get(i, 0) for i in test_instances]
    return binary_metrics(y_true, y_pred)


def run(
    train_dataset: str,
    test_dataset: str,
    config: dict,
    seed: int,
    k: int,
    max_len: int,
    out_dir: Path,
    cache_dir: Path,
    path_mode: str = "rare",
    detector_kind: str = "lof",
) -> dict:
    started = time.perf_counter()
    data_dir = Path(config["paths"]["clean"])
    train_trace = Trace.load(data_dir, train_dataset, Scenario.BENIGN)
    test_benign = Trace.load(data_dir, test_dataset, Scenario.BENIGN)
    test_anomaly = Trace.load(data_dir, test_dataset, Scenario.ANOMALY)
    rng = np.random.default_rng(seed)

    train_ids = [i for i in train_trace.instance_ids if len(train_trace.own_events(i).get("ts", []))]
    split = _split(train_ids, rng, config["split"]["train_ratio"], 0.15)
    if train_dataset == test_dataset:
        benign_test_ids = split["test"]
    else:
        benign_test_ids = [i for i in test_benign.instance_ids if len(test_benign.own_events(i).get("ts", []))]
        rng.shuffle(benign_test_ids)

    anomaly_ids = [i for i in test_anomaly.instance_ids if len(test_anomaly.own_events(i).get("ts", []))]
    db = FrequencyDB.build(train_trace, split["train"])

    tag = f"{train_dataset}_{test_dataset}_k{k}_L{max_len}_{path_mode}_{detector_kind}_seed{seed}"
    train_paths = _paths_with_cache(
        train_trace, split["train"], db, k, max_len, cache_dir / f"{tag}_train.pkl", "train paths",
        mode=path_mode, seed=seed,
    )
    val_paths = _paths_with_cache(
        train_trace, split["val"], db, k, max_len, cache_dir / f"{tag}_val.pkl", "val paths",
        mode=path_mode, seed=seed,
    )
    test_benign_paths = _paths_with_cache(
        test_benign, benign_test_ids, db, k, max_len, cache_dir / f"{tag}_benign.pkl", "test benign paths",
        mode=path_mode, seed=seed,
    )
    anomaly_paths = _paths_with_cache(
        test_anomaly, anomaly_ids, db, k, max_len, cache_dir / f"{tag}_anomaly.pkl", "anomaly paths",
        mode=path_mode, seed=seed,
    )
    # Instance ids are local to each trace (both start at 0).  Namespace the
    # anomaly ids so benign and malicious instances never collide.
    offset = 1_000_000
    anomaly_paths_keyed = {int(i) + offset: paths for i, paths in anomaly_paths.items()}

    train_sentences, _, _ = _flatten(train_paths)
    if len(train_sentences) < 2:
        raise RuntimeError("not enough training paths")
    encoder = PathEncoder(
        vector_size=config["params"]["doc2vec"]["vector_size"],
        dm=config["params"]["doc2vec"]["dm"],
        window=config["params"]["doc2vec"]["window"],
        epochs=config["params"]["doc2vec"]["epochs"],
        seed=seed,
    ).fit(train_sentences)
    train_vectors = encoder.transform(train_sentences)
    detector = NoveltyDetector(
        kind=detector_kind,
        n_neighbors=config["params"]["lof"]["n_neighbors"],
        seed=seed,
    ).fit(train_vectors)

    def score_paths(paths_by_instance):
        sentences, labels, instances = _flatten(paths_by_instance)
        vectors = encoder.transform(sentences) if sentences else np.zeros((0, 100))
        scores = detector.score(vectors)
        return scores, np.asarray(labels), np.asarray(instances)

    primary_t = int(config["params"]["threshold_t"])
    val_scores, _, val_instances = score_paths(val_paths)
    val_grouped = _group_scores(val_instances, val_scores)

    def val_fpr(quantile: float) -> tuple[float, float]:
        candidate = path_threshold(val_scores, quantile)
        decisions = aggregate_instances(val_grouped, candidate, t=primary_t)
        fpr = float(np.mean([decisions.get(int(i), 0) for i in split["val"]])) if split["val"] else 0.0
        return candidate, fpr

    grid = [0.001, 0.002, 0.005, 0.01, 0.02, 0.03, 0.05, 0.08, 0.10]
    threshold, threshold_quantile, calibrated_fpr = path_threshold(val_scores, grid[-1]), grid[-1], 1.0
    for quantile in [grid[-1]] + list(reversed(grid[:-1])):
        candidate, fpr = val_fpr(quantile)
        if fpr <= 0.05:
            threshold, threshold_quantile, calibrated_fpr = candidate, quantile, fpr
            break

    test_benign_scores, _, test_benign_instances = score_paths(test_benign_paths)
    anomaly_scores, anomaly_labels, anomaly_instances = score_paths(anomaly_paths_keyed)

    all_scores = np.concatenate([test_benign_scores, anomaly_scores])
    all_path_labels = np.concatenate([np.zeros(len(test_benign_scores), dtype=int), anomaly_labels])
    path_pred = (all_scores < threshold).astype(int)
    path_metrics = binary_metrics(all_path_labels, path_pred)
    path_balanced = None
    positive_paths = np.flatnonzero(all_path_labels == 1)
    negative_paths = np.flatnonzero(all_path_labels == 0)
    if len(positive_paths) and len(negative_paths):
        sample_negatives = rng.choice(
            negative_paths, size=min(len(negative_paths), len(positive_paths)), replace=False
        )
        keep = np.concatenate([positive_paths, sample_negatives])
        path_balanced = binary_metrics(all_path_labels[keep], path_pred[keep])
    path_ranking = {
        "auroc": float(roc_auc_score(all_path_labels, -all_scores)) if len(np.unique(all_path_labels)) > 1 else 0.0,
        "auprc": float(average_precision_score(all_path_labels, -all_scores))
        if len(np.unique(all_path_labels)) > 1
        else 0.0,
    }

    test_instances = list(map(int, benign_test_ids)) + [int(i) + offset for i in anomaly_ids]
    labels = {}
    for instance in benign_test_ids:
        labels[int(instance)] = 0
    for instance in anomaly_ids:
        labels[int(instance) + offset] = int(test_anomaly.instances.loc[instance, "label"])

    scores_by_instance = _group_scores(anomaly_instances, anomaly_scores)
    scores_by_instance.update(_group_scores(test_benign_instances, test_benign_scores))

    t_sweep = {}
    for t in (1, 2, 3, 4, 5):
        decisions = aggregate_instances(scores_by_instance, threshold, t=t)
        for instance in test_instances:
            decisions.setdefault(int(instance), 0)
        t_sweep[t] = _decision_metrics(test_instances, labels, decisions)
    decisions = aggregate_instances(scores_by_instance, threshold, t=primary_t)
    for instance in test_instances:
        decisions.setdefault(int(instance), 0)

    positives = [i for i in test_instances if labels[i] == 1]
    negatives = [i for i in test_instances if labels[i] == 0]
    balanced_negatives = list(rng.choice(negatives, size=min(len(negatives), max(1, len(positives))), replace=False))
    balanced = [int(i) for i in positives] + [int(i) for i in balanced_negatives]

    # Baselines on exactly the same test instances.
    rule_decisions = {}
    for key in test_instances:
        if key >= offset:
            rule_decisions[key] = rule_predict(test_anomaly, key - offset)
        else:
            rule_decisions[key] = rule_predict(test_benign, key)
    whitelist_threshold, whitelist_val_fpr, whitelist_calibration = calibrate_whitelist(
        train_trace, split["val"], db
    )
    whitelist_cutoff = whitelist_calibration["support_cutoff"]
    whitelist_benign_fractions = whitelist_fractions(
        test_benign, list(map(int, benign_test_ids)), db, whitelist_cutoff
    )
    whitelist_anom_fractions = whitelist_fractions(
        test_anomaly, list(map(int, anomaly_ids)), db, whitelist_cutoff
    )
    whitelist_fractions_all = {
        **{int(i): v for i, v in whitelist_benign_fractions.items()},
        **{int(i) + offset: v for i, v in whitelist_anom_fractions.items()},
    }
    whitelist_decisions_all = {
        i: int(v > whitelist_threshold) for i, v in whitelist_fractions_all.items()
    }

    min_log = {}
    for instance, paths in test_benign_paths.items():
        if paths:
            min_log[int(instance)] = float(min(path.log_rarity for path in paths))
    for instance, paths in anomaly_paths.items():
        if paths:
            min_log[int(instance) + offset] = float(min(path.log_rarity for path in paths))
    val_min_log = {
        int(instance): float(min(path.log_rarity for path in paths))
        for instance, paths in val_paths.items()
        if paths
    }
    if val_min_log:
        anomaly_threshold = float(np.quantile(list(val_min_log.values()), 0.05))
    else:
        anomaly_threshold = float("-inf")
    anomaly_decisions = anomaly_score_decisions(
        test_anomaly, [int(i) + offset for i in anomaly_ids], min_log, anomaly_threshold
    )
    anomaly_decisions.update(
        anomaly_score_decisions(test_benign, list(map(int, benign_test_ids)), min_log, anomaly_threshold)
    )

    def summarize(decisions_map: dict[int, int]) -> dict:
        return {
            "full": _decision_metrics(test_instances, labels, decisions_map),
            "balanced": _decision_metrics(balanced, labels, decisions_map),
        }

    y_true = [labels[i] for i in test_instances]

    def ranking_metrics(score_map: dict[int, float]) -> dict:
        scores = [float(score_map.get(i, 0.0)) for i in test_instances]
        if len(set(y_true)) < 2:
            return {"auroc": 0.0, "auprc": 0.0}
        return {
            "auroc": float(roc_auc_score(y_true, scores)),
            "auprc": float(average_precision_score(y_true, scores)),
        }

    lof_instance_scores = {
        i: float(np.sum(scores_by_instance.get(i, np.array([])) < threshold)) for i in test_instances
    }
    anomaly_scores_instance = {i: -min_log.get(i, 1e9) for i in test_instances}

    results = {
        "config": {
            "train_dataset": train_dataset,
            "test_dataset": test_dataset,
            "seed": seed,
            "k": k,
            "max_len": max_len,
            "path_mode": path_mode,
            "detector": detector_kind,
            "threshold_quantile": threshold_quantile,
            "calibrated_val_fpr": calibrated_fpr,
            "primary_t": primary_t,
            "train_instances": len(split["train"]),
            "val_instances": len(split["val"]),
            "benign_test_instances": len(benign_test_ids),
            "anomaly_instances": len(anomaly_ids),
            "positive_instances": len(positives),
        },
        "coverage": {
            "train_paths": len(train_sentences),
            "val_paths": len(val_scores),
            "test_benign_paths": len(test_benign_scores),
            "anomaly_paths": len(anomaly_scores),
            "train_instances_with_paths": sum(1 for p in train_paths.values() if p),
            "test_benign_with_paths": sum(1 for p in test_benign_paths.values() if p),
            "anomaly_with_paths": sum(1 for p in anomaly_paths.values() if p),
        },
        "lof_threshold": threshold,
        "path_level": path_metrics,
        "path_level_balanced": path_balanced,
        "path_ranking": path_ranking,
        "instance_ranking": {
            "provdetector": ranking_metrics(lof_instance_scores),
            "whitelist": ranking_metrics(whitelist_fractions_all),
            "anomaly_score": ranking_metrics(anomaly_scores_instance),
        },
        "instance_level_t_sweep": t_sweep,
        "methods": {
            "provdetector": summarize(decisions),
            "rule_heuristic": summarize(rule_decisions),
            "whitelist": summarize(whitelist_decisions_all),
            "anomaly_score": summarize(anomaly_decisions),
        },
        "whitelist_cutoff": whitelist_cutoff,
        "whitelist_threshold": whitelist_threshold,
        "whitelist_val_fpr": whitelist_val_fpr,
        "whitelist_calibration": whitelist_calibration,
        "anomaly_score_threshold": anomaly_threshold,
        "runtime_seconds": time.perf_counter() - started,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{tag}.json").write_text(json.dumps(results, indent=2))
    rows = []
    for instance in test_instances:
        raw_instance = instance - offset if instance >= offset else instance
        rows.append(
            {
                "instance": raw_instance,
                "dataset": test_dataset,
                "split": "anomaly" if instance >= offset else "benign",
                "label": labels[instance],
                "paths": len(scores_by_instance.get(instance, [])),
                "outlier_paths": int(np.sum(scores_by_instance.get(instance, np.array([])) < threshold)),
                "provdetector": decisions.get(instance, 0),
                "rule": rule_decisions.get(instance, 0),
                "whitelist": whitelist_decisions_all.get(instance, 0),
                "novel_fraction": whitelist_fractions_all.get(instance, 0.0),
                "anomaly_score": anomaly_decisions.get(instance, 0),
                "min_log_rarity": min_log.get(instance, 0.0),
            }
        )
    pd.DataFrame(rows).to_csv(out_dir / f"{tag}_predictions.csv", index=False)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--train", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--seed", type=int, default=20261025)
    parser.add_argument("--k", type=int, default=20)
    parser.add_argument("--max-len", type=int, default=5)
    parser.add_argument("--out", default="experiments/results")
    parser.add_argument("--path-mode", choices=["rare", "random"], default="rare")
    parser.add_argument("--detector", choices=["lof", "ocsvm", "iforest", "robustcov"], default="lof")
    args = parser.parse_args(argv)
    config = yaml.safe_load(Path(args.config).read_text())
    results = run(
        args.train,
        args.test,
        config,
        args.seed,
        args.k,
        args.max_len,
        Path(args.out),
        Path(args.out) / "cache",
        path_mode=args.path_mode,
        detector_kind=args.detector,
    )
    print(json.dumps({k: results[k] for k in ("config", "coverage", "path_level", "runtime_seconds")}, indent=2))
    print(json.dumps(results["methods"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
