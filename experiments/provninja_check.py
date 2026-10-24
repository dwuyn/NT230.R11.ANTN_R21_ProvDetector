"""Cross-check the LOF stage on ProvNinja's published feature vectors.

ProvNinja (BSD-3-Clause) ships Doc2Vec features for benign, anomaly and
adversarial-gadget paths.  We do not copy their detector; we fit our LOF on the
benign vectors and report how many held-out benign, anomaly and gadget paths are
flagged.  This validates the embedding/novelty stage independently of the PKU
traces.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.detect.lof import LOFDetector, path_threshold


def main() -> int:
    root = Path("data/raw-provninja")
    frames = {
        "benign": pd.read_csv(root / "benign-fv.csv", header=None).to_numpy(dtype=float),
        "anomaly": pd.read_csv(root / "anomaly-fv.csv", header=None).to_numpy(dtype=float),
        "gadget": pd.read_csv(root / "gadget-fv.csv", header=None).to_numpy(dtype=float),
    }
    rng = np.random.default_rng(20261025)
    benign = frames["benign"]
    order = rng.permutation(len(benign))
    n_train, n_val = int(0.7 * len(order)), int(0.15 * len(order))
    train = benign[order[:n_train]]
    val = benign[order[n_train : n_train + n_val]]
    test = benign[order[n_train + n_val :]]
    detector = LOFDetector(n_neighbors=20).fit(train)
    val_scores = detector.score(val)
    threshold = path_threshold(val_scores, 0.05)
    result = {"threshold": threshold, "train": len(train), "val": len(val), "test": len(test)}
    for name, vectors in [("benign_test", test), ("anomaly", frames["anomaly"]), ("gadget", frames["gadget"])]:
        scores = detector.score(vectors)
        result[name] = {
            "paths": len(scores),
            "flagged": int(np.sum(scores < threshold)),
            "flag_rate": float(np.mean(scores < threshold)),
        }
    out = Path("experiments/results/provninja-check.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
