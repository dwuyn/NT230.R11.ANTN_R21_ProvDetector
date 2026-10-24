"""LOF novelty detection over path embeddings and instance aggregation."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.neighbors import LocalOutlierFactor


@dataclass
class LOFDetector:
    n_neighbors: int = 20
    model: LocalOutlierFactor | None = None

    def fit(self, vectors: np.ndarray) -> LOFDetector:
        if len(vectors) < 3:
            raise ValueError("LOF needs at least three training vectors")
        neighbors = min(self.n_neighbors, len(vectors) - 1)
        self.model = LocalOutlierFactor(n_neighbors=neighbors, novelty=True)
        self.model.fit(vectors)
        return self

    def score(self, vectors: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("detector is not fitted")
        if len(vectors) == 0:
            return np.array([], dtype=np.float64)
        return np.asarray(self.model.decision_function(vectors), dtype=np.float64)


def path_threshold(scores: np.ndarray, quantile: float = 0.05) -> float:
    """Threshold that flags `quantile` of benign validation paths."""
    if len(scores) == 0:
        return 0.0
    return float(np.quantile(scores, quantile))


def aggregate_instances(
    scores_by_instance: dict[int, np.ndarray],
    threshold: float,
    t: int = 3,
) -> dict[int, int]:
    """An instance is malicious if at least `t` of its paths are outliers."""
    result = {}
    for instance, scores in scores_by_instance.items():
        count = int(np.sum(scores < threshold))
        result[int(instance)] = int(count >= t)
    return result
