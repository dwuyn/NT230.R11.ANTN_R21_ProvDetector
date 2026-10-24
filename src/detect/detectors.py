"""Novelty detector variants used in the T08/T11 ablation."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM


@dataclass
class NoveltyDetector:
    kind: str = "lof"
    n_neighbors: int = 20
    seed: int = 20261025
    model: object | None = None

    def fit(self, vectors: np.ndarray) -> NoveltyDetector:
        kind = self.kind.lower()
        if kind == "lof":
            neighbors = min(self.n_neighbors, max(1, len(vectors) - 1))
            model = LocalOutlierFactor(n_neighbors=neighbors, novelty=True)
        elif kind == "ocsvm":
            model = OneClassSVM(nu=0.1, kernel="rbf", gamma=0.5)
        elif kind == "iforest":
            model = IsolationForest(
                n_estimators=100, contamination=0.04, random_state=self.seed, n_jobs=1
            )
        elif kind == "robustcov":
            model = EllipticEnvelope(contamination=0.04, random_state=self.seed)
        else:
            raise ValueError(f"unknown detector: {self.kind}")
        model.fit(vectors)
        self.model = model
        return self

    def score(self, vectors: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("detector is not fitted")
        if len(vectors) == 0:
            return np.array([], dtype=np.float64)
        if hasattr(self.model, "decision_function"):
            scores = self.model.decision_function(vectors)
        else:
            scores = self.model.score_samples(vectors)
        return np.asarray(scores, dtype=np.float64)
