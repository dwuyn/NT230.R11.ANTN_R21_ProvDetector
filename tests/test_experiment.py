import numpy as np
import pandas as pd

from src.experiment import _inject_noise, _split
from src.ingest.schema import Rel
from src.select.paths import SelectedPath


def test_temporal_split_is_ordered():
    class Stub:
        instances = pd.DataFrame(
            {"start": [40, 10, 30, 20]}, index=[0, 1, 2, 3]
        )

    split = _split([0, 1, 2, 3], np.random.default_rng(0), 0.5, 0.25, trace=Stub(), mode="temporal")
    assert split["train"] == [1, 3]
    assert split["val"] == [2]
    assert split["test"] == [0]


def _path(instance, label):
    return SelectedPath(instance, label, -1.0, (0, 1), ((0, Rel.READ, 1, 10),), ("P:a", "READ", "F:b"))


def test_noise_injection_adds_only_to_malicious_instances():
    anomaly = {1: [_path(1, 1), _path(1, 1)], 2: [_path(2, 1), _path(2, 1)], 3: []}
    pool = [_path(9, 0), _path(10, 0)]
    noisy = _inject_noise(anomaly, pool, 0.5, np.random.default_rng(1))
    assert len(noisy[1]) == 2
    assert len(noisy[2]) == 2
    assert noisy[1][0].tokens == ("P:a", "READ", "F:b")
    assert noisy[3] == []
    assert all(path.label == 1 for path in noisy[1])
    assert _inject_noise(anomaly, pool, 0.0, np.random.default_rng(1)) is anomaly
