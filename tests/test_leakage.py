import pytest

from src.ingest.schema import Rel
from src.select.paths import SelectedPath
from src.util.leakage import assert_disjoint, instance_overlap, path_overlap


def _path(edges):
    return SelectedPath(0, 0, -1.0, (0, 1), edges, ("P:a", "READ", "F:b"))


def test_instance_overlap():
    assert instance_overlap([1, 2, 3], [3, 4]) == 1
    with pytest.raises(AssertionError):
        assert_disjoint({"train": [1], "test": [1]})
    assert_disjoint({"train": [1], "test": [2]})


def test_path_overlap():
    a = {0: [_path(((0, Rel.READ, 1, 10),))]}
    b = {1: [_path(((0, Rel.READ, 1, 99),))]}
    assert path_overlap(a, b) == 1
