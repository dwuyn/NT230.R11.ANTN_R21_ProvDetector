"""Leakage checks for the instance-level protocol."""
from __future__ import annotations

from src.select.paths import SelectedPath


def instance_overlap(*groups: list[int]) -> int:
    seen: set[int] = set()
    overlap = 0
    for group in groups:
        current = set(map(int, group))
        overlap += len(current & seen)
        seen |= current
    return overlap


def path_signature(path: SelectedPath) -> tuple:
    return tuple((src, rel, dst) for src, rel, dst, _ts in path.edges)


def path_overlap(
    first: dict[int, list[SelectedPath]],
    second: dict[int, list[SelectedPath]],
) -> int:
    left = {path_signature(path) for paths in first.values() for path in paths}
    right = {path_signature(path) for paths in second.values() for path in paths}
    return len(left & right)


def assert_disjoint(names: dict[str, list[int]]) -> None:
    items = list(names.items())
    for index, (name_a, group_a) in enumerate(items):
        for name_b, group_b in items[index + 1 :]:
            overlap = set(map(int, group_a)) & set(map(int, group_b))
            if overlap:
                raise AssertionError(f"{name_a} and {name_b} share {len(overlap)} instances")
