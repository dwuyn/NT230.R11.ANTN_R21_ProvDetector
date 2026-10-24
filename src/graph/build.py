"""Per-process provenance graph construction from the compact event tables."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from src.ingest.schema import REL_NAMES, Scenario


@dataclass
class GraphEdges:
    """Edges of the expanded graph rooted at one process instance."""

    root: int
    timestamps: np.ndarray
    src: np.ndarray
    dst: np.ndarray
    rel: np.ndarray

    def __len__(self) -> int:
        return len(self.timestamps)


class Trace:
    """One dataset scenario (benign or anomaly) loaded from parquet."""

    def __init__(self, events: pd.DataFrame, nodes: pd.DataFrame, instances: pd.DataFrame):
        self.events = events.sort_values(["instance", "ts"], kind="stable").reset_index(drop=True)
        self.nodes = nodes.set_index("id").sort_index()
        self.labels = self.nodes["label"].to_dict()
        self.instances = instances.set_index("instance").sort_index()
        self._bounds: dict[int, tuple[int, int]] = {}
        instance_array = self.events["instance"].to_numpy()
        if len(instance_array):
            unique, first = np.unique(instance_array, return_index=True)
            ends = np.append(first[1:], len(instance_array))
            self._bounds = {
                int(instance): (int(start), int(end))
                for instance, start, end in zip(unique, first, ends)
            }
        self.children: dict[int, list[int]] = defaultdict(list)
        for child, parent in self.instances["parent"].items():
            if int(parent) >= 0:
                self.children[int(parent)].append(int(child))
        self._arrays = {
            column: self.events[column].to_numpy() for column in ("ts", "instance", "src", "dst", "rel")
        }

    @classmethod
    def load(cls, directory: str | Path, dataset: str, scenario: Scenario) -> Trace:
        stem = f"{dataset}_{scenario.name.lower()}"
        directory = Path(directory)
        return cls(
            pd.read_parquet(directory / f"{stem}_events.parquet"),
            pd.read_parquet(directory / f"{stem}_nodes.parquet"),
            pd.read_parquet(directory / f"{stem}_instances.parquet"),
        )

    @property
    def instance_ids(self) -> list[int]:
        return list(self.instances.index)

    def label(self, instance: int) -> int:
        return int(self.instances.loc[instance, "label"])

    def node_label(self, node: int) -> str:
        return self.labels[int(node)]

    def root_node(self, instance: int) -> int:
        return int(self.instances.loc[instance, "node"])

    def own_events(self, instance: int) -> dict:
        bounds = self._bounds.get(int(instance))
        if bounds is None:
            return {}
        lo, hi = bounds
        return {column: arrays[lo:hi] for column, arrays in self._arrays.items()}

    def descendants(self, instance: int, depth: int = 2) -> list[tuple[int, int]]:
        """Breadth-first (instance, depth) descendants, including the root."""
        result = [(int(instance), 0)]
        frontier = [int(instance)]
        for current_depth in range(1, depth + 1):
            next_frontier = []
            for parent in frontier:
                for child in self.children.get(parent, []):
                    result.append((child, current_depth))
                    next_frontier.append(child)
            frontier = next_frontier
            if not frontier:
                break
        return result

    def edges(self, instance: int, depth: int = 2, cap: int = 40_000) -> GraphEdges:
        """Concatenate edges of the root and its descendants.

        Child process events live under the child's own instance, so expanding
        two levels is what reconstructs a chain such as
        winword -> cmd -> powershell -> dropped file.  The cap protects against
        ancient, long-lived benign daemons with huge child fan-out.
        """
        members = self.descendants(instance, depth=depth)
        parts = []
        total = 0
        for member, level in members:
            events = self.own_events(member)
            if not events:
                continue
            take = len(events["ts"])
            if total + take > cap:
                take = max(0, cap - total)
            if take == 0:
                break
            parts.append(
                {
                    "ts": events["ts"][:take],
                    "src": events["src"][:take],
                    "dst": events["dst"][:take],
                    "rel": events["rel"][:take],
                }
            )
            total += take
        root = self.root_node(instance)
        if not parts:
            empty = np.array([], dtype=np.int64)
            return GraphEdges(root, empty, empty.astype(np.int32), empty.astype(np.int32), empty.astype(np.int8))
        timestamps = np.concatenate([p["ts"] for p in parts])
        src = np.concatenate([p["src"] for p in parts])
        dst = np.concatenate([p["dst"] for p in parts])
        rel = np.concatenate([p["rel"] for p in parts])
        order = np.argsort(timestamps, kind="stable")
        return GraphEdges(root, timestamps[order], src[order], dst[order], rel[order])

    def family_names(self, instance: int, depth: int = 2) -> set[str]:
        names = set()
        for member, _ in self.descendants(instance, depth=depth):
            name = str(self.instances.loc[member, "name"])
            if name:
                names.add(name)
        return names

    def edge_key(self, src_node: int, rel: int, dst_node: int) -> tuple[str, str, str]:
        return (self.node_label(src_node), REL_NAMES[int(rel)], self.node_label(dst_node))


class FrequencyDB:
    """Regularity database built only from benign training instances.

    ProvDetector/NoDoze use host frequency and time-window stability.  The
    simulated traces contain a single host with several capture sessions, so
    host frequency degenerates; we use the benign instance as the unit for
    edge frequency and for IN/OUT activity.  This is recorded as an adaptation
    in docs/limitations.md rather than presented as the original formula.
    """

    def __init__(self, edge_counts: dict, src_counts: dict, dst_counts: dict, n_instances: int):
        self.edge_counts = edge_counts
        self.src_counts = src_counts
        self.dst_counts = dst_counts
        self.n = max(1, n_instances)
        self._cache: dict[tuple[str, str, str], float] = {}

    def log_rarity(self, key: tuple[str, str, str]) -> float:
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        src, _rel, dst = key
        edge = (self.edge_counts.get(key, 0) + 1) / (self.n + 2)
        out = (self.src_counts.get(src, 0) + 1) / (self.n + 2)
        inn = (self.dst_counts.get(dst, 0) + 1) / (self.n + 2)
        value = float(np.log(max(edge * out * inn, 1e-12)))
        self._cache[key] = value
        return value

    @classmethod
    def build(cls, trace: Trace, instances: list[int]) -> FrequencyDB:
        edge_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        src_counts: dict[str, int] = defaultdict(int)
        dst_counts: dict[str, int] = defaultdict(int)
        used = 0
        for instance in instances:
            events = trace.own_events(instance)
            if not events or not len(events["ts"]):
                continue
            used += 1
            keys = set()
            srcs = set()
            dsts = set()
            for src, rel, dst in zip(events["src"], events["rel"], events["dst"]):
                key = trace.edge_key(int(src), int(rel), int(dst))
                keys.add(key)
                srcs.add(key[0])
                dsts.add(key[2])
            for key in keys:
                edge_counts[key] += 1
            for src in srcs:
                src_counts[src] += 1
            for dst in dsts:
                dst_counts[dst] += 1
        return cls(dict(edge_counts), dict(src_counts), dict(dst_counts), used)
