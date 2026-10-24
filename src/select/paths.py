"""Top-K rarest causal paths from a process-centred provenance graph."""
from __future__ import annotations

import heapq
from collections.abc import Iterable
from dataclasses import dataclass

from src.graph.build import FrequencyDB, GraphEdges, Trace
from src.ingest.schema import REL_NAMES


@dataclass(frozen=True)
class SelectedPath:
    instance: int
    label: int
    log_rarity: float
    nodes: tuple[int, ...]
    edges: tuple[tuple[int, int, int, int], ...]  # src, rel, dst, ts
    tokens: tuple[str, ...]


def _adjacency(trace: Trace, graph: GraphEdges) -> dict[int, list[tuple[int, int, int]]]:
    adjacency: dict[int, list[tuple[int, int, int]]] = {}
    for ts, src, dst, rel in zip(graph.timestamps, graph.src, graph.dst, graph.rel):
        adjacency.setdefault(int(src), []).append((int(ts), int(dst), int(rel)))
    for entries in adjacency.values():
        entries.sort(key=lambda item: item[0])
    return adjacency


def select_paths(
    trace: Trace,
    instance: int,
    db: FrequencyDB,
    k: int = 20,
    max_len: int = 5,
    beam: int = 300,
    max_expansions: int = 50_000,
) -> list[SelectedPath]:
    """Keep the K rarest time-respecting paths from the instance root.

    Only processes are edge sources, so almost every edge ends in a terminal
    file/socket node.  We therefore score terminal edges directly (sorting the
    outgoing edges, no combinatorial walk) and only expand edges that lead to
    another process.  This is exact for the terminal paths and beam-bounded for
    process chains, which in these traces are short
    (victim -> shell -> payload).
    """
    graph = trace.edges(instance)
    root = graph.root
    adjacency = _adjacency(trace, graph)
    if not adjacency.get(root):
        return []

    label = trace.label(instance)
    heap: list[tuple[float, int, tuple[int, ...], tuple[tuple[int, int, int, int], ...]]] = []
    seen: set[tuple[tuple[str, int, str], ...]] = set()
    counter = 0
    expansions = 0

    def signature(nodes: tuple[int, ...], edges: tuple[tuple[int, int, int, int], ...]) -> tuple:
        return tuple(
            (trace.node_label(src), int(rel), trace.node_label(dst))
            for src, rel, dst, _ts in edges
        )

    def offer(log_rarity: float, nodes: tuple[int, ...], edges: tuple[tuple[int, int, int, int], ...]) -> None:
        nonlocal counter
        sig = signature(nodes, edges)
        if sig in seen:
            return
        seen.add(sig)
        item = (-log_rarity, counter, nodes, edges)
        counter += 1
        if len(heap) < k:
            heapq.heappush(heap, item)
        elif log_rarity < -heap[0][0]:
            heapq.heapreplace(heap, item)

    states: list[tuple[float, int, int, tuple[int, ...], tuple[tuple[int, int, int, int], ...]]] = [
        (0.0, root, -(2**62), (root,), ())
    ]

    for depth in range(1, max_len + 1):
        next_states = []
        for log_rarity, node, last_ts, path_nodes, path_edges in states:
            outgoing = [(ts, dst, rel) for ts, dst, rel in adjacency.get(node, ()) if ts > last_ts]
            if not outgoing:
                continue
            terminal = []
            continuing = []
            for ts, dst, rel in outgoing:
                key = (trace.node_label(node), int(rel), trace.node_label(dst))
                new_log = log_rarity + db.log_rarity(key)
                new_nodes = path_nodes + (dst,)
                new_edges = path_edges + ((node, int(rel), dst, ts),)
                if adjacency.get(dst):
                    continuing.append((new_log, dst, ts, new_nodes, new_edges))
                else:
                    terminal.append((new_log, new_nodes, new_edges))
            terminal.sort(key=lambda item: item[0])
            for new_log, new_nodes, new_edges in terminal[:k]:
                offer(new_log, new_nodes, new_edges)
            if depth < max_len:
                continuing.sort(key=lambda item: item[0])
                next_states.extend(continuing[:beam])
                expansions += min(len(continuing), beam)
                if expansions >= max_expansions:
                    break
        if not next_states or expansions >= max_expansions:
            break
        next_states.sort(key=lambda item: item[0])
        states = next_states[:beam]

    if not heap:
        return []

    results: list[SelectedPath] = []
    for neg_log, _counter, nodes, edges in sorted(heap, key=lambda item: item[0]):
        tokens = [trace.node_label(nodes[0])]
        for _src, rel, dst, _ts in edges:
            tokens.extend((REL_NAMES[int(rel)], trace.node_label(dst)))
        results.append(
            SelectedPath(
                instance=instance,
                label=label,
                log_rarity=-neg_log,
                nodes=tuple(int(n) for n in nodes),
                edges=tuple(edges),
                tokens=tuple(tokens),
            )
        )
    return results

def select_for_instances(
    trace: Trace,
    instances: Iterable[int],
    db: FrequencyDB,
    k: int = 20,
    max_len: int = 5,
) -> dict[int, list[SelectedPath]]:
    result = {}
    for index, instance in enumerate(instances):
        result[int(instance)] = select_paths(trace, int(instance), db, k=k, max_len=max_len)
    return result


def sample_paths(
    trace: Trace,
    instance: int,
    k: int = 20,
    max_len: int = 5,
    rng=None,
) -> list[SelectedPath]:
    """Random time-respecting paths from the root (ablation: no path selection)."""
    import random

    rng = rng or random.Random(0)
    graph = trace.edges(instance)
    adjacency = _adjacency(trace, graph)
    root = graph.root
    if not adjacency.get(root):
        return []
    label = trace.label(instance)
    results: list[SelectedPath] = []
    seen: set[tuple] = set()
    attempts = 0
    while len(results) < k and attempts < k * 20:
        attempts += 1
        node = root
        last_ts = -(2**62)
        nodes = (root,)
        edges: tuple[tuple[int, int, int, int], ...] = ()
        for _ in range(max_len):
            outgoing = [edge for edge in adjacency.get(node, ()) if edge[0] > last_ts]
            if not outgoing:
                break
            ts, dst, rel = rng.choice(outgoing)
            nodes += (dst,)
            edges += ((node, int(rel), dst, ts),)
            last_ts = ts
            node = dst
            if not adjacency.get(dst):
                break
        if not edges:
            continue
        signature = tuple(
            (trace.node_label(src), int(rel), trace.node_label(dst))
            for src, rel, dst, _ts in edges
        )
        if signature in seen:
            continue
        seen.add(signature)
        tokens = [trace.node_label(nodes[0])]
        for src, rel, dst, _ts in edges:
            tokens.extend((REL_NAMES[int(rel)], trace.node_label(dst)))
        results.append(
            SelectedPath(
                instance=instance,
                label=label,
                log_rarity=0.0,
                nodes=tuple(nodes),
                edges=edges,
                tokens=tuple(tokens),
            )
        )
    return results
