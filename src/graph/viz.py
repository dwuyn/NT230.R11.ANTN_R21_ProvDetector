"""Render one benign and one anomalous provenance graph for the report."""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from src.graph.build import Trace
from src.ingest.schema import Scenario


def draw(trace: Trace, instance: int, path: Path, title: str, max_nodes: int = 120) -> None:
    graph = trace.edges(instance)
    g = nx.DiGraph()
    for ts, src, dst, rel in zip(graph.timestamps, graph.src, graph.dst, graph.rel):
        g.add_edge(int(src), int(dst), ts=int(ts), rel=int(rel))
    if len(g) > max_nodes:
        keep = [n for n in nx.bfs_tree(g, graph.root, depth_limit=2)][:max_nodes]
        g = g.subgraph(keep).copy()
    colors = []
    for node in g.nodes:
        label = trace.node_label(node)
        colors.append("#4c78a8" if label.startswith("P:") else "#f58518" if label.startswith("F:") else "#54a24b")
    labels = {node: trace.node_label(node).split(":", 1)[1][:28] for node in g.nodes}
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(g, seed=7, k=0.6)
    nx.draw_networkx_nodes(g, pos, node_color=colors, node_size=600, alpha=0.9)
    nx.draw_networkx_edges(g, pos, arrows=True, alpha=0.5, arrowsize=12)
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=6)
    plt.title(title)
    plt.axis("off")
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="WS12")
    parser.add_argument("--nodes", type=int, default=80)
    args = parser.parse_args()
    out = Path("experiments/figs")
    benign = Trace.load("data/clean", args.dataset, Scenario.BENIGN)
    anomaly = Trace.load("data/clean", args.dataset, Scenario.ANOMALY)
    benign_id = next(i for i in benign.instance_ids if len(benign.own_events(i).get("ts", [])) > 5)
    mal_ids = [i for i in anomaly.instance_ids if int(anomaly.instances.loc[i, "label"]) == 1]
    candidates = [
        i for i in mal_ids
        if len(anomaly.own_events(i).get("ts", [])) > 5 and anomaly.children.get(int(i))
    ]
    attack_id = max(candidates, key=lambda i: len(anomaly.children.get(int(i), [])), default=mal_ids[0])
    draw(benign, benign_id, out / f"{args.dataset}-benign.png", f"{args.dataset} benign instance {benign_id}", args.nodes)
    draw(anomaly, attack_id, out / f"{args.dataset}-attack.png", f"{args.dataset} malicious instance {attack_id}", args.nodes)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
