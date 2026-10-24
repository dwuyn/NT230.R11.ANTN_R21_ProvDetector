"""Error analysis: chain-level recall, false positives and false negatives."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import pandas as pd


def climb(instances: pd.DataFrame, instance: int) -> int:
    current = int(instance)
    while current in instances.index:
        parent = int(instances.loc[current, "parent"])
        if parent < 0 or parent not in instances.index:
            break
        name = str(instances.loc[parent, "name"])
        if not name or name == "unknown":
            break
        current = parent
    return current


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("predictions", help="predictions CSV from src.experiment")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--out", default="experiments/results/error-analysis.md")
    args = parser.parse_args()
    pred = pd.read_csv(args.predictions)
    instances = pd.read_parquet(f"data/clean/{args.dataset}_anomaly_instances.parquet").set_index("instance")
    anomaly = pred[pred["split"] == "anomaly"].copy()
    anomaly["root"] = anomaly["instance"].map(lambda i: climb(instances, i))
    methods = ["provdetector", "rule", "whitelist", "anomaly_score"]
    lines = [f"# Error analysis — {Path(args.predictions).stem}\n"]
    lines.append("\n## Chain-level recall (at least one malicious process in the spawn chain)\n")
    lines.append("| Method | Chains detected | Chains | Recall |")
    lines.append("|---|---|---|---|")
    chains = anomaly[anomaly["label"] == 1].groupby("root")
    for method in methods:
        detected = sum(1 for _, group in chains if group[method].max() == 1)
        lines.append(f"| {method} | {detected} | {len(chains)} | {detected / max(1, len(chains)):.3f} |")

    lines.append("\n## False positives (benign instances flagged)\n")
    benign = pred[(pred["split"] == "benign") & (pred["label"] == 0)]
    for method in methods:
        flagged = benign[benign[method] == 1]
        lines.append(f"- **{method}**: {len(flagged)}/{len(benign)} benign instances flagged")
        if len(flagged):
            names = instances.reindex(flagged["instance"]).dropna()
            if len(names):
                common = Counter(names["name"]).most_common(8)
                lines.append(f"  - top process names: {common}")

    lines.append("\n## False negatives (malicious instances missed)\n")
    positives = pred[(pred["split"] == "anomaly") & (pred["label"] == 1)]
    for method in methods:
        missed = positives[positives[method] == 0]
        lines.append(f"- **{method}**: {len(missed)}/{len(positives)} missed")
        if len(missed):
            names = instances.reindex(missed["instance"]).dropna()
            if len(names):
                lines.append(f"  - names: {Counter(names['name']).most_common(8)}")

    lines.append("\n## Path coverage\n")
    lines.append(
        f"- Malicious instances with 0 selected paths: "
        f"{int((positives['paths'] == 0).sum())}/{len(positives)}"
    )
    lines.append(
        f"- Benign instances with 0 selected paths: "
        f"{int((benign['paths'] == 0).sum())}/{len(benign)}"
    )
    out = Path(args.out)
    out.write_text("\n".join(lines) + "\n")
    print(out.read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
