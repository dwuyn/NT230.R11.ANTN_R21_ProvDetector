"""Render experiment JSON files into the report tables."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def row(name: str, metrics: dict) -> str:
    return (
        f"| {name} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | "
        f"{metrics['f1']:.3f} | {metrics['fpr']:.3f} | {metrics['tp']}/{metrics['fp']}/{metrics['tn']}/{metrics['fn']} |"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", help="result JSON files")
    parser.add_argument("--out", default="experiments/results/main-table.md")
    args = parser.parse_args()
    blocks = [
        "# R21 main results\n",
        "Method reproduction on PKU-ASAL Simulated-Data; **not** a reproduction of the paper's private-enterprise F1=0.974.\n",
    ]
    for path in map(Path, args.results):
        data = json.loads(path.read_text())
        cfg = data["config"]
        blocks.append(
            f"\n## Train `{cfg['train_dataset']}` → test `{cfg['test_dataset']}` "
            f"(seed {cfg['seed']}, K={cfg['k']}, t={cfg['primary_t']})\n"
        )
        blocks.append(
            f"Coverage: train paths {data['coverage']['train_paths']}, "
            f"anomaly instances with paths {data['coverage']['anomaly_with_paths']}"
            f"/{cfg['anomaly_instances']}; benign test with paths "
            f"{data['coverage']['test_benign_with_paths']}/{cfg['benign_test_instances']}.\n"
        )
        blocks.append("\n### Instance level (balanced test set)\n")
        blocks.append("| Method | P | R | F1 | FPR | TP/FP/TN/FN |")
        blocks.append("|---|---|---|---|---|---|")
        for method, values in data["methods"].items():
            blocks.append(row(method, values["balanced"]))
        blocks.append("\n### Instance level (full test set)\n")
        blocks.append("| Method | P | R | F1 | FPR | TP/FP/TN/FN |")
        blocks.append("|---|---|---|---|---|---|")
        for method, values in data["methods"].items():
            blocks.append(row(method, values["full"]))
        path = data["path_level"]
        blocks.append(
            f"\nPath level (LOF threshold {data['lof_threshold']:.4f}): "
            f"P={path['precision']:.3f} R={path['recall']:.3f} F1={path['f1']:.3f} "
            f"(TP/FP/FN {path['tp']}/{path['fp']}/{path['fn']}).\n"
        )
        if data.get("path_level_balanced"):
            pb = data["path_level_balanced"]
            blocks.append(
                f"Path level (balanced): P={pb['precision']:.3f} R={pb['recall']:.3f} "
                f"F1={pb['f1']:.3f} FPR={pb['fpr']:.3f}; "
                f"path AUROC={data['path_ranking']['auroc']:.3f}, "
                f"AUPRC={data['path_ranking']['auprc']:.3f}.\n"
            )
        blocks.append("\n### Ranking (full test set)\n")
        blocks.append("| Method | AUROC | AUPRC |")
        blocks.append("|---|---|---|")
        for method, values in data.get("instance_ranking", {}).items():
            blocks.append(f"| {method} | {values['auroc']:.3f} | {values['auprc']:.3f} |")
        blocks.append(
            f"\nLOF calibration: quantile {data['config']['threshold_quantile']}, "
            f"benign-val instance FPR {data['config']['calibrated_val_fpr']:.3f}; "
            f"whitelist support {data.get('whitelist_cutoff')} "
            f"fraction threshold {data.get('whitelist_threshold', 0):.3f}.\n"
        )
        blocks.append("\n### t sweep (ProvDetector, full test)\n")
        blocks.append("| t | P | R | F1 | FPR |")
        blocks.append("|---|---|---|---|---|")
        for t, metrics in data["instance_level_t_sweep"].items():
            blocks.append(
                f"| {t} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | "
                f"{metrics['f1']:.3f} | {metrics['fpr']:.3f} |"
            )
        blocks.append(f"\nRuntime: {data['runtime_seconds']:.1f}s.\n")
    out = Path(args.out)
    out.write_text("\n".join(blocks) + "\n")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
