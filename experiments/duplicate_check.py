"""Exact duplicate rate in the normalised event tables."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


def main() -> int:
    rows = []
    for path in sorted(Path("data/clean").glob("*_events.parquet")):
        frame = pd.read_parquet(path)
        duplicate = frame.duplicated().sum()
        rows.append({"file": path.name, "events": len(frame), "duplicates": duplicate, "rate": duplicate / max(1, len(frame))})
        print(path.name, rows[-1])
    Path("experiments/results/duplicate-check.json").write_text(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
