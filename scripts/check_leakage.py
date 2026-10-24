"""Check cached path sets for instance leakage and report path overlap."""
from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.util.leakage import assert_disjoint, path_overlap


def load(path: Path):
    with path.open("rb") as handle:
        return pickle.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cache_dir", default="experiments/results/cache", nargs="?")
    args = parser.parse_args()
    cache = Path(args.cache_dir)
    train_files = sorted(cache.glob("*_train.pkl"))
    if not train_files:
        print(f"no cache files in {cache}")
        return 1
    failures = 0
    for train_file in train_files:
        prefix = train_file.name[: -len("_train.pkl")]
        val_file = cache / f"{prefix}_val.pkl"
        if not val_file.exists():
            continue
        train = load(train_file)
        val = load(val_file)
        try:
            assert_disjoint({"train": list(train), "validation": list(val)})
        except AssertionError as error:
            failures += 1
            print(f"FAIL {prefix}: {error}")
            continue
        overlap = path_overlap(train, val)
        print(f"OK   {prefix}: instance disjoint; path signatures shared train/val = {overlap}")
    print("LEAKAGE CHECK PASSED" if not failures else f"{failures} FAILURES")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
