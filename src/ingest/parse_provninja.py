"""Parse ProvNinja causal-paragraph CSVs into path/token records.

ProvNinja stores a path as alternating node/relation tokens:
`PROCESS READ_WRITE FILE ...`.  We keep the raw token sequence for doc2vec and
also expose (src, relation, dst) triples for inspection.  This is a cross-check
source only; the main evaluation uses the PKU-ASAL traces.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

RELATIONS = {"READ_WRITE", "PROC_CREATE", "PROC_TERMINATE", "READ", "WRITE"}


def parse_paragraph(line: str) -> dict | None:
    tokens = line.split()
    if len(tokens) < 3:
        return None
    edges = []
    index = 0
    while index + 2 < len(tokens):
        src, relation, dst = tokens[index], tokens[index + 1], tokens[index + 2]
        if relation not in RELATIONS:
            # Malformed/odd-length line: rescale from the next token.
            index += 1
            continue
        edges.append((src, relation, dst))
        index += 2
    if not edges:
        return None
    return {"tokens": tokens, "edges": edges, "nodes": [edge[0] for edge in edges] + [edges[-1][2]]}


def parse_file(path: str | Path, out_path: str | Path, label: str) -> dict:
    stats = {"lines": 0, "paths": 0, "label": label}
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open(encoding="utf-8", errors="replace") as source, out.open("w", encoding="utf-8") as sink:
        for line in source:
            stats["lines"] += 1
            parsed = parse_paragraph(line)
            if parsed is None:
                continue
            parsed["label"] = label
            sink.write(json.dumps(parsed) + "\n")
            stats["paths"] += 1
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("label")
    args = parser.parse_args(argv)
    print(json.dumps(parse_file(args.input, args.output, args.label), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
