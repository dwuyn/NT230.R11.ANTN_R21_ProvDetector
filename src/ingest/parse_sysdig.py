"""Parse the PKU-ASAL Ubuntu Sysdig trace into the shared provenance schema.

Sysdig records in this release do not carry `proc.pid`; the only process
identifier is `proc.cmdline`.  We therefore define an instance as
``(process command line, 60-second time bucket)``.  This keeps instances
bounded while preserving the causal chain parent-cmdline -> child-cmdline.
Labels for the anomaly trace come from the published `attack_annotation/*.txt`
files: an instance is malicious if it contains an event inside an annotated
time window whose command line matches that annotation's distinctive token.
This is a heuristic label and is documented as such in the data card.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from .normalize import abstract_path, normalize_name
from .parse_pku import EVENT_SCHEMA, INSTANCE_SCHEMA, NODE_SCHEMA, NodeTable
from .schema import Rel, Scenario

# The PKU annotations are in UTC+8; the Sysdig epoch times confirm it
# (e.g. event 1648192574 = 2022-03-25 15:16:14 UTC+8).
ANNOTATION_TZ = timezone(timedelta(hours=8))
BUCKET_NS = 60 * 1_000_000_000
FILE_EVENTS = {"read", "readv", "write", "writev"}
NET_EVENTS = {"send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg", "connect", "accept"}
PROC_EVENTS = {"clone", "fork", "execve"}
MATCH_TOKENS = [
    "fscan",
    "sqltool_amd64_upx",
    "sandcat-linux",
    "juicypotato",
    "base64 -d",
    "whoami",
    "curl -o",
]
_SECTION = re.compile(r"^\[(occurTime|hostIp|pCommand|pFilePath)\]\s*$")


def _parse_annotations(directory: Path) -> list[dict]:
    annotations = []
    for path in sorted(directory.glob("A*.txt")):
        if path.name.startswith("A_alltime"):
            continue
        sections: dict[str, list[str]] = {}
        current = None
        for raw in path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            match = _SECTION.match(line)
            if match:
                current = match.group(1)
                sections.setdefault(current, [])
                continue
            if current:
                sections[current].append(line)
        times = sections.get("occurTime", [])
        commands = sections.get("pCommand", [])
        if len(times) < 2 or not commands:
            continue
        try:
            start = datetime.strptime(times[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=ANNOTATION_TZ).timestamp() * 1e9
            end = datetime.strptime(times[1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=ANNOTATION_TZ).timestamp() * 1e9
        except ValueError:
            continue
        command = " ".join(commands)
        tokens = [token for token in MATCH_TOKENS if token in command.lower()]
        if not tokens:
            # Fall back to an explicit executable path in the command.
            first = command.strip().split()[0] if command.strip() else ""
            base = first.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if base and base not in {"echo", "curl", "mkdir", "chmod"}:
                tokens = [base]
        annotations.append({"file": path.name, "start": int(start), "end": int(end), "tokens": tokens})
    return annotations


def _cmdline(record: dict) -> str:
    return (record.get("proc.cmdline") or "").strip()


def _exe(record: dict) -> str:
    args = record.get("evt.args") or ""
    match = re.search(r"exe=([^\s]+)", args)
    if match:
        return match.group(1)
    cmd = _cmdline(record)
    return cmd.split()[0] if cmd else ""


def _bucket(ts: int) -> int:
    return int(ts // BUCKET_NS)


def _node_key(cmd: str, bucket: int) -> str:
    return hashlib.sha1(f"{cmd}|{bucket}".encode()).hexdigest()[:16]


def _is_file(fd: str) -> bool:
    return fd.startswith("/") or re.match(r"^[a-zA-Z]:[\\/]", fd) is not None


def _is_socket(fd: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F:.]+:\d+$", fd))


def parse_file(
    input_path: str | Path,
    out_dir: str | Path,
    dataset: str,
    scenario: Scenario,
    annotations_dir: str | Path | None = None,
) -> dict:
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    annotations = _parse_annotations(Path(annotations_dir)) if annotations_dir else []
    nodes = NodeTable()
    stem = f"{dataset}_{scenario.name.lower()}"
    events_path = out_dir / f"{stem}_events.parquet"
    writer = pq.ParquetWriter(events_path, EVENT_SCHEMA, compression="zstd")
    batch: list[tuple] = []
    instances: dict[int, dict] = {}
    by_key: dict[str, int] = {}
    next_instance = 0
    stats = {"lines": 0, "events": 0, "skipped": 0, "instances": 0, "malicious_instances": 0, "annotations": len(annotations)}

    def instance_for(cmd: str, ts: int) -> int:
        nonlocal next_instance
        bucket = _bucket(ts)
        # Reuse by node key rather than a second dict of tuples.
        node_key = _node_key(cmd, bucket)
        existing_id = by_key.get(node_key)
        if existing_id is not None:
            existing = instances[existing_id]
            existing["start"] = min(existing["start"], ts)
            existing["end"] = max(existing["end"], ts)
            return existing_id
        instance = next_instance
        next_instance += 1
        by_key[node_key] = instance
        instances[instance] = {
            "instance": instance,
            "key": node_key,
            "pid": 0,
            "ppid": 0,
            "name": normalize_name(cmd.split()[0] if cmd else ""),
            "cmdline": cmd,
            "start": ts,
            "end": ts,
            "label": 0,
            "parent": -1,
            "node": -1,
        }
        return instance

    def label_for(cmd: str, ts: int) -> int:
        if not annotations:
            return 0
        lowered = cmd.lower()
        for rule in annotations:
            if (
                rule["start"] - 2_000_000_000 <= ts <= rule["end"] + 2_000_000_000
                and any(token in lowered for token in rule["tokens"])
            ):
                return 1
        return 0

    def flush() -> None:
        if not batch:
            return
        columns = list(zip(*batch))
        writer.write_table(pa.Table.from_pydict(dict(zip(["ts", "instance", "src", "dst", "rel", "label"], columns)), schema=EVENT_SCHEMA))
        batch.clear()

    with input_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stats["lines"] += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = int(record.get("evt.time") or 0)
            event_type = (record.get("evt.type") or "").lower()
            cmd = _cmdline(record)
            if not ts or not cmd:
                stats["skipped"] += 1
                continue
            instance = instance_for(cmd, ts)
            inst = instances[instance]
            inst["label"] = max(inst["label"], label_for(cmd, ts))
            src_node = nodes.process(instance, inst["name"])
            inst["node"] = src_node
            rel = None
            dst_node = None
            if event_type in FILE_EVENTS:
                fd = record.get("fd.name") or ""
                if _is_file(fd):
                    rel = Rel.READ if event_type.startswith("read") else Rel.WRITE
                    dst_node = nodes.file(abstract_path(fd))
            elif event_type in NET_EVENTS:
                fd = record.get("fd.name") or ""
                if _is_socket(fd):
                    rel = Rel.CONNECT
                    dst_node = nodes.socket(fd)
                elif _is_file(fd):
                    rel = Rel.READ if event_type.startswith("recv") else Rel.WRITE
                    dst_node = nodes.file(abstract_path(fd))
            elif event_type == "execve":
                path = _exe(record)
                if path:
                    rel = Rel.EXECUTE
                    dst_node = nodes.file(abstract_path(path))
            elif event_type in ("clone", "fork"):
                parent_cmd = (record.get("proc.pcmdline") or "").strip()
                if parent_cmd and parent_cmd != cmd:
                    parent_inst = instance_for(parent_cmd, ts)
                    parent_node = nodes.process(parent_inst, normalize_name(parent_cmd.split()[0]))
                    rel, dst_node = Rel.START, parent_node
            if rel is None or dst_node is None:
                stats["skipped"] += 1
                continue
            if rel == Rel.START:
                # START edge belongs to the parent graph.
                parent_cmd = (record.get("proc.pcmdline") or "").strip()
                parent_instance = instance_for(parent_cmd, ts)
                batch.append((ts, parent_instance, dst_node, src_node, int(rel), inst["label"]))
            else:
                batch.append((ts, instance, src_node, dst_node, int(rel), inst["label"]))
            stats["events"] += 1
            if len(batch) >= 250_000:
                flush()
    flush()
    writer.close()

    rows = sorted(instances.values(), key=lambda item: (item["start"], item["instance"]))
    for row in rows:
        row["malicious"] = row["label"]
    stats["malicious_instances"] = sum(row["label"] for row in rows)
    stats["instances"] = len(rows)
    pq.write_table(
        pa.Table.from_pydict(
            {
                "instance": [row["instance"] for row in rows],
                "parent": [row["parent"] for row in rows],
                "node": [row["node"] for row in rows],
                "label": [row["label"] for row in rows],
                "pid": [row["pid"] for row in rows],
                "ppid": [row["ppid"] for row in rows],
                "name": [row["name"] for row in rows],
                "cmdline": [row["cmdline"] for row in rows],
                "start": [row["start"] for row in rows],
                "end": [row["end"] for row in rows],
                "scenario": [int(scenario) for _ in rows],
                "dataset": [dataset for _ in rows],
            },
            schema=INSTANCE_SCHEMA,
        ),
        out_dir / f"{stem}_instances.parquet",
        compression="zstd",
    )
    pq.write_table(
        pa.Table.from_pydict({"id": list(range(len(nodes.labels))), "type": nodes.types, "label": nodes.labels}, schema=NODE_SCHEMA),
        out_dir / f"{stem}_nodes.parquet",
        compression="zstd",
    )
    stats.update({"dataset": dataset, "scenario": scenario.name.lower(), "nodes": len(nodes.labels)})
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("out_dir")
    parser.add_argument("dataset", default="Ubuntu")
    parser.add_argument("scenario", choices=["benign", "anomaly"])
    parser.add_argument("--annotations", default=None)
    args = parser.parse_args(argv)
    stats = parse_file(args.input, args.out_dir, args.dataset, Scenario[args.scenario.upper()], args.annotations)
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
