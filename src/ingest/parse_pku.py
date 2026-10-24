"""Parse PKU-ASAL Simulated-Data ETW JSONL into a compact provenance schema.

Two passes over the JSONL file keep memory bounded:

1. lifecycle pass: only Process/Start and Process/Stop records, plus per-PID
   min/max timestamps (thousands of rows).
2. event pass: every event is assigned to the process interval active at its
   timestamp and appended to a Parquet writer in batches.

The W10 traces interleave events from several capture sessions (timestamps are
not globally ordered), so intervals are built per PID after sorting each PID's
lifecycle records rather than assuming file order.
"""
from __future__ import annotations

import argparse
import bisect
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from .normalize import abstract_path, normalize_name, socket_endpoint
from .schema import (
    EVENT_COLUMNS,
    NodeType,
    Rel,
    Scenario,
)

EVENT_SCHEMA = pa.schema(
    [
        ("ts", pa.int64()),
        ("instance", pa.int32()),
        ("src", pa.int32()),
        ("dst", pa.int32()),
        ("rel", pa.int8()),
        ("label", pa.int8()),
    ]
)
NODE_SCHEMA = pa.schema([("id", pa.int32()), ("type", pa.int8()), ("label", pa.string())])
INSTANCE_SCHEMA = pa.schema(
    [
        ("instance", pa.int32()),
        ("parent", pa.int32()),
        ("node", pa.int32()),
        ("label", pa.int8()),
        ("pid", pa.int32()),
        ("ppid", pa.int32()),
        ("name", pa.string()),
        ("cmdline", pa.string()),
        ("start", pa.int64()),
        ("end", pa.int64()),
        ("scenario", pa.int8()),
        ("dataset", pa.string()),
    ]
)

ITER_EVENTS = {"FileIO/Read", "FileIO/Write", "Image/Load", "TcpIp/Send", "TcpIp/Recv"}


@dataclass
class Interval:
    instance: int
    pid: int
    ppid: int
    name: str
    cmdline: str
    start: int
    end: int
    label: int
    parent: int = -1
    node: int = -1
    implicit: bool = False


@dataclass
class Lifecycle:
    intervals: dict[int, list[Interval]] = field(default_factory=lambda: defaultdict(list))
    starts: dict[int, list[int]] = field(default_factory=lambda: defaultdict(list))
    start_to_instance: dict[tuple[int, int], Interval] = field(default_factory=dict)
    by_instance: dict[int, Interval] = field(default_factory=dict)
    implicit: dict[int, Interval] = field(default_factory=dict)
    max_ts: int = 0

    def pick(self, pid: int, ts: int) -> Interval | None:
        entries = self.intervals.get(pid)
        if not entries:
            return self.implicit.get(pid)
        starts = self.starts[pid]
        idx = bisect.bisect_right(starts, ts) - 1
        if idx < 0:
            return self.implicit.get(pid, entries[0])
        candidate = entries[idx]
        # Prefer the enclosing interval; fall back to the nearest preceding one
        # when a stop record is missing (traces truncate at capture end).
        if candidate.end >= ts or idx == len(entries) - 1:
            return candidate
        return entries[idx]

    def parent_of(self, child: Interval) -> int:
        entries = self.intervals.get(child.ppid)
        if not entries:
            return -1
        starts = self.starts[child.ppid]
        idx = bisect.bisect_right(starts, child.start) - 1
        while idx >= 0:
            candidate = entries[idx]
            if (
                candidate.instance != child.instance
                and candidate.start <= child.start
                and candidate.end >= child.start
            ):
                return candidate.instance
            idx -= 1
        return -1


class NodeTable:
    def __init__(self) -> None:
        self._ids: dict[tuple, int] = {}
        self.labels: list[str] = []
        self.types: list[int] = []

    def _get(self, key: tuple, node_type: NodeType, label: str) -> int:
        node_id = self._ids.get(key)
        if node_id is None:
            node_id = len(self.labels)
            self._ids[key] = node_id
            self.labels.append(label)
            self.types.append(int(node_type))
        return node_id

    def process_instance(self, interval: Interval) -> int:
        if interval.node < 0:
            interval.node = self._get(
                ("process", interval.instance),
                NodeType.PROCESS,
                f"P:{normalize_name(interval.name)}",
            )
        return interval.node

    def orphan_process(self, pid: int, name: str) -> int:
        return self._get(("orphan", pid, name), NodeType.PROCESS, f"P:{normalize_name(name)}")

    def file(self, path: str) -> int:
        return self._get(("file", path), NodeType.FILE, f"F:{path}")

    def socket(self, endpoint: str) -> int:
        return self._get(("socket", endpoint), NodeType.SOCKET, f"S:{endpoint}")


def _ts(record: dict) -> int:
    try:
        return int(round(float(record.get("MSec", 0)) * 1000))
    except (TypeError, ValueError):
        return 0


def _int(record: dict, key: str, default: int = 0) -> int:
    raw = record.get(key)
    if raw is None:
        return default
    try:
        return int(str(raw).replace(",", ""))
    except ValueError:
        return default


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _process_key(record: dict) -> tuple[int, str, str]:
    pid = _int(record, "PID")
    unique = str(record.get("UniqueProcessKey") or record.get("DirectoryTableBase") or "")
    cmdline = (record.get("CommandLine") or "")[:200]
    return pid, unique, cmdline


def scan_lifecycle(path: Path, dataset: str, scenario: Scenario) -> Lifecycle:
    lifecycle = Lifecycle()
    raw_starts: dict[int, list[dict]] = defaultdict(list)
    raw_stops: dict[int, list[dict]] = defaultdict(list)
    seen: dict[int, tuple[int, int]] = {}

    for record in _iter_jsonl(path):
        pid = _int(record, "PID")
        ts = _ts(record)
        lo, hi = seen.get(pid, (ts, ts))
        seen[pid] = (min(lo, ts), max(hi, ts))
        lifecycle.max_ts = max(lifecycle.max_ts, ts)
        event = record.get("EventName")
        if event == "Process/Start":
            raw_starts[pid].append(record)
        elif event == "Process/Stop":
            raw_stops[pid].append(record)

    next_instance = 0
    pending: list[Interval] = []
    for pid in sorted(raw_starts):
        starts = sorted(raw_starts[pid], key=_ts)
        stops = sorted(raw_stops.get(pid, []), key=_ts)
        used_stops: set[int] = set()
        for start_record in starts:
            start = _ts(start_record)
            key = _process_key(start_record)
            end = lifecycle.max_ts
            # Pair with the earliest unused stop sharing the kernel process key.
            for index, stop_record in enumerate(stops):
                if index in used_stops:
                    continue
                stop_ts = _ts(stop_record)
                if stop_ts < start:
                    continue
                if _process_key(stop_record) == key:
                    end = stop_ts
                    used_stops.add(index)
                    break
            interval = Interval(
                instance=next_instance,
                pid=pid,
                ppid=_int(start_record, "ParentID"),
                name=start_record.get("PName") or start_record.get("ImageFileName") or "",
                cmdline=(start_record.get("CommandLine") or "").replace("&quot;", '"'),
                start=start,
                end=max(start, end),
                label=int(start_record.get("is_warn") == "True"),
            )
            next_instance += 1
            pending.append(interval)
            lifecycle.start_to_instance[(pid, start)] = interval

    # PIDs that only appear as parents or started before capture still need an
    # implicit instance so their events are not dropped.
    for interval in pending:
        lifecycle.intervals[interval.pid].append(interval)
        lifecycle.by_instance[interval.instance] = interval
    for pid in sorted(lifecycle.intervals):
        lifecycle.intervals[pid].sort(key=lambda i: i.start)
        lifecycle.starts[pid] = [i.start for i in lifecycle.intervals[pid]]

    for pid, (lo, hi) in seen.items():
        entries = lifecycle.intervals.get(pid)
        if entries and entries[0].start <= lo:
            continue
        implicit = Interval(
            instance=next_instance,
            pid=pid,
            ppid=0,
            name="",
            cmdline="",
            start=lo,
            end=hi,
            label=0,
            implicit=True,
        )
        next_instance += 1
        lifecycle.implicit[pid] = implicit
        lifecycle.by_instance[implicit.instance] = implicit
        if entries:
            entries.insert(0, implicit)
            lifecycle.starts[pid].insert(0, lo)
        else:
            lifecycle.intervals[pid] = [implicit]
            lifecycle.starts[pid] = [lo]

    for pid, entries in lifecycle.intervals.items():
        for interval in entries:
            interval.parent = lifecycle.parent_of(interval)
    return lifecycle


def _event_rows(record: dict, interval: Interval, nodes: NodeTable) -> tuple[int, int, int, int] | None:
    event = record.get("EventName")
    ts = _ts(record)
    if event == "FileIO/Read":
        return ts, interval.node, nodes.file(abstract_path(record.get("FileName", ""))), int(Rel.READ)
    if event == "FileIO/Write":
        return ts, interval.node, nodes.file(abstract_path(record.get("FileName", ""))), int(Rel.WRITE)
    if event == "Image/Load":
        return ts, interval.node, nodes.file(abstract_path(record.get("FileName", ""))), int(Rel.EXECUTE)
    if event in ("TcpIp/Send", "TcpIp/Recv"):
        endpoint = socket_endpoint(
            record.get("saddr", ""),
            record.get("sport", ""),
            record.get("daddr", ""),
            record.get("dport", ""),
        )
        return ts, interval.node, nodes.socket(endpoint), int(Rel.CONNECT)
    return None


def parse_file(
    input_path: str | Path,
    out_dir: str | Path,
    dataset: str,
    scenario: Scenario,
    host: str = "pku",
) -> dict:
    input_path = Path(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    lifecycle = scan_lifecycle(input_path, dataset, scenario)
    nodes = NodeTable()

    stem = f"{dataset}_{scenario.name.lower()}"
    events_path = out_dir / f"{stem}_events.parquet"
    nodes_path = out_dir / f"{stem}_nodes.parquet"
    instances_path = out_dir / f"{stem}_instances.parquet"

    writer = pq.ParquetWriter(events_path, EVENT_SCHEMA, compression="zstd")
    batch: list[tuple[int, int, int, int, int, int]] = []
    stats = {"lines": 0, "events": 0, "skipped": 0, "starts": 0, "malicious_starts": 0}

    def flush() -> None:
        if not batch:
            return
        columns = list(zip(*batch))
        writer.write_table(pa.Table.from_pydict(dict(zip(EVENT_COLUMNS, columns)), schema=EVENT_SCHEMA))
        batch.clear()

    for record in _iter_jsonl(input_path):
        stats["lines"] += 1
        pid = _int(record, "PID")
        ts = _ts(record)
        event = record.get("EventName")

        if event == "Process/Start":
            child = lifecycle.start_to_instance.get((pid, ts))
            if child is None:
                # Duplicate timestamp: fall back to the interval pick.
                child = lifecycle.pick(pid, ts)
            if child is None:
                stats["skipped"] += 1
                continue
            stats["starts"] += 1
            stats["malicious_starts"] += child.label
            child_node = nodes.process_instance(child)
            if child.parent >= 0:
                parent_interval = lifecycle.by_instance[child.parent]
                parent_node = nodes.process_instance(parent_interval)
                # The START edge belongs to the parent graph; the child's own
                # behaviour is stored under the child instance.
                batch.append(
                    (ts, child.parent, parent_node, child_node, int(Rel.START), int(parent_interval.label))
                )
                stats["events"] += 1
            continue

        if event not in ITER_EVENTS:
            stats["skipped"] += 1
            continue

        interval = lifecycle.pick(pid, ts)
        if interval is None:
            stats["skipped"] += 1
            continue
        nodes.process_instance(interval)
        row = _event_rows(record, interval, nodes)
        if row is None:
            stats["skipped"] += 1
            continue
        ev_ts, src, dst, rel = row
        batch.append((ev_ts, interval.instance, src, dst, rel, interval.label))
        stats["events"] += 1
        if len(batch) >= 250_000:
            flush()
    flush()
    writer.close()

    # Persist every interval, including implicit pre-capture ones.
    intervals = sorted(
        (i for entries in lifecycle.intervals.values() for i in entries),
        key=lambda i: (i.start, i.pid, i.instance),
    )
    for interval in intervals:
        nodes.process_instance(interval)
    pq.write_table(
        pa.Table.from_pydict(
            {
                "instance": [i.instance for i in intervals],
                "parent": [i.parent for i in intervals],
                "node": [i.node for i in intervals],
                "label": [i.label for i in intervals],
                "pid": [i.pid for i in intervals],
                "ppid": [i.ppid for i in intervals],
                "name": [normalize_name(i.name) for i in intervals],
                "cmdline": [i.cmdline for i in intervals],
                "start": [i.start for i in intervals],
                "end": [i.end for i in intervals],
                "scenario": [int(scenario) for _ in intervals],
                "dataset": [dataset for _ in intervals],
            },
            schema=INSTANCE_SCHEMA,
        ),
        instances_path,
        compression="zstd",
    )
    pq.write_table(
        pa.Table.from_pydict(
            {"id": list(range(len(nodes.labels))), "type": nodes.types, "label": nodes.labels},
            schema=NODE_SCHEMA,
        ),
        nodes_path,
        compression="zstd",
    )
    stats.update(
        {
            "dataset": dataset,
            "scenario": scenario.name.lower(),
            "instances": len(intervals),
            "nodes": len(nodes.labels),
            "events_path": str(events_path),
        }
    )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="ETW JSONL file")
    parser.add_argument("out_dir", help="output directory")
    parser.add_argument("dataset", help="dataset name, e.g. W10")
    parser.add_argument("scenario", choices=["benign", "anomaly"])
    args = parser.parse_args(argv)
    stats = parse_file(
        args.input,
        args.out_dir,
        args.dataset,
        Scenario[args.scenario.upper()],
    )
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
