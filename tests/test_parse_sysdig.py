import json
from datetime import datetime, timedelta, timezone

import pandas as pd

from src.ingest.parse_sysdig import parse_file
from src.ingest.schema import Rel, Scenario

ICT = timezone(timedelta(hours=8))


def _ns(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=ICT).timestamp() * 1e9)


def _event(ts, event_type, cmd, pcmd="bash", fd=None, args=""):
    return {
        "evt.time": ts,
        "evt.type": event_type,
        "evt.args": args,
        "fd.name": fd,
        "proc.cmdline": cmd,
        "proc.name": cmd.split()[0],
        "proc.pcmdline": pcmd,
        "proc.pname": pcmd.split()[0],
        "is_warn": False,
    }


def test_sysdig_parser_labels_and_edges(tmp_path):
    annotations = tmp_path / "annotations"
    annotations.mkdir()
    (annotations / "A1.txt").write_text(
        "[occurTime]\n2022-03-25 15:16:18\n2022-03-25 15:16:30\n[hostIp]\n192.168.0.155\n[pCommand]\nwhoami\n"
    )
    ts = _ns("2022-03-25 15:16:20")
    rows = [
        _event(ts, "clone", "whoami", pcmd="bash", args="pid=100 ptid=50"),
        _event(ts + 1, "read", "whoami", pcmd="bash", fd="/etc/passwd"),
        _event(ts + 2, "write", "whoami", pcmd="bash", fd="/tmp/out"),
        _event(ts + 3, "sendmsg", "whoami", pcmd="bash", fd="124.223.85.207:443"),
        _event(ts + 4, "read", "cat", pcmd="bash", fd="/etc/hosts"),
    ]
    raw = tmp_path / "trace.jsonl"
    raw.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    stats = parse_file(raw, tmp_path, "Ubuntu", Scenario.ANOMALY, annotations)
    assert stats["events"] >= 4
    assert stats["malicious_instances"] >= 1

    events = pd.read_parquet(tmp_path / "Ubuntu_anomaly_events.parquet")
    instances = pd.read_parquet(tmp_path / "Ubuntu_anomaly_instances.parquet")
    nodes = pd.read_parquet(tmp_path / "Ubuntu_anomaly_nodes.parquet").set_index("id")["label"].to_dict()
    assert (events["rel"] == Rel.READ).any()
    assert (events["rel"] == Rel.WRITE).any()
    assert (events["rel"] == Rel.CONNECT).any()
    assert (events["rel"] == Rel.START).any()
    malicious = instances[instances["label"] == 1]
    assert len(malicious) == 1
    assert "whoami" in malicious.iloc[0]["cmdline"]
    assert any(label == "F:/etc/passwd" for label in nodes.values())
    assert any(label == "S:124.223.85.207:443" for label in nodes.values())


def test_sysdig_parser_without_annotations_is_benign(tmp_path):
    ts = _ns("2022-03-25 15:16:20")
    raw = tmp_path / "trace.jsonl"
    raw.write_text(json.dumps(_event(ts, "read", "cat", fd="/etc/hosts")) + "\n")
    stats = parse_file(raw, tmp_path, "Ubuntu", Scenario.BENIGN)
    assert stats["malicious_instances"] == 0
