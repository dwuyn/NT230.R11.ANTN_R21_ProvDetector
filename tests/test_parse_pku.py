import json

import pandas as pd

from src.ingest.normalize import abstract_path, normalize_name, socket_endpoint
from src.ingest.parse_pku import parse_file
from src.ingest.schema import Rel, Scenario


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(row) + "\n" for row in rows)


def _proc(pid, ppid, name, ms, command="cmd.exe", warn=False, unique="0xA"):
    return {
        "MSec": str(ms),
        "PID": str(pid),
        "PName": name,
        "TID": "-1",
        "EventName": "Process/Start",
        "ProcessID": str(pid),
        "ParentID": str(ppid),
        "ImageFileName": name + ".exe",
        "UniqueProcessKey": unique,
        "CommandLine": command,
        "is_warn": "True" if warn else "False",
        "PPName": "parent",
    }


def _stop(pid, ms, command="cmd.exe", unique="0xA"):
    return {
        "MSec": str(ms),
        "PID": str(pid),
        "PName": "",
        "EventName": "Process/Stop",
        "ProcessID": str(pid),
        "ParentID": "1",
        "ImageFileName": "x.exe",
        "UniqueProcessKey": unique,
        "CommandLine": command,
    }


def _file(pid, ms, event, path):
    return {
        "MSec": str(ms),
        "PID": str(pid),
        "PName": "x",
        "EventName": event,
        "FileName": path,
    }


def test_normalization():
    assert normalize_name(r"C:\Windows\System32\CMD.EXE") == "cmd.exe"
    assert abstract_path(r"C:\Users\Alice\Desktop\Paper.DOC") == "*:/users/*/desktop/paper.doc"
    assert abstract_path("/home/alice/secret.txt") == "/home/*/secret.txt"
    assert socket_endpoint("192.168.0.5", "50000", "8.8.8.8", "443") == "8.8.8.8:443"
    assert socket_endpoint("8.8.8.8", "443", "192.168.0.5", "50000") == "8.8.8.8:443"


def test_parser_assigns_events_and_parent_edges(tmp_path):
    raw = tmp_path / "trace.jsonl"
    rows = [
        _proc(100, 1, "explorer", 100, unique="0x100"),
        _file(100, 110, "FileIO/Read", r"C:\Windows\a.dll"),
        _proc(200, 100, "cmd", 120, command="cmd /c whoami", warn=True, unique="0x200"),
        _file(200, 130, "FileIO/Write", r"C:\Users\Bob\out.txt"),
        _file(200, 140, "TcpIp/Send", "x"),
        _stop(200, 150, command="cmd /c whoami", unique="0x200"),
        _file(100, 160, "FileIO/Read", r"C:\Windows\a.dll"),
        _stop(100, 170, unique="0x100"),
    ]
    rows[4].update({"saddr": "192.168.0.5", "sport": "50000", "daddr": "1.2.3.4", "dport": "443"})
    _write_jsonl(raw, rows)

    stats = parse_file(raw, tmp_path, "TEST", Scenario.ANOMALY)
    assert stats["instances"] == 2
    assert stats["malicious_starts"] == 1

    events = pd.read_parquet(tmp_path / "TEST_anomaly_events.parquet")
    instances = pd.read_parquet(tmp_path / "TEST_anomaly_instances.parquet")
    nodes = pd.read_parquet(tmp_path / "TEST_anomaly_nodes.parquet")

    parent = instances.loc[instances["pid"] == 100].iloc[0]
    child = instances.loc[instances["pid"] == 200].iloc[0]
    assert child["parent"] == parent["instance"]
    assert child["label"] == 1
    assert parent["label"] == 0

    # Parent owns the START edge and the second read after the child exits.
    parent_events = events[events["instance"] == parent["instance"]]
    assert (parent_events["rel"] == Rel.START).sum() == 1
    assert (parent_events["rel"] == Rel.READ).sum() == 2

    # Child owns its write and connect events.
    child_events = events[events["instance"] == child["instance"]]
    assert (child_events["rel"] == Rel.WRITE).sum() == 1
    assert (child_events["rel"] == Rel.CONNECT).sum() == 1
    assert set(child_events["label"]) == {1}

    labels = nodes.set_index("id")["label"].to_dict()
    assert labels[child["node"]] == "P:cmd"
    assert any(label == "F:*:/users/*/out.txt" for label in labels.values())
    assert any(label == "S:1.2.3.4:443" for label in labels.values())


def test_pre_capture_events_get_implicit_instance(tmp_path):
    raw = tmp_path / "trace.jsonl"
    rows = [
        _file(9, 10, "FileIO/Read", r"C:\Windows\x.dll"),
        _proc(100, 1, "explorer", 20, unique="0x100"),
    ]
    _write_jsonl(raw, rows)
    parse_file(raw, tmp_path, "TEST", Scenario.BENIGN)
    instances = pd.read_parquet(tmp_path / "TEST_benign_instances.parquet")
    events = pd.read_parquet(tmp_path / "TEST_benign_events.parquet")
    implicit = instances[instances["pid"] == 9]
    assert len(implicit) == 1
    assert events.loc[events["src"] != events["dst"], "instance"].isin(implicit["instance"]).any()
