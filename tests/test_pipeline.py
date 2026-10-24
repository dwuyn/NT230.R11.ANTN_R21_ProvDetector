import json

import numpy as np

from src.detect.lof import LOFDetector, aggregate_instances, path_threshold
from src.embed.doc2vec import PathEncoder
from src.graph.build import FrequencyDB, Trace
from src.ingest.parse_pku import parse_file
from src.ingest.schema import Scenario
from src.select.paths import select_paths
from src.util.metrics import binary_metrics


def _proc(pid, ppid, name, ms, warn=False, unique="0xA"):
    return {
        "MSec": str(ms), "PID": str(pid), "PName": name, "TID": "-1",
        "EventName": "Process/Start", "ProcessID": str(pid), "ParentID": str(ppid),
        "ImageFileName": name + ".exe", "UniqueProcessKey": unique,
        "CommandLine": name, "is_warn": "True" if warn else "False", "PPName": "p",
    }


def _file(pid, ms, event, path):
    return {"MSec": str(ms), "PID": str(pid), "PName": "x", "EventName": event, "FileName": path}


def test_rarest_path_prefers_child_write(tmp_path):
    rows = [
        _proc(100, 1, "explorer", 100, unique="0x100"),
        _file(100, 110, "FileIO/Read", r"C:\Windows\common.dll"),
        _file(100, 120, "FileIO/Read", r"C:\Windows\common.dll"),
        _proc(200, 100, "cmd", 130, warn=True, unique="0x200"),
        _file(200, 140, "FileIO/Write", r"C:\Users\Bob\rare.txt"),
        _file(200, 150, "TcpIp/Send", "net"),
        _proc(300, 1, "benign", 100, unique="0x300"),
        _file(300, 110, "FileIO/Read", r"C:\Windows\common.dll"),
    ]
    rows[5].update({"saddr": "192.168.0.5", "sport": "50000", "daddr": "1.2.3.4", "dport": "443"})
    raw = tmp_path / "t.jsonl"
    with open(raw, "w") as handle:
        handle.writelines(json.dumps(row) + "\n" for row in rows)
    parse_file(raw, tmp_path, "TEST", Scenario.ANOMALY)

    trace = Trace.load(tmp_path, "TEST", Scenario.ANOMALY)
    benign_like = [i for i in trace.instance_ids if trace.instances.loc[i, "pid"] == 100]
    db = FrequencyDB.build(trace, benign_like)
    mal = trace.instances[trace.instances["pid"] == 200].index[0]
    paths = select_paths(trace, mal, db, k=5)
    assert paths
    # The child write is rarer than the parent's common read.
    assert any("F:*:/users/*/rare.txt" in path.tokens for path in paths)
    # And the parent's own graph can reach the child through the START edge.
    parent = trace.instances[trace.instances["pid"] == 100].index[0]
    parent_paths = select_paths(trace, parent, db, k=5)
    assert any("P:cmd" in path.tokens for path in parent_paths)


def test_doc2vec_and_lof_are_repeatable():
    sentences = [
        ["P:cmd", "WRITE", "F:a"],
        ["P:cmd", "WRITE", "F:b"],
        ["P:explorer", "READ", "F:c"],
        ["P:explorer", "READ", "F:d"],
    ]
    first = PathEncoder(epochs=20, seed=7).fit(sentences).transform(sentences)
    second = PathEncoder(epochs=20, seed=7).fit(sentences).transform(sentences)
    assert np.allclose(first, second)
    detector = LOFDetector(n_neighbors=2).fit(first)
    scores = detector.score(first)
    assert scores.shape == (4,)
    threshold = path_threshold(scores, 0.25)
    assert aggregate_instances({0: scores[:1], 1: scores[1:]}, threshold, t=1)[0] in (0, 1)


def test_metrics():
    metrics = binary_metrics([1, 0, 1, 0], [1, 0, 0, 1])
    assert metrics["tp"] == 1 and metrics["fn"] == 1 and metrics["fp"] == 1
    assert metrics["f1"] == 0.5
