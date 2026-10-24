"""Shared provenance schema for the R21 reproduction.

Event relations follow ProvDetector Table I: only a process can be the source
of an edge.  END edges are not materialised (they carry no path information);
the process lifetime is represented by the instance interval instead.
"""
from __future__ import annotations

from enum import IntEnum


class Rel(IntEnum):
    START = 0
    READ = 1
    WRITE = 2
    EXECUTE = 3
    CONNECT = 4


REL_NAMES = {int(r): r.name for r in Rel}
REL_NAME_TO_CODE = {r.name: int(r) for r in Rel}


class NodeType(IntEnum):
    PROCESS = 0
    FILE = 1
    SOCKET = 2


class Scenario(IntEnum):
    BENIGN = 0
    ANOMALY = 1


EVENT_COLUMNS = ["ts", "instance", "src", "dst", "rel", "label"]
NODE_COLUMNS = ["id", "type", "label"]
INSTANCE_COLUMNS = [
    "instance",
    "parent",
    "node",
    "label",
    "pid",
    "ppid",
    "name",
    "cmdline",
    "start",
    "end",
    "scenario",
    "dataset",
]
