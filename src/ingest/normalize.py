"""Entity/path abstraction used by the R21 pipeline.

The paper abstracts user names out of file paths and drops local endpoints of
sockets.  We follow that, and additionally lowercase everything so that
Windows' case-insensitive paths collapse to one node.
"""
from __future__ import annotations

import ipaddress
import os
import re

_DRIVE_USER = re.compile(r"^([a-z]):/users/[^/]+/")
_HOME = re.compile(r"^/home/[^/]+/")
_ROOT_HOME = re.compile(r"^/root/")
_LONG_PREFIX = re.compile(r"^\\\\\?\\")


def normalize_name(name: str) -> str:
    """Normalise a process image name to a stable label."""
    if not name:
        return "unknown"
    value = name.replace("\\", "/").strip().lower()
    # Windows images are often given with an absolute path.
    base = value.rsplit("/", 1)[-1]
    return base or "unknown"


def abstract_path(path: str) -> str:
    """Abstract a file path: lowercase, forward slashes, wildcard user/home."""
    if not path:
        return "<unknown>"
    value = path.replace("\\", "/").strip().lower()
    value = _LONG_PREFIX.sub("", value)
    value = _DRIVE_USER.sub(r"*:/users/*/", value)
    value = _HOME.sub("/home/*/", value)
    value = _ROOT_HOME.sub("/root/*/", value)
    # Collapse repeated separators without touching the scheme-like prefix.
    value = re.sub(r"/{2,}", "/", value)
    return value


def _is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def socket_endpoint(src_ip: str, src_port: str, dst_ip: str, dst_port: str) -> str:
    """Return the remote endpoint of a flow.

    PCT traces do not carry a local-address list, so RFC1918/loopback is used
    as the local-endpoint heuristic.  If both ends are public we keep the
    destination (outbound convention).
    """
    sport = str(src_port).split(",")[-1].strip()
    dport = str(dst_port).split(",")[-1].strip()
    if _is_private(src_ip) and not _is_private(dst_ip):
        return f"{dst_ip}:{dport}"
    if _is_private(dst_ip) and not _is_private(src_ip):
        return f"{src_ip}:{sport}"
    if _is_private(src_ip) and _is_private(dst_ip):
        # Internal flow: keep the destination; both ends are local.
        return f"{dst_ip}:{dport}"
    return f"{dst_ip}:{dport}"


def node_label(node_type: int, label: str) -> str:
    prefix = {0: "P", 1: "F", 2: "S"}[int(node_type)]
    return f"{prefix}:{label}"


def basename(path: str) -> str:
    return os.path.basename(path.replace("\\", "/"))
