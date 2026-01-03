from __future__ import annotations
from collections.abc import Iterator
from pathlib import Path
import random
from typing import Any
from platformdirs import user_state_path
from .consts import TRANSACTION_ID_LEN
from .types import InetAddr, Node


def gen_transaction_id() -> bytes:
    return random.randbytes(TRANSACTION_ID_LEN)


def expand_ip(msg: dict[bytes, Any]) -> None:
    if (addr := msg.get(b"ip")) is not None and isinstance(addr, bytes):
        try:
            msg[b"ip"] = InetAddr.from_compact(addr)
        except ValueError:
            pass


def expand_nodes(msg: dict[bytes, Any]) -> None:
    if (bs := msg.get(b"r", {}).get(b"nodes")) is not None and isinstance(bs, bytes):
        try:
            nodes = [Node.from_compact(n) for n in split_bytes(bs, 26)]
        except ValueError:
            pass
        else:
            msg[b"r"][b"nodes"] = nodes
    if (bs := msg.get(b"r", {}).get(b"nodes6")) is not None and isinstance(bs, bytes):
        try:
            nodes = [Node.from_compact(n) for n in split_bytes(bs, 38)]
        except ValueError:
            pass
        else:
            msg[b"r"][b"nodes6"] = nodes


def expand_values(msg: dict[bytes, Any]) -> None:
    if (lst := msg.get(b"r", {}).get(b"values")) is not None and isinstance(lst, list):
        try:
            lst2 = [InetAddr.from_compact(v) for v in lst]
        except ValueError:
            pass
        else:
            msg[b"r"][b"values"] = lst2


def split_bytes(bs: bytes, size: int) -> Iterator[bytes]:
    while bs:
        if len(bs) >= size:
            yield bs[:size]
        else:
            raise ValueError("short bytes")
        bs = bs[size:]


def node_id_file() -> Path:
    return user_state_path("dht-query", "jwodder") / "node-id.dat"


def get_node_id() -> bytes:
    try:
        return node_id_file().read_bytes()
    except FileNotFoundError:
        raise RuntimeError("No node ID set; generate one with `set-node-id` subcommand")


def set_node_id(bs: bytes) -> None:
    p = node_id_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(bs)
