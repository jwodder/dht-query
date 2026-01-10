from __future__ import annotations
from collections.abc import Iterator
import contextlib
import json
from pathlib import Path
import random
from typing import Any
from platformdirs import user_state_path
from .consts import DEFAULT_BOOTSTRAP_NODES, TRANSACTION_ID_LEN
from .types import InetAddr, InfoHash, Node, NodeId, PrettyBytes


def gen_transaction_id() -> bytes:
    return random.randbytes(TRANSACTION_ID_LEN)


def convert_reply(raw: dict[bytes, Any], strict: bool = False) -> dict[str, Any]:
    msg = strify_keys(raw)
    if (addr := msg.get("ip")) is not None and isinstance(addr, bytes):
        with maybe_strict(strict):
            msg["ip"] = InetAddr.from_compact(addr)
    if r := msg.get("r"):
        if isinstance(r, dict):
            if (bs := r.get("id")) is not None:
                if isinstance(bs, bytes):
                    with maybe_strict(strict):
                        r["id"] = NodeId(bs)
                elif strict:
                    raise TypeError(f"r.id is {type(bs).__name__} instead of bytes")
            if (bs := r.get("nodes")) is not None:
                if isinstance(bs, bytes):
                    with maybe_strict(strict):
                        r["nodes"] = [Node.from_compact(n) for n in split_bytes(bs, 26)]
                elif strict:
                    raise TypeError(f"r.nodes is {type(bs).__name__} instead of bytes")
            if (bs := r.get("nodes6")) is not None:
                if isinstance(bs, bytes):
                    with maybe_strict(strict):
                        r["nodes6"] = [
                            Node.from_compact(n) for n in split_bytes(bs, 38)
                        ]
                elif strict:
                    raise TypeError(f"r.nodes6 is {type(bs).__name__} instead of bytes")
            if (lst := r.get("values")) is not None:
                if isinstance(lst, list):
                    with maybe_strict(strict):
                        r["values"] = [InetAddr.from_compact(v) for v in lst]
                elif strict:
                    raise TypeError(f"r.values is {type(lst).__name__} instead of list")
            if (bs := r.get("samples")) is not None:
                if isinstance(bs, bytes):
                    with maybe_strict(strict):
                        r["samples"] = [InfoHash(ih) for ih in split_bytes(bs, 20)]
                elif strict:
                    raise TypeError(
                        f"r.samples is {type(bs).__name__} instead of bytes"
                    )
            if (token := r.get("token")) is not None:
                if isinstance(token, bytes):
                    r["token"] = PrettyBytes(token)
                elif strict:
                    raise TypeError(f"r.token is {type(r).__name__} instead of bytes")
        elif strict:
            raise TypeError(f"r is {type(r).__name__} instead of dict")
    if (e := msg.get("e")) is not None:
        if isinstance(e, list):
            if len(e) >= 2:
                bs = e[1]
                if isinstance(bs, bytes):
                    e[1] = bs.decode("utf-8", "surrogateescape")
                elif strict:
                    raise TypeError(f"e.1 is {type(bs).__name__} instead of bytes")
        elif strict:
            raise TypeError(f"e is {type(e).__name__} instead of list")
    if (y := msg.get("y")) is not None:
        if isinstance(y, bytes):
            msg["y"] = y.decode("utf-8", "surrogateescape")
        elif strict:
            raise TypeError(f"y is {type(y).__name__} instead of bytes")
    if (q := msg.get("q")) is not None:
        if isinstance(q, bytes):
            msg["q"] = q.decode("utf-8", "surrogateescape")
        elif strict:
            raise TypeError(f"q is {type(q).__name__} instead of bytes")
    if (t := msg.get("t")) is not None:
        if isinstance(t, bytes):
            msg["t"] = PrettyBytes(t)
        elif strict:
            raise TypeError(f"t is {type(t).__name__} instead of bytes")
    return msg


def strify_keys(d: dict[bytes, Any]) -> dict[str, Any]:
    d2 = {}
    for kb, v in d.items():
        ks = kb.decode("utf-8", "surrogateescape")
        if isinstance(v, dict):
            v = strify_keys(v)
        d2[ks] = v
    return d2


def maybe_strict(strict: bool) -> contextlib.AbstractContextManager[None]:
    if strict:
        return contextlib.suppress(ValueError)
    else:
        return contextlib.nullcontext()


def split_bytes(bs: bytes, size: int) -> Iterator[bytes]:
    while bs:
        if len(bs) >= size:
            yield bs[:size]
        else:
            raise ValueError("short bytes")
        bs = bs[size:]


def node_id_file() -> Path:
    return user_state_path("dht-query", "jwodder") / "node-id.dat"


def get_node_id() -> NodeId:
    try:
        return NodeId(node_id_file().read_bytes())
    except FileNotFoundError:
        raise RuntimeError("No node ID set; generate one with `set-node-id` subcommand")


def set_node_id(bs: NodeId) -> None:
    p = node_id_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(bytes(bs))


def quantify(qty: int, singular: str, plural: str | None = None) -> str:
    # cf. the humanfriendly package's pluralize() function
    if qty == 1:
        return f"{qty} {singular}"
    elif plural is None:
        return f"{qty} {singular}s"
    else:
        return f"{qty} {plural}"


def jsonify(obj: Any) -> str:
    return json.dumps(obj, indent=4, default=for_json)


def for_json(obj: Any) -> Any:
    if hasattr(obj, "for_json"):
        return obj.for_json()
    elif isinstance(obj, bytes):
        return obj.hex()
    else:
        raise TypeError(type(obj).__name__)


def get_default_bootstrap_nodes() -> list[InetAddr]:
    return [InetAddr.parse(n) for n in DEFAULT_BOOTSTRAP_NODES]
