from __future__ import annotations
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pprint import pprint
import random
import socket
from typing import Any
import click
from .bencode import bencode, unbencode

MY_NODE_ID = bytes.fromhex("e2bbceb25a531beca0489e46fd2a68b084363c09")

UDP_PACKET_LEN = 65535

TRANSACTION_ID_LEN = 2

TIMEOUT = 60


@dataclass
class InetAddr:
    host: str
    port: int

    @classmethod
    def parse(cls, s: str) -> InetAddr:
        host, colon, port_str = s.partition(":")
        if not colon:
            raise ValueError(f"invalid address: {s!r}")
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"invalid address: {s!r}")
        return cls(host=host, port=port)


@dataclass
class Node:
    id: bytes
    ip: IPv4Address | IPv6Address
    port: int

    @classmethod
    def from_compact(cls, bs: bytes) -> Node:
        nid = bs[:20]
        (ip, port) = uncompact_addr(bs[20:])
        return cls(id=nid, ip=ip, port=port)


def parse_info_hash(s: str) -> bytes:
    bs = bytes.fromhex(s)
    if len(bs) != 20:
        raise ValueError("info hashes must be 20 bytes long")
    return bs


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main() -> None:
    """Query the DHT"""
    pass


@main.command()
@click.argument("addr", type=InetAddr.parse)
def ping(addr: InetAddr) -> None:
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"ping",
        b"a": {b"id": MY_NODE_ID},
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query))
    msg = unbencode(reply)
    expand_ip(msg)
    pprint(msg)


@main.command()
@click.option("--want4", is_flag=True)
@click.option("--want6", is_flag=True)
@click.argument("addr", type=InetAddr.parse)
@click.argument("infohash", type=parse_info_hash)
def get_peers(addr: InetAddr, infohash: bytes, want4: bool, want6: bool) -> None:
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"get_peers",
        b"a": {
            b"id": MY_NODE_ID,
            b"info_hash": infohash,
        },
        b"v": b"TEST",
        b"ro": 1,
    }
    if want4 or want6:
        want = []
        if want4:
            want.append(b"n4")
        if want6:
            want.append(b"n6")
        query[b"a"][b"want"] = want
    reply = chat(addr, bencode(query))
    msg = unbencode(reply)
    expand_ip(msg)
    expand_nodes(msg)
    expand_values(msg)
    pprint(msg)


@main.command()
@click.argument("addr", type=InetAddr.parse)
def error(addr: InetAddr) -> None:
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"poke",
        b"a": {b"id": MY_NODE_ID},
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query))
    msg = unbencode(reply)
    expand_ip(msg)
    pprint(msg)


def chat(addr: InetAddr, msg: bytes) -> bytes:
    with socket.socket(type=socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.bind(("0.0.0.0", 0))
        s.connect((addr.host, addr.port))
        s.send(msg)
        return s.recv(UDP_PACKET_LEN)


def gen_transaction_id() -> bytes:
    return random.randbytes(TRANSACTION_ID_LEN)


def expand_ip(msg: dict[bytes, Any]) -> None:
    if (addr := msg.get(b"ip")) is not None and isinstance(addr, bytes):
        try:
            msg[b"ip"] = uncompact_addr(addr)
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
            lst2 = [uncompact_addr(v) for v in lst]
        except ValueError:
            pass
        else:
            msg[b"r"][b"values"] = lst2


def uncompact_addr(bs: bytes) -> tuple[IPv4Address | IPv6Address, int]:
    if len(bs) == 6:
        ip4 = IPv4Address(bs[:4])
        port = int.from_bytes(bs[4:])
        return (ip4, port)
    elif len(bs) == 18:
        ip6 = IPv6Address(bs[:16])
        port = int.from_bytes(bs[16:])
        return (ip6, port)
    else:
        raise ValueError(f"Compact address has invalid length {len(bs)}")


def split_bytes(bs: bytes, size: int) -> Iterator[bytes]:
    while bs:
        if len(bs) >= size:
            yield bs[:size]
        else:
            raise ValueError("short bytes")
        bs = bs[size:]


if __name__ == "__main__":
    main()
