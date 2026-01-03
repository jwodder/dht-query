from __future__ import annotations
from binascii import crc32
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from pprint import pprint
import random
import re
import socket
from typing import Any
import click
from platformdirs import user_state_path
from .bencode import bencode, unbencode

UDP_PACKET_LEN = 65535

TRANSACTION_ID_LEN = 2

DEFAULT_TIMEOUT = 15.0


@dataclass
class InetAddr:
    host: str | IPv4Address | IPv6Address
    port: int

    @classmethod
    def parse(cls, s: str) -> InetAddr:
        host: str | IPv4Address | IPv6Address
        if m := re.fullmatch(r"(\d+\.\d+\.\d+\.\d+):(\d+)", s):
            host = IPv4Address(m[1])
            port = int(m[2])
        elif m := re.fullmatch(r"\[([A-Fa-f0-9:]+)\]:(\d+)", s):
            host = IPv6Address(m[1])
            port = int(m[2])
        else:
            host, colon, port_str = s.partition(":")
            if not colon:
                raise ValueError(f"invalid address: {s!r}")
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"invalid address: {s!r}")
        return cls(host=host, port=port)

    def resolve(self) -> tuple[socket.AddressFamily, str, int]:
        if isinstance(self.host, str):
            (family, _, _, _, addr) = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_DGRAM
            )[0]
            ip = addr[0]
            port = addr[1]
            assert isinstance(ip, str)
            assert isinstance(port, int)
            return (family, ip, port)
        elif isinstance(self.host, IPv4Address):
            return (socket.AF_INET, str(self.host), self.port)
        else:
            assert isinstance(self.host, IPv6Address)
            return (socket.AF_INET6, str(self.host), self.port)


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
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.argument("addr", type=InetAddr.parse)
def ping(addr: InetAddr, timeout: float) -> None:
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"ping",
        b"a": {b"id": get_node_id()},
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = unbencode(reply)
    expand_ip(msg)
    pprint(msg)


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.option("--want4", is_flag=True)
@click.option("--want6", is_flag=True)
@click.argument("addr", type=InetAddr.parse)
@click.argument("infohash", type=parse_info_hash)
def get_peers(
    addr: InetAddr, infohash: bytes, timeout: float, want4: bool, want6: bool
) -> None:
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"get_peers",
        b"a": {
            b"id": get_node_id(),
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
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = unbencode(reply)
    expand_ip(msg)
    expand_nodes(msg)
    expand_values(msg)
    pprint(msg)


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.argument("addr", type=InetAddr.parse)
def error(addr: InetAddr, timeout: float) -> None:
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"poke",
        b"a": {b"id": get_node_id()},
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = unbencode(reply)
    expand_ip(msg)
    pprint(msg)


@main.command("get-node-id")
def get_node_id_cmd() -> None:
    print(get_node_id().hex())


@main.command("set-node-id")
@click.option("--ip", type=IPv4Address)
def set_node_id_cmd(ip: IPv4Address | None) -> None:
    if ip is None:
        node_id = random.randbytes(20)
    else:
        ba = bytearray(ip.packed)
        ba[0] &= 0x03
        ba[1] &= 0x0F
        ba[2] &= 0x3F
        ba[3] &= 0xFF
        rand = random.randrange(256)
        ba[0] |= (rand & 0x07) << 5
        crc = crc32(ba)
        node_id0 = bytearray()
        node_id0.append((crc >> 24) & 0xFF)
        node_id0.append((crc >> 16) & 0xFF)
        node_id0.append(((crc >> 8) & 0xF8) | random.randrange(8))
        node_id0.extend(random.randbytes(16))
        node_id0.append(rand)
        node_id = bytes(node_id0)
    print(node_id.hex())
    set_node_id(node_id)


def chat(addr: InetAddr, msg: bytes, timeout: float = DEFAULT_TIMEOUT) -> bytes:
    (family, ip, port) = addr.resolve()
    with socket.socket(family=family, type=socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        if family is socket.AF_INET:
            s.bind(("0.0.0.0", 0))
        else:
            assert family is socket.AF_INET6
            s.bind(("::", 0))
        s.connect((ip, port))
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


if __name__ == "__main__":
    main()
