from __future__ import annotations
from binascii import crc32
from ipaddress import IPv4Address, IPv6Address
import logging
from pprint import pprint
import random
import re
import socket
import sys
from typing import IO, Any
import anyio
import click
import colorlog
from .bencode import bencode, unbencode
from .consts import DEFAULT_TIMEOUT, UDP_PACKET_LEN
from .lookup import DEFAULT_SIMILARITY_TARGET, Lookup
from .types import InetAddr, InfoHash, NodeId
from .util import (
    convert_reply,
    gen_transaction_id,
    get_node_id,
    set_node_id,
)


class InetAddrParam(click.ParamType):
    name = "inetaddr"

    def convert(
        self,
        value: str | InetAddr,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> InetAddr:
        if isinstance(value, str):
            try:
                return InetAddr.parse(value)
            except ValueError as e:
                self.fail(f"{value!r}: {e}", param, ctx)
        else:
            return value

    def get_metavar(
        self, param: click.Parameter, ctx: click.Context | None = None  # noqa: U100
    ) -> str:
        return "HOST:PORT"


class InfoHashParam(click.ParamType):
    name = "infohash"

    def convert(
        self,
        value: str | InfoHash,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> InfoHash:
        if isinstance(value, str):
            try:
                return InfoHash(value)
            except ValueError as e:
                self.fail(f"{value!r}: {e}", param, ctx)
        else:
            return value

    def get_metavar(
        self, param: click.Parameter, ctx: click.Context | None = None  # noqa: U100
    ) -> str:
        return "INFOHASH"


class NodeIdParam(click.ParamType):
    name = "node-id"

    def convert(
        self,
        value: str | NodeId,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> NodeId:
        if isinstance(value, str):
            try:
                return NodeId(value)
            except ValueError as e:
                self.fail(f"{value!r}: {e}", param, ctx)
        else:
            return value

    def get_metavar(
        self, param: click.Parameter, ctx: click.Context | None = None  # noqa: U100
    ) -> str:
        return "NODEID"


class IPParam(click.ParamType):
    name = "ip"

    def convert(
        self,
        value: str | IPv4Address | IPv6Address,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> IPv4Address | IPv6Address:
        if isinstance(value, str):
            try:
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
                    return IPv4Address(value)
                elif re.fullmatch(r"[A-Fa-f0-9:]+", value):
                    return IPv6Address(value)
                else:
                    raise ValueError("not an IP address")
            except ValueError as e:
                self.fail(f"{value!r}: {e}", param, ctx)
        else:
            return value

    def get_metavar(
        self, param: click.Parameter, ctx: click.Context | None = None  # noqa: U100
    ) -> str:
        return "IP"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main() -> None:
    """Query the DHT"""
    pass


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.argument("addr", type=InetAddrParam())
def ping(addr: InetAddr, timeout: float) -> None:
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"ping",
        b"a": {b"id": bytes(get_node_id())},
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    pprint(msg)


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.option("--want4", is_flag=True)
@click.option("--want6", is_flag=True)
@click.argument("addr", type=InetAddrParam())
@click.argument("info_hash", type=InfoHashParam())
def get_peers(
    addr: InetAddr, info_hash: InfoHash, timeout: float, want4: bool, want6: bool
) -> None:
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"get_peers",
        b"a": {
            b"id": bytes(get_node_id()),
            b"info_hash": bytes(info_hash),
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
    msg = convert_reply(unbencode(reply))
    pprint(msg)


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.option("--want4", is_flag=True)
@click.option("--want6", is_flag=True)
@click.argument("addr", type=InetAddrParam())
@click.argument("node_id", type=NodeIdParam())
def find_node(
    addr: InetAddr, node_id: NodeId, timeout: float, want4: bool, want6: bool
) -> None:
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"find_node",
        b"a": {
            b"id": bytes(get_node_id()),
            b"target": bytes(node_id),
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
    msg = convert_reply(unbencode(reply))
    pprint(msg)


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.argument("addr", type=InetAddrParam())
@click.argument("target", type=NodeIdParam())
def sample_infohashes(addr: InetAddr, target: NodeId, timeout: float) -> None:
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"sample_infohashes",
        b"a": {
            b"id": bytes(get_node_id()),
            b"target": bytes(target),
        },
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    pprint(msg)


@main.command()
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.argument("addr", type=InetAddrParam())
def error(addr: InetAddr, timeout: float) -> None:
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"poke",
        b"a": {b"id": bytes(get_node_id())},
        b"v": b"TEST",
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    pprint(msg)


@main.command("get-node-id")
def get_node_id_cmd() -> None:
    print(get_node_id())


@main.command("set-node-id")
@click.option("--ip", type=IPParam())
def set_node_id_cmd(ip: IPv4Address | IPv6Address | None) -> None:
    if ip is None:
        node_id = NodeId(random.randbytes(20))
    else:
        if isinstance(ip, IPv4Address):
            mask = [0x03, 0x0F, 0x3F, 0xFF]
        else:
            mask = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF]
        ba = bytearray([b1 & b2 for b1, b2 in zip(ip.packed, mask)])
        rand = random.randrange(256)
        ba[0] |= (rand & 0x07) << 5
        crc = crc32(ba)
        node_id0 = bytearray()
        node_id0.append((crc >> 24) & 0xFF)
        node_id0.append((crc >> 16) & 0xFF)
        node_id0.append(((crc >> 8) & 0xF8) | random.randrange(8))
        node_id0.extend(random.randbytes(16))
        node_id0.append(rand)
        node_id = NodeId(bytes(node_id0))
    print(node_id)
    set_node_id(node_id)


@main.command("lookup")
@click.option("-a", "--all-peers", is_flag=True)
@click.option("-B", "--bootstrap-node", type=InetAddrParam())
@click.option("-s", "--similarity", type=int, default=DEFAULT_SIMILARITY_TARGET)
@click.option("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
@click.option("-o", "--outfile", type=click.File("w"), default="-")
@click.argument("info_hash", type=InfoHashParam())
def lookup_cmd(
    info_hash: InfoHash,
    outfile: IO[str],
    timeout: float,
    similarity: int,
    all_peers: bool,
    bootstrap_node: InetAddr | None,
) -> None:
    colorlog.basicConfig(
        format="%(log_color)s%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "bold",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        },
        level=logging.DEBUG,
        stream=sys.stderr,
    )
    lkp = Lookup(
        info_hash=info_hash,
        timeout=timeout,
        similarity_target=similarity,
        all_peers=all_peers,
    )
    if bootstrap_node is not None:
        lkp.bootstrap_node = bootstrap_node
    peers = anyio.run(lkp.run)
    with outfile:
        for p in sorted(peers):
            print(p, file=outfile)


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


if __name__ == "__main__":
    main()
