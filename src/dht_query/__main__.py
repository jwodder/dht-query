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
from .consts import CLIENT, DEFAULT_TIMEOUT, UDP_PACKET_LEN
from .search_peers import DEFAULT_BOOTSTRAP_NODE, DEFAULT_SIMILARITY_TARGET, SearchPeers
from .types import InetAddr, InfoHash, NodeId
from .util import (
    convert_reply,
    gen_transaction_id,
    get_node_id,
    jsonify,
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


class BytesParam(click.ParamType):
    name = "bytes"

    def convert(
        self,
        value: str | bytes,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> bytes:
        if isinstance(value, str):
            try:
                return bytes.fromhex(value)
            except ValueError as e:
                self.fail(f"{value!r}: {e}", param, ctx)
        else:
            return value

    def get_metavar(
        self, param: click.Parameter, ctx: click.Context | None = None  # noqa: U100
    ) -> str:
        return "HEXBYTES"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main() -> None:
    """Query the DHT"""
    pass


@main.command()
@click.option("-J", "--json", is_flag=True, help="Display response as JSON")
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.argument("addr", type=InetAddrParam())
def ping(addr: InetAddr, timeout: float, json: bool) -> None:
    """Send a "ping" query to a node and pretty-print the decoded response"""
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"ping",
        b"a": {b"id": bytes(get_node_id())},
        b"v": CLIENT,
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    if json:
        print(jsonify(msg))
    else:
        pprint(msg)


@main.command()
@click.option("-J", "--json", is_flag=True, help="Display response as JSON")
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.option("--want4", is_flag=True, help="Request IPv4 nodes")
@click.option("--want6", is_flag=True, help="Request IPv6 nodes")
@click.argument("addr", type=InetAddrParam())
@click.argument("info_hash", type=InfoHashParam())
def get_peers(
    addr: InetAddr,
    info_hash: InfoHash,
    timeout: float,
    json: bool,
    want4: bool,
    want6: bool,
) -> None:
    """Send a "get_peers" query to a node and pretty-print the decoded response"""
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"get_peers",
        b"a": {
            b"id": bytes(get_node_id()),
            b"info_hash": bytes(info_hash),
        },
        b"v": CLIENT,
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
    if json:
        print(jsonify(msg))
    else:
        pprint(msg)


@main.command()
@click.option("-J", "--json", is_flag=True, help="Display response as JSON")
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.option("--want4", is_flag=True, help="Request IPv4 nodes")
@click.option("--want6", is_flag=True, help="Request IPv6 nodes")
@click.argument("addr", type=InetAddrParam())
@click.argument("node_id", type=NodeIdParam())
def find_node(
    addr: InetAddr,
    node_id: NodeId,
    timeout: float,
    json: bool,
    want4: bool,
    want6: bool,
) -> None:
    """Send a "find_node" query to a node and pretty-print the decoded response"""
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"find_node",
        b"a": {
            b"id": bytes(get_node_id()),
            b"target": bytes(node_id),
        },
        b"v": CLIENT,
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
    if json:
        print(jsonify(msg))
    else:
        pprint(msg)


@main.command()
@click.option("-J", "--json", is_flag=True, help="Display response as JSON")
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.argument("addr", type=InetAddrParam())
@click.argument("info_hash", type=InfoHashParam())
@click.argument("port", type=int)
@click.argument("token", type=BytesParam())
def announce_peer(
    addr: InetAddr,
    info_hash: InfoHash,
    port: int,
    token: bytes,
    timeout: float,
    json: bool,
) -> None:
    """Send an "announce_peer" query to a node and pretty-print the decoded response"""
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"announce_peer",
        b"a": {
            b"id": bytes(get_node_id()),
            b"info_hash": bytes(info_hash),
            b"port": port,
            b"token": token,
        },
        b"v": CLIENT,
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    if json:
        print(jsonify(msg))
    else:
        pprint(msg)


@main.command()
@click.option("-J", "--json", is_flag=True, help="Display response as JSON")
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.argument("addr", type=InetAddrParam())
@click.argument("target", type=NodeIdParam())
def sample_infohashes(
    addr: InetAddr, target: NodeId, timeout: float, json: bool
) -> None:
    """
    Send a "sample_infohashes" query to a node and pretty-print the decoded
    response
    """
    query: dict[bytes, Any] = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"sample_infohashes",
        b"a": {
            b"id": bytes(get_node_id()),
            b"target": bytes(target),
        },
        b"v": CLIENT,
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    if json:
        print(jsonify(msg))
    else:
        pprint(msg)


@main.command()
@click.option("-J", "--json", is_flag=True, help="Display response as JSON")
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.argument("addr", type=InetAddrParam())
def error(addr: InetAddr, timeout: float, json: bool) -> None:
    """
    Send a query with an invalid method to a node and pretty-print the decoded
    response
    """
    query = {
        b"t": gen_transaction_id(),
        b"y": b"q",
        b"q": b"poke",
        b"a": {b"id": bytes(get_node_id())},
        b"v": CLIENT,
        b"ro": 1,
    }
    reply = chat(addr, bencode(query), timeout=timeout)
    msg = convert_reply(unbencode(reply))
    if json:
        print(jsonify(msg))
    else:
        pprint(msg)


@main.command("get-node-id")
def get_node_id_cmd() -> None:
    """Print out the locally-stored node ID in hexadecimal"""
    print(get_node_id())


@main.command("set-node-id")
@click.option(
    "--ip",
    type=IPParam(),
    help="Make the new ID valid for the given IP address according to BEP 42",
)
def set_node_id_cmd(ip: IPv4Address | IPv6Address | None) -> None:
    """Randomly generate & store a new node ID to use in outgoing queries"""
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


@main.command()
@click.option(
    "-a",
    "--all-peers",
    is_flag=True,
    help="Print out all peers found rather than just those from the last response",
)
@click.option(
    "-B",
    "--bootstrap-node",
    type=InetAddrParam(),
    default=DEFAULT_BOOTSTRAP_NODE,
    help="Make the initial query to the given node",
    show_default=True,
)
@click.option(
    "-o",
    "--outfile",
    type=click.File("w"),
    default="-",
    help="Write the peers to the given file instead of stdout",
)
@click.option(
    "-s",
    "--similarity",
    type=int,
    default=DEFAULT_SIMILARITY_TARGET,
    help=(
        "Don't stop until after peers are received from a node whose ID matches"
        " the infohash in this many leading bits"
    ),
    show_default=True,
)
@click.option(
    "-t",
    "--timeout",
    type=float,
    default=DEFAULT_TIMEOUT,
    help="Maximum number of seconds to wait for a reply to a query",
    show_default=True,
)
@click.argument("info_hash", type=InfoHashParam())
def search_peers(
    info_hash: InfoHash,
    outfile: IO[str],
    timeout: float,
    similarity: int,
    all_peers: bool,
    bootstrap_node: InetAddr,
) -> None:
    """
    Do a simple search for peers downloading the torrent with the given
    infohash
    """
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
    search = SearchPeers(
        info_hash=info_hash,
        timeout=timeout,
        similarity_target=similarity,
        all_peers=all_peers,
        bootstrap_node=bootstrap_node,
    )
    peers = anyio.run(search.run)
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
