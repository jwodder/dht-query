from __future__ import annotations
from binascii import crc32
from ipaddress import IPv4Address
import logging
from pprint import pprint
import random
import socket
import sys
from typing import IO, Any
import anyio
import click
import colorlog
from .bencode import bencode, unbencode
from .consts import DEFAULT_TIMEOUT, UDP_PACKET_LEN
from .lookup import lookup
from .types import InetAddr, parse_info_hash
from .util import (
    expand_ip,
    expand_nodes,
    expand_values,
    gen_transaction_id,
    get_node_id,
    set_node_id,
)


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


@main.command("lookup")
@click.option("-o", "--outfile", type=click.File("w"), default="-")
@click.argument("info_hash", type=parse_info_hash)
def lookup_cmd(info_hash: bytes, outfile: IO[str]) -> None:
    colorlog.basicConfig(
        format="%(log_color)s[%(levelname)-8s] %(message)s",
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
    peers = anyio.run(lookup, info_hash)
    with outfile:
        for p in peers:
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
