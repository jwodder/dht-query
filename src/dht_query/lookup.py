from __future__ import annotations
from dataclasses import dataclass, field
import heapq
import logging
import socket
from typing import Any
from anyio import create_udp_socket, fail_after
from anyio.abc import AsyncResource, UDPSocket
from .bencode import UnbencodeError, bencode, unbencode
from .consts import DEFAULT_TIMEOUT
from .types import InetAddr, Node
from .util import expand_nodes, expand_values, gen_transaction_id, get_node_id

DEFAULT_BOOTSTRAP_NODE = InetAddr(host="router.bittorrent.com", port=6881)

DEFAULT_SIMILARITY_TARGET = 10

log = logging.getLogger(__name__)


@dataclass
class Lookup:
    info_hash: bytes
    timeout: float = DEFAULT_TIMEOUT
    similarity_target: int = DEFAULT_SIMILARITY_TARGET
    all_peers: bool = False
    bootstrap_node: InetAddr = DEFAULT_BOOTSTRAP_NODE

    async def run(self) -> list[InetAddr]:
        nodes = NodeTable(self.info_hash)
        peer_set = set()
        async with await create_dht_client(get_node_id()) as client:
            log.info('Issuing "get_peers" query to bootstrap node ...')
            r = await client.get_peers(
                self.bootstrap_node, self.info_hash, timeout=self.timeout
            )
            log.info(
                "Bootstrap node returned %d peer(s) and %d node(s)",
                len(r.peers),
                len(r.nodes),
            )
            peer_set.update(r.peers)
            nodes.extend(r.nodes)
            while (n := nodes.pop_nearest()) is not None:
                try:
                    log.info(
                        'Issuing "get_peers" query to node %s at %s ...',
                        n.id.hex(),
                        n.address,
                    )
                    r = await client.get_peers(
                        n.address, self.info_hash, timeout=self.timeout
                    )
                except (
                    DhtProtoError,
                    OSError,
                    TypeError,
                    UnbencodeError,
                    ValueError,
                ) as e:
                    log.warning(
                        "Error communicating with node: %s: %s",
                        type(e).__name__,
                        str(e),
                    )
                else:
                    log.info(
                        "Node returned %d peer(s) and %d node(s)",
                        len(r.peers),
                        len(r.nodes),
                    )
                    peer_set.update(r.peers)
                    nodes.extend(r.nodes)
                    if (
                        similarity(n.id, self.info_hash) >= self.similarity_target
                        and r.peers
                    ):
                        if self.all_peers:
                            return list(peer_set)
                        else:
                            return r.peers
            raise RuntimeError("Could not find close enough node with peers")


@dataclass
class DhtClient(AsyncResource):
    node_id: bytes
    ipv4: UDPSocket
    ipv6: UDPSocket

    async def aclose(self) -> None:
        await self.ipv4.aclose()
        await self.ipv6.aclose()

    async def get_peers(
        self, addr: InetAddr, info_hash: bytes, timeout: float = DEFAULT_TIMEOUT
    ) -> GetPeersResponse:
        txn_id = gen_transaction_id()
        query: dict[bytes, Any] = {
            b"t": txn_id,
            b"y": b"q",
            b"q": b"get_peers",
            b"a": {
                b"id": self.node_id,
                b"info_hash": info_hash,
                b"want": [b"n4", b"n6"],
            },
            b"v": b"TEST",
            b"ro": 1,
        }
        reply = await self.chat(addr, bencode(query), timeout=timeout)
        msg = unbencode(reply)
        match msg.get(b"y"):
            case b"r":
                if msg.get(b"t") != txn_id:
                    raise DhtProtoError(
                        "Node replied with different transaction ID than was in query"
                    )
                expand_nodes(msg, strict=True)
                expand_values(msg, strict=True)
                peers = msg.get(b"r", {}).get(b"values", [])
                assert isinstance(peers, list)
                nodes4 = msg.get(b"r", {}).get(b"nodes", [])
                assert isinstance(nodes4, list)
                nodes6 = msg.get(b"r", {}).get(b"nodes6", [])
                assert isinstance(nodes6, list)
                return GetPeersResponse(peers=peers, nodes=nodes4 + nodes6)
            case b"e":
                elst = msg.get(b"e", [])
                raise DhtProtoError(f"Node replied with error message: {elst!r}")
            case other:
                raise DhtProtoError(
                    f"Node replied with unexpected message type {other!r}"
                )

    async def chat(
        self, addr: InetAddr, msg: bytes, timeout: float = DEFAULT_TIMEOUT
    ) -> bytes:
        (family, ip, port) = addr.resolve()
        if family is socket.AF_INET:
            s = self.ipv4
        else:
            assert family is socket.AF_INET6
            s = self.ipv6
        await s.sendto(msg, ip, port)
        with fail_after(timeout):
            async for in_msg, (in_ip, in_port) in s:
                if in_ip == ip and in_port == port:
                    return in_msg
                else:
                    log.warning(
                        "Received unexpected UDP packet from %s; ignoring",
                        InetAddr.from_pair(in_ip, in_port),
                    )
        raise RuntimeError("Local UDP socket closed")


@dataclass
class GetPeersResponse:
    peers: list[InetAddr]
    nodes: list[Node]


@dataclass
class NodeTable:
    info_hash: bytes
    counter: int = field(init=False, default=0)
    nodes: list[tuple[int, int, Node]] = field(init=False, default_factory=list)
    seen_addrs: set[InetAddr] = field(init=False, default_factory=set)

    def extend(self, nodes: list[Node]) -> None:
        for n in nodes:
            if (addr := n.address) not in self.seen_addrs:
                t = (xor_bytes(n.id, self.info_hash), -self.counter, n)
                self.counter += 1
                heapq.heappush(self.nodes, t)
                self.seen_addrs.add(addr)

    def pop_nearest(self) -> Node | None:
        try:
            _, _, n = heapq.heappop(self.nodes)
            return n
        except IndexError:
            return None


class DhtProtoError(Exception):
    pass


async def create_dht_client(node_id: bytes) -> DhtClient:
    ipv4 = await create_udp_socket(family=socket.AF_INET)
    ipv6 = await create_udp_socket(family=socket.AF_INET6)
    return DhtClient(node_id=node_id, ipv4=ipv4, ipv6=ipv6)


def similarity(bs1: bytes, bs2: bytes) -> int:
    """
    Returns the number of leading bits of ``bs1`` and ``bs2`` that are equal
    """
    sim = 0
    for b1, b2 in zip(bs1, bs2):
        b = ~(b1 ^ b2) & 0xFF
        if b == 0xFF:
            sim += 8
        else:
            i = 0x80
            while i != 0:
                if b & i:
                    sim += 1
                    i >>= 1
                else:
                    break
            break
    return sim


def xor_bytes(bs1: bytes, bs2: bytes) -> int:
    bx = bytes([b1 ^ b2 for (b1, b2) in zip(bs1, bs2)])
    return int.from_bytes(bx)
