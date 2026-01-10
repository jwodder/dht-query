from __future__ import annotations
import asyncio
from bisect import insort
from dataclasses import dataclass, field
import logging
import socket
from typing import Any
import anyio
from anyio import create_memory_object_stream, create_udp_socket
from anyio.abc import AsyncResource, UDPSocket
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from .bencode import bencode, unbencode
from .consts import CLIENT, DEFAULT_TIMEOUT
from .types import InetAddr, InfoHash, Node, NodeId
from .util import (
    convert_reply,
    get_default_bootstrap_nodes,
    quantify,
)

DEFAULT_CLOSEST = 8

log = logging.getLogger(__name__)


@dataclass
class SearchPeers:
    info_hash: InfoHash
    node_id: NodeId
    timeout: float = DEFAULT_TIMEOUT
    closest: int = DEFAULT_CLOSEST
    bootstrap: list[InetAddr] = field(default_factory=get_default_bootstrap_nodes)

    async def create_session(self) -> Session:
        ipv4 = await create_udp_socket(family=socket.AF_INET)
        ipv6 = await create_udp_socket(family=socket.AF_INET6)
        (event_sender, event_receiver) = create_memory_object_stream[
            Message | Timeout | FatalError
        ]()
        return Session(
            search=self,
            ipv4=ipv4,
            ipv6=ipv6,
            event_sender=event_sender,
            event_receiver=event_receiver,
        )

    async def run(self) -> set[InetAddr]:
        nodes = NodeTable(self.info_hash)
        peers = set()
        async with await self.create_session() as s:
            for addr in self.bootstrap:
                bn = BootstrapNode(addr)
                log.info('Issuing "get_peers" query to %s ...', bn)
                await s.query(bn, self.info_hash)
            while s.has_active_txns():
                match await s.next_event():
                    case Timeout(node):
                        log.warning("Query to %s timed out", node)
                    case GetPeersResponse() as r:
                        log.info(
                            "%s returned %s and %s",
                            str(r.sender).capitalize(),
                            quantify(len(r.peers), "peer"),
                            quantify(len(r.nodes), "node"),
                        )
                        peers.update(r.peers)
                        nodes.extend(r.nodes)
                        for n in nodes.closest(self.closest):
                            if n.address not in s.queried:
                                log.info('Issuing "get_peers" query to %s ...', n)
                                await s.query(n, self.info_hash)
                    case ErrorReply(sender, code, msg):
                        log.warning(
                            "%s replied with error message: code %d: %r",
                            str(sender).capitalize(),
                            code,
                            msg,
                        )
                    case BadMessage(sender, about):
                        log.warning(
                            "%s sent invalid DHT message: %s",
                            str(sender).capitalize(),
                            about,
                        )
                    case FatalError(e):
                        raise e
        return peers


@dataclass
class Session(AsyncResource):
    search: SearchPeers
    ipv4: UDPSocket
    ipv6: UDPSocket
    ipv4_recv_task: asyncio.Task[None] = field(init=False)
    ipv6_recv_task: asyncio.Task[None] = field(init=False)
    event_receiver: MemoryObjectReceiveStream[Message | Timeout | FatalError]
    event_sender: MemoryObjectSendStream[Message | Timeout | FatalError]
    txn_counter: int = field(init=False, default=0)
    in_flight: dict[bytes, tuple[InetAddr, asyncio.Task[None]]] = field(
        init=False, default_factory=dict
    )
    queried: set[InetAddr] = field(init=False, default_factory=set)
    addr2node: dict[InetAddr, Node | BootstrapNode] = field(
        init=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        self.ipv4_recv_task = asyncio.create_task(
            recv_task(self.ipv4, self.event_sender.clone())
        )
        self.ipv6_recv_task = asyncio.create_task(
            recv_task(self.ipv6, self.event_sender.clone())
        )

    async def aclose(self) -> None:
        outstanding = []
        for _, t in self.in_flight.values():
            t.cancel()
            outstanding.append(t)
        self.ipv4_recv_task.cancel()
        outstanding.append(self.ipv4_recv_task)
        self.ipv6_recv_task.cancel()
        outstanding.append(self.ipv6_recv_task)
        await asyncio.wait(outstanding)
        await self.ipv4.aclose()
        await self.ipv6.aclose()

    def has_active_txns(self) -> bool:
        return bool(self.in_flight)

    def gen_transaction_id(self) -> bytes:
        t = self.txn_counter
        self.txn_counter = (self.txn_counter + 1) & 0xFF_FF_FF_FF
        return t.to_bytes(4, "big")

    async def query(self, sendto: Node | BootstrapNode, info_hash: InfoHash) -> None:
        txn_id = self.gen_transaction_id()
        query: dict[bytes, Any] = {
            b"t": txn_id,
            b"y": b"q",
            b"q": b"get_peers",
            b"a": {
                b"id": bytes(self.search.node_id),
                b"info_hash": bytes(info_hash),
                b"want": [b"n4", b"n6"],
            },
            b"v": CLIENT,
            b"ro": 1,
        }
        msg = bencode(query)
        if isinstance(sendto, Node):
            addr = sendto.address
            (family, ip, port) = addr.resolve()
        else:
            (family, ip, port) = sendto.address.resolve()
            addr = InetAddr.from_ipstr_port(ip, port)
        self.addr2node[addr] = sendto
        if family is socket.AF_INET:
            s = self.ipv4
        else:
            assert family is socket.AF_INET6
            s = self.ipv6
        self.queried.add(addr)
        task = asyncio.create_task(
            txn_timeout(
                Timeout(sendto, txn_id), self.search.timeout, self.event_sender.clone()
            )
        )
        self.in_flight[txn_id] = (addr, task)
        await s.sendto(msg, ip, port)

    async def next_event(
        self,
    ) -> Timeout | GetPeersResponse | ErrorReply | BadMessage | FatalError:
        while True:
            ev = await self.event_receiver.receive()
            match ev:
                case Timeout() as tm:
                    self.in_flight.pop(tm.txn_id)
                    return tm
                case Message(sender, content):
                    full_sender = self.addr2node.get(sender)
                    if full_sender is None:
                        log.debug(
                            "Message received from unknown address %s; ignoring",
                            sender,
                        )
                        continue
                    try:
                        msg = convert_reply(unbencode(content), strict=True)
                    except (TypeError, ValueError) as e:
                        log.debug(
                            "Received message from %s that could not be"
                            " deserialized: %s; ignoring",
                            full_sender,
                            e,
                        )
                        continue
                    y = msg.get("y")
                    if y == "q":
                        log.debug(
                            "Received query message from %s; ignoring", full_sender
                        )
                        continue
                    elif y != "r" and y != "e":
                        log.debug(
                            "Received unexpected message type %r from %s; ignoring",
                            y,
                            full_sender,
                        )
                        continue
                    t = msg.get("t")
                    if t is None:
                        log.debug(
                            "Received reply from %s without transaction ID; ignoring",
                            full_sender,
                        )
                        continue
                    txn_id = bytes(t)
                    flying = self.in_flight.pop(txn_id, None)
                    if flying is None or flying[0] != sender:
                        log.debug(
                            "Received reply from %s with unexpected transaction"
                            " ID; ignoring",
                            full_sender,
                        )
                        if flying is not None:
                            self.in_flight[txn_id] = flying
                        continue
                    (_, task) = flying
                    task.cancel()
                    if y == "r":
                        peers = msg.get("r", {}).get("values", [])
                        assert isinstance(peers, list)
                        nodes4 = msg.get("r", {}).get("nodes", [])
                        assert isinstance(nodes4, list)
                        nodes6 = msg.get("r", {}).get("nodes6", [])
                        assert isinstance(nodes6, list)
                        return GetPeersResponse(
                            sender=full_sender, peers=peers, nodes=nodes4 + nodes6
                        )
                    else:
                        elst = msg.get("e", [])
                        if (
                            len(elst) >= 2
                            and isinstance(elst[0], int)
                            and isinstance(elst[1], str)
                        ):
                            code = elst[0]
                            errmsg = elst[1]
                            return ErrorReply(sender=full_sender, code=code, msg=errmsg)
                        else:
                            return BadMessage(
                                sender=full_sender,
                                about="malformed error message",
                            )
                case FatalError() as e:
                    return e


@dataclass
class NodeTable:
    info_hash: InfoHash
    counter: int = field(init=False, default=0)
    nodes: list[tuple[int, int, Node]] = field(init=False, default_factory=list)
    seen_addrs: set[InetAddr] = field(init=False, default_factory=set)

    def extend(self, nodes: list[Node]) -> None:
        for n in nodes:
            if (addr := n.address) not in self.seen_addrs:
                t = (xor_bytes(bytes(n.id), bytes(self.info_hash)), -self.counter, n)
                self.counter += 1
                insort(self.nodes, t)
                self.seen_addrs.add(addr)

    def closest(self, k: int) -> list[Node]:
        return [n for (_, _, n) in self.nodes[:k]]


@dataclass
class BootstrapNode:
    address: InetAddr

    def __str__(self) -> str:
        return f"bootstrap node at {self.address}"


@dataclass
class GetPeersResponse:
    sender: Node | BootstrapNode
    peers: list[InetAddr]
    nodes: list[Node]


@dataclass
class ErrorReply:
    sender: Node | BootstrapNode
    code: int
    msg: str


@dataclass
class Timeout:
    node: Node | BootstrapNode
    txn_id: bytes


@dataclass
class Message:
    sender: InetAddr
    content: bytes


@dataclass
class FatalError:
    e: Exception


@dataclass
class BadMessage:
    sender: Node | BootstrapNode
    about: str


def xor_bytes(bs1: bytes, bs2: bytes) -> int:
    bx = bytes([b1 ^ b2 for (b1, b2) in zip(bs1, bs2)])
    return int.from_bytes(bx, "big")


async def txn_timeout(
    t: Timeout, duration: float, sender: MemoryObjectSendStream
) -> None:
    async with sender:
        await asyncio.sleep(duration)
        await sender.send(t)


async def recv_task(
    s: UDPSocket, sender: MemoryObjectSendStream[Message | Timeout | FatalError]
) -> None:
    async with sender:
        while True:
            try:
                (content, (ip, port)) = await s.receive()
            except (
                anyio.ClosedResourceError,
                anyio.EndOfStream,
                anyio.BrokenResourceError,
            ) as e:
                e2 = RuntimeError("Local UDP socket closed")
                e2.__cause__ = e
                await sender.send(FatalError(e2))
            except OSError as e:
                e2 = RuntimeError("Error reading from UDP socket")
                e2.__cause__ = e
                await sender.send(FatalError(e2))
            else:
                await sender.send(
                    Message(content=content, sender=InetAddr.from_ipstr_port(ip, port))
                )
