from __future__ import annotations
from dataclasses import dataclass
from functools import total_ordering
from ipaddress import IPv4Address, IPv6Address
import re
import socket
from typing import Any


@total_ordering
@dataclass(frozen=True)
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

    @classmethod
    def from_pair(cls, host_str: str, port: int) -> InetAddr:
        host: str | IPv4Address | IPv6Address
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host_str):
            host = IPv4Address(host_str)
        elif re.fullmatch(r"[A-Fa-f0-9:]+", host_str):
            host = IPv6Address(host_str)
        else:
            host = host_str
        return cls(host=host, port=port)

    @classmethod
    def from_compact(cls, bs: bytes) -> InetAddr:
        if len(bs) == 6:
            ip4 = IPv4Address(bs[:4])
            port = int.from_bytes(bs[4:], "big")
            return cls(host=ip4, port=port)
        elif len(bs) == 18:
            ip6 = IPv6Address(bs[:16])
            port = int.from_bytes(bs[16:], "big")
            return cls(host=ip6, port=port)
        else:
            raise ValueError(f"Compact address has invalid length {len(bs)}")

    def __str__(self) -> str:
        if isinstance(self.host, IPv6Address):
            return f"[{self.host}]:{self.port}"
        else:
            return f"{self.host}:{self.port}"

    def _cmpkey(self) -> tuple[int, str | IPv4Address | IPv6Address, int]:
        if isinstance(self.host, str):
            return (0, self.host, self.port)
        elif isinstance(self.host, IPv4Address):
            return (4, self.host, self.port)
        else:
            return (6, self.host, self.port)

    def __lt__(self, other: InetAddr) -> bool:
        return self._cmpkey() < other._cmpkey()

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

    def for_json(self) -> str:
        return str(self)


@dataclass
class Node:
    id: NodeId
    ip: IPv4Address | IPv6Address
    port: int

    @classmethod
    def from_compact(cls, bs: bytes) -> Node:
        nid = NodeId(bs[:20])
        addr = InetAddr.from_compact(bs[20:])
        assert not isinstance(addr.host, str)
        return cls(id=nid, ip=addr.host, port=addr.port)

    @property
    def address(self) -> InetAddr:
        return InetAddr(host=self.ip, port=self.port)

    def for_json(self) -> dict[str, str | int]:
        return {"id": str(self.id), "ip": str(self.ip), "port": self.port}


class NodeId:
    def __init__(self, nid: str | bytes) -> None:
        if isinstance(nid, str):
            nid = bytes.fromhex(nid)
        if len(nid) != 20:
            raise ValueError("node IDs must be 20 bytes (40 hex chars) long")
        self.id: bytes = nid

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, NodeId):
            return self.id == other.id
        else:
            return NotImplemented

    def __hash__(self) -> int:
        return hash(self.id)

    def __str__(self) -> str:
        return self.id.hex()

    def __bytes__(self) -> bytes:
        return self.id

    def __repr__(self) -> str:
        return f"NodeId({self.id.hex()!r})"

    def for_json(self) -> str:
        return str(self)


class InfoHash:
    def __init__(self, info_hash: str | bytes) -> None:
        if isinstance(info_hash, str):
            info_hash = bytes.fromhex(info_hash)
        if len(info_hash) != 20:
            raise ValueError("info hashes must be 20 bytes (40 hex chars) long")
        self.hash: bytes = info_hash

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, InfoHash):
            return self.hash == other.hash
        else:
            return NotImplemented

    def __hash__(self) -> int:
        return hash(self.hash)

    def __str__(self) -> str:
        return self.hash.hex()

    def __bytes__(self) -> bytes:
        return self.hash

    def __repr__(self) -> str:
        return f"InfoHash({self.hash.hex()!r})"

    def for_json(self) -> str:
        return str(self)


class PrettyBytes:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, PrettyBytes):
            return self.value == other.value
        else:
            return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return self.value.hex()

    def __bytes__(self) -> bytes:
        return self.value

    def __repr__(self) -> str:
        return f"bytes.fromhex({self.value.hex()!r})"

    def for_json(self) -> str:
        return str(self)
