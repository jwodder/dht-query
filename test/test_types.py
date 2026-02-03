from ipaddress import IPv4Address, IPv6Address
import socket
from typing import Any
import pytest
from pytest import MonkeyPatch
from dht_query.types import InetAddr, InfoHash, Node, NodeId


class TestInetAddr:
    @pytest.mark.parametrize(
        "input_str, expected_host, expected_port, expected_type",
        [
            ("192.168.0.1:8080", "192.168.0.1", 8080, IPv4Address),
            ("0.0.0.0:0", "0.0.0.0", 0, IPv4Address),
            ("255.255.255.255:65535", "255.255.255.255", 65535, IPv4Address),
            ("[2001:db8::1]:443", "2001:db8::1", 443, IPv6Address),
            ("[::]:0", "::", 0, IPv6Address),
            (
                "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                65535,
                IPv6Address,
            ),
            ("example.com:80", "example.com", 80, str),
            ("localhost:1234", "localhost", 1234, str),
        ],
    )
    def test_parse_valid(
        self,
        input_str: str,
        expected_host: str,
        expected_port: int,
        expected_type: type[IPv4Address] | type[IPv6Address] | type[str],
    ) -> None:
        addr = InetAddr.parse(input_str)
        assert isinstance(addr.host, expected_type)
        assert str(addr.host) == expected_host
        assert addr.port == expected_port

    @pytest.mark.parametrize(
        "host, port, expected_type",
        [
            ("0.0.0.0", 0, IPv4Address),
            ("192.168.0.1", 8080, IPv4Address),
            ("255.255.255.255", 65535, IPv4Address),
            ("::", 0, IPv6Address),
            ("2001:db8::1", 443, IPv6Address),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535, IPv6Address),
        ],
    )
    def test_from_ipstr_port_valid(
        self,
        host: str,
        port: int,
        expected_type: type[IPv4Address] | type[IPv6Address] | type[str],
    ) -> None:
        addr = InetAddr.from_ipstr_port(host, port)

        assert isinstance(addr.host, expected_type)
        assert str(addr.host) == host
        assert addr.port == port

    @pytest.mark.parametrize(
        "invalid_host",
        [
            "",
            "256.0.0.1",
            "192.168.1",
            "192.168.1.1.1",
            "12345::1",
            "2001:db8:::1",
            "2001:db8::1::1",
        ],
    )
    def test_from_ipstr_port_invalid(self, invalid_host: str) -> None:
        with pytest.raises(ValueError):
            InetAddr.from_ipstr_port(invalid_host, 8080)

    @pytest.mark.parametrize(
        "host, port",
        [
            (IPv4Address("0.0.0.0"), 0),
            (IPv4Address("192.168.1.10"), 8080),
            (IPv4Address("255.255.255.255"), 65535),
            (IPv6Address("::"), 0),
            (IPv6Address("3f2a:1d4b::9abc:def0"), 8080),
            (IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 65535),
        ],
    )
    def test_from_compact_valid(
        self, host: IPv4Address | IPv6Address, port: int
    ) -> None:
        bs = host.packed + port.to_bytes(length=2, byteorder="big")
        addr = InetAddr.from_compact(bs)

        assert isinstance(addr.host, type(host))
        assert addr.host == host
        assert addr.port == port

    @pytest.mark.parametrize("length", [0, 1, 5, 7, 17, 19, 32])
    def test_from_compact_invalid_length(self, length: int) -> None:
        bs = b"\x00" * length

        with pytest.raises(ValueError):
            InetAddr.from_compact(bs)

    @pytest.mark.parametrize(
        "family, host, port",
        [
            (socket.AF_INET, IPv4Address("0.0.0.0"), 0),
            (socket.AF_INET, IPv4Address("192.168.0.1"), 8080),
            (socket.AF_INET, IPv4Address("255.255.255.255"), 65535),
            (socket.AF_INET6, IPv6Address("::"), 0),
            (socket.AF_INET6, IPv6Address("3f2a:1d4b::9abc:def0"), 8080),
            (
                socket.AF_INET6,
                IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                65535,
            ),
        ],
    )
    def test_resolve_with_ip(
        self, family: socket.AddressFamily, host: IPv4Address | IPv6Address, port: int
    ) -> None:
        addr = InetAddr(host=host, port=port)
        actual_address_family, actual_host, actual_port = addr.resolve()

        assert actual_address_family == family
        assert actual_host == str(host)
        assert actual_port == port

    @pytest.mark.parametrize(
        "family, hostname, port",
        [
            (socket.AF_INET, "github.com", 80),
            (socket.AF_INET, "google.com", 80),
            (socket.AF_INET, "cloudflare.com", 80),
        ],
    )
    def test_resolve_with_hostname(
        self,
        monkeypatch: MonkeyPatch,
        family: socket.AddressFamily,
        hostname: str,
        port: int,
    ) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *_a, **_kwargs: [(family, 0, 0, 0, (hostname, port))],
        )

        addr = InetAddr(host=hostname, port=port)
        actual_address_family, actual_host, actual_port = addr.resolve()

        assert actual_address_family == family
        assert actual_host == hostname
        assert actual_port == port

    @pytest.mark.parametrize(
        "unknown_hostname",
        ["", "unknown-hostname.com", "you_dont_know_me.com", "!invalid_hostname"],
    )
    def test_resolve_invalid_or_unknown_hostname(
        self, monkeypatch: MonkeyPatch, unknown_hostname: str
    ) -> None:
        def fake_getaddrinfo(*_a: Any, **_kw: Any) -> None:
            raise socket.gaierror()

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        addr = InetAddr(host=unknown_hostname, port=80)

        with pytest.raises(socket.gaierror):
            addr.resolve()

    @pytest.mark.parametrize(
        "host, port, expected_str",
        [
            (IPv4Address("192.168.0.1"), 8080, "192.168.0.1:8080"),
            (IPv6Address("2001:db8::1"), 443, "[2001:db8::1]:443"),
            ("example.com", 80, "example.com:80"),
            ("localhost", 1234, "localhost:1234"),
        ],
    )
    def test_str(
        self, host: IPv4Address | IPv6Address, port: int, expected_str: str
    ) -> None:
        addr = InetAddr(host=host, port=port)
        assert str(addr) == expected_str

    @pytest.mark.parametrize(
        "a_host, a_port, b_host, b_port, expected",
        [
            pytest.param(
                "example.com", 80, IPv4Address("1.1.1.1"), 80, True, id="str < IPv4"
            ),
            pytest.param(
                IPv4Address("1.1.1.1"),
                80,
                IPv6Address("::1"),
                80,
                True,
                id="IPv4 < IPv6",
            ),
            pytest.param(
                IPv4Address("1.1.1.1"),
                80,
                IPv4Address("1.1.1.2"),
                80,
                True,
                id="IPv4 host comparison",
            ),
            pytest.param(
                IPv4Address("1.1.1.1"),
                80,
                IPv4Address("1.1.1.1"),
                90,
                True,
                id="IPv4 port comparison",
            ),
            pytest.param(
                IPv4Address("1.1.1.1"),
                80,
                IPv4Address("1.1.1.1"),
                80,
                False,
                id="Equal objects",
            ),
            pytest.param(
                IPv6Address("::"),
                80,
                IPv4Address("0.0.0.0"),
                80,
                False,
                id="IPv6 < IPv4",
            ),
        ],
    )
    def test_lt(
        self,
        a_host: str | IPv4Address | IPv6Address,
        a_port: int,
        b_host: IPv4Address | IPv6Address,
        b_port: int,
        expected: bool,
    ) -> None:
        a = InetAddr(a_host, a_port)
        b = InetAddr(b_host, b_port)
        assert (a < b) == expected


class TestNodeId:
    @pytest.mark.parametrize(
        "nid",
        [
            "0123456789abcdef0123456789abcdef01234567",
            bytes.fromhex("a3f1c9d47b2e8f019c6a4d5e7b8c9a1d2e3f4b5c"),
        ],
    )
    def test_init_valid(self, nid: str | bytes) -> None:
        node_id = NodeId(nid)
        assert isinstance(node_id.id, bytes)
        assert len(node_id.id) == 20

    @pytest.mark.parametrize("nid_length", [0, 1, 5, 7, 19, 50])
    def test_init_invalid_nid_length(self, nid_length: int) -> None:
        nid = "ef" * nid_length
        with pytest.raises(ValueError) as e:
            NodeId(nid)
        assert str(e.value) == "node IDs must be 20 bytes (40 hex chars) long"

    @pytest.mark.parametrize("invalid_hex_number", ["eee", "I", "love", "cats", "!"])
    def test_invalid_hex_number(self, invalid_hex_number: str) -> None:
        with pytest.raises(ValueError):
            NodeId(nid=invalid_hex_number)


class TestNode:
    @pytest.mark.parametrize(
        "host, port",
        [
            (IPv4Address("192.168.1.10"), 8080),
            (IPv6Address("3f2a:1d4b::9abc:def0"), 8080),
        ],
    )
    def test_from_compact_valid(
        self, host: IPv4Address | IPv6Address, port: int
    ) -> None:
        node_id_bs = b"\x01" * 20
        socket_bs = host.packed + port.to_bytes(length=2, byteorder="big")
        bs = node_id_bs + socket_bs
        addr = InetAddr.from_compact(socket_bs)
        node = Node.from_compact(bs)

        assert node.id == NodeId(node_id_bs)
        assert node.ip == addr.host
        assert node.port == addr.port

    def test_for_json(self) -> None:
        node = Node(id=NodeId("fe" * 20), ip=IPv4Address("127.0.0.1"), port=80)

        assert node.for_json() == {
            "id": str(node.id),
            "ip": str(node.ip),
            "port": node.port,
        }


class TestInfoHash:
    @pytest.mark.parametrize(
        "info_hash",
        [
            "0123456789abcdef0123456789abcdef01234567",
            bytes.fromhex("a3f1c9d47b2e8f019c6a4d5e7b8c9a1d2e3f4b5c"),
        ],
    )
    def test_init_valid(self, info_hash: str | bytes) -> None:
        ih = InfoHash(info_hash)
        assert isinstance(ih.hash, bytes)
        assert len(ih.hash) == 20

    @pytest.mark.parametrize("hash_length", [0, 1, 5, 7, 19, 50])
    def test_init_invalid_hash_length(self, hash_length: int) -> None:
        info_hash = "ef" * hash_length
        with pytest.raises(ValueError) as e:
            InfoHash(info_hash)
        assert str(e.value) == "info hashes must be 20 bytes (40 hex chars) long"
