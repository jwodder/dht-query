import contextlib
from typing import Any, Type, TypeVar
import pytest
from pytest import MonkeyPatch
import dht_query
from dht_query.util import convert_reply, split_bytes, strify_keys


class BadType:
    pass


class FakeInetAddr:
    def __init__(self, value: bytes) -> None:
        self.value = value


T = TypeVar("T", bound="FakeNode")


class FakeNode:
    @classmethod
    def from_compact(cls: Type[T], value: bytes) -> T:
        return cls(value)

    def __init__(self, value: bytes) -> None:
        self.value = value


class FakeNodeId:
    def __init__(self, value: bytes) -> None:
        self.value = value


class FakeInfoHash:
    def __init__(self, value: bytes) -> None:
        self.value = value


class FakePrettyBytes:
    def __init__(self, value: bytes) -> None:
        self.value = value


class TestConvertReply:

    def test_convert_reply_values(self, monkeypatch: MonkeyPatch) -> None:
        ip_bytes = b"ip_bytes"
        id_bytes = b"id_bytes"
        nodes_bytes = b"node1node2"
        nodes6_bytes = b"node6_bytes"
        values_list = [b"value1", b"value2"]
        samples_bytes = b"sample_bytes"
        token_bytes = b"token_bytes"
        e_list = [b"error0", b"error1", b"error2"]
        y_byte = b"y_byte"
        q_byte = b"q_byte"
        t_byte = b"t_byte"

        raw = {
            b"ip": ip_bytes,
            b"r": {
                b"id": id_bytes,
                b"nodes": nodes_bytes,
                b"nodes6": nodes6_bytes,
                b"values": values_list[:],
                b"samples": samples_bytes,
                b"token": token_bytes,
            },
            b"e": e_list[:],
            b"y": y_byte,
            b"q": q_byte,
            b"t": t_byte,
        }

        monkeypatch.setattr(dht_query.util.InetAddr, "from_compact", FakeInetAddr)  # type: ignore
        monkeypatch.setattr(dht_query.util.Node, "from_compact", FakeNode)  # type: ignore
        monkeypatch.setattr(dht_query.util, "NodeId", FakeNodeId)
        monkeypatch.setattr(dht_query.util, "InfoHash", FakeInfoHash)
        monkeypatch.setattr(dht_query.util, "PrettyBytes", FakePrettyBytes)
        monkeypatch.setattr(dht_query.util, "split_bytes", lambda bs, _size: [bs])
        monkeypatch.setattr(
            dht_query.util, "maybe_strict", lambda _strict: contextlib.nullcontext()
        )

        msg = convert_reply(raw)

        assert isinstance(msg["ip"], FakeInetAddr)
        assert msg["ip"].value == ip_bytes

        r = msg["r"]

        assert isinstance(r["id"], FakeNodeId)
        assert r["id"].value == id_bytes

        assert isinstance(r["nodes"], list)
        assert isinstance(r["nodes"][0], FakeNode)
        assert r["nodes"][0].value == nodes_bytes

        assert isinstance(r["nodes6"], list)
        assert isinstance(r["nodes6"][0], FakeNode)
        assert r["nodes6"][0].value == nodes6_bytes

        assert isinstance(r["values"], list)
        assert isinstance(r["values"][0], FakeInetAddr)
        assert r["values"][0].value == values_list[0]

        assert isinstance(r["samples"], list)
        assert isinstance(r["samples"][0], FakeInfoHash)
        assert r["samples"][0].value == samples_bytes

        assert isinstance(r["token"], FakePrettyBytes)
        assert r["token"].value == token_bytes

        assert isinstance(msg["e"], list)
        assert isinstance(msg["e"][1], str)
        assert msg["e"][1] == e_list[1].decode("utf-8")

        assert isinstance(msg["y"], str)
        assert msg["y"] == y_byte.decode("utf-8")

        assert isinstance(msg["q"], str)
        assert msg["q"] == q_byte.decode("utf-8")

        assert isinstance(msg["t"], FakePrettyBytes)
        assert msg["t"].value == t_byte

    def test_convert_reply_empty_input(self) -> None:
        assert convert_reply({}, strict=False) == {}
        assert convert_reply({}, strict=True) == {}

    @pytest.mark.parametrize(
        "key, value",
        [(key, b"bad_value") for key in [b"ip", b"id", b"nodes", b"nodes6", b"samples"]]
        + [(b"values", [b"bad_value"])],
    )
    def test_convert_reply_value_error(self, key: bytes, value: Any) -> None:
        raw = self.get_test_reply_dict(key, value)

        # strict = False
        with pytest.raises(ValueError):
            convert_reply(raw, strict=False)

        # strict = True
        res = convert_reply(raw, strict=True)
        assert isinstance(res, dict)

    @pytest.mark.parametrize(
        "key, bad_type",
        [
            (key, BadType)
            for key in [
                b"id",
                b"r",
                b"nodes",
                b"nodes6",
                b"values",
                b"samples",
                b"token",
                b"e",
                b"y",
                b"q",
                b"t",
            ]
        ]
        + [(b"e", [BadType, BadType])],
    )
    def test_convert_reply_type_error(self, key: bytes, bad_type: Any) -> None:
        raw = self.get_test_reply_dict(key, bad_type)

        # strict = False
        res = convert_reply(raw, strict=False)
        assert isinstance(res, dict)

        # strict = True
        with pytest.raises(TypeError):
            convert_reply(raw, strict=True)

    @pytest.mark.parametrize("value", [[], [b"only_one"]])
    def test_convert_reply_e_length_less_than_two(self, value: list) -> None:
        raw = {b"e": value}

        result = convert_reply(raw, strict=False)
        assert result["e"] == value

        result = convert_reply(raw, strict=False)
        assert result["e"] == value

    @classmethod
    def get_test_reply_dict(cls, key: bytes, value: Any) -> dict[bytes, Any]:
        raw: dict[bytes, Any]
        nested_dict_keys = [b"id", b"nodes", b"nodes6", b"values", b"samples", b"token"]

        if key in nested_dict_keys:
            raw = {b"r": {key: value}}
        else:
            raw = {key: value}

        return raw


def test_converted_reply_message_pretty_print() -> None:
    raw = {
        # compact IP: 4 байта IPv4 + 2 байта порт (network byte order)
        b"ip": b"\xc0\xa8\x01\x64\x1a\xe1",  # 192.168.1.100:6881
        # response dictionary
        b"r": {
            # node ID (20 bytes, SHA1-like)
            b"id": b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
            b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc",
            # IPv4 nodes (each entry = 26 bytes: 20 id + 4 ip + 2 port)
            b"nodes": (
                b"\xaa" * 20
                + b"\x7f\x00\x00\x01\x1a\xe1"  # 127.0.0.1:6881
                + b"\xbb" * 20
                + b"\x08\x08\x08\x08\x1a\xe9"  # 8.8.8.8:6889
            ),
            # IPv6 nodes (each entry = 38 bytes: 20 id + 16 ip + 2 port)
            b"nodes6": (
                b"\xcc" * 20 + b"\x20\x01\x0d\xb8\x85\xa3\x00\x00"
                b"\x00\x00\x8a\x2e\x03\x70\x73\x34" + b"\x1a\xe1"
            ),
            # peers (compact format: 6 bytes each)
            b"values": [
                b"\x5d\xb8\xd8\x22\x1a\xe1",  # 93.184.216.34:6881
                b"\x34\xd9\x1f\x2a\x1a\xe9",  # 52.217.31.42:6889
            ],
            # BEP-51: sample_infohashes (concatenated 20-byte hashes)
            b"samples": (b"\x01" * 20 + b"\x02" * 20 + b"\x03" * 20),
            # short-lived opaque token
            b"token": b"\x9f\x4a\x7c\x21",
        },
        # error list (normally absent in successful response, но формат допустим)
        # [error_code, error_message]
        b"e": [201, b"Generic Error"],
        # message type: response
        b"y": b"r",
        # query name (обычно отсутствует в response, но иногда логируется)
        b"q": b"get_peers",
        # transaction id (1–4 bytes, most often 2)
        b"t": b"aa",
    }

    msg = convert_reply(raw)
    from pprint import pprint

    print()
    pprint(msg)


def test_strify_keys() -> None:
    original = {
        b"key1": 123,
        b"key2": b"Hello world",
        b"key3": [b"value1", b"value2"],
        b"key4": {b"nested_key1": b"some_value", b"nested_key2": 456},
    }

    d = original.copy()

    result = strify_keys(d)

    assert original == d

    assert all(isinstance(key, str) for key in result.keys())

    assert isinstance(result["key4"], dict)
    assert all(isinstance(key, str) for key in result["key4"].keys())

    assert result["key1"] == 123
    assert result["key2"] == b"Hello world"
    assert result["key3"] == [b"value1", b"value2"]
    assert result["key4"] == {"nested_key1": b"some_value", "nested_key2": 456}


class TestSplitBytes:
    def test_split_bytes_valid(self) -> None:
        bs = b"abcdefgh"
        size = 4

        result = list(split_bytes(bs, size))
        assert result == [b"abcd", b"efgh"]

    @pytest.mark.parametrize(
        "size",
        [
            pytest.param(3, id="Short tail"),
            pytest.param(10, id="Size larger than bs length"),
        ],
    )
    def test_split_bytes_value_error(self, size: int) -> None:
        bs = b"abcd"

        with pytest.raises(ValueError):
            list(split_bytes(bs, size))
