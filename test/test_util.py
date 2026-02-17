from ipaddress import IPv4Address, IPv6Address
import pprint
from typing import Any
import pytest
from dht_query.types import InetAddr, InfoHash, Node, NodeId, PrettyBytes
from dht_query.util import convert_reply, for_json, jsonify, split_bytes, strify_keys


class BadType:
    pass


class TestConvertReply:

    def test_convert_reply_values(self) -> None:
        port_bs = (1234).to_bytes(2, byteorder="big")
        ip4_port_bs = IPv4Address("127.0.0.1").packed + port_bs
        ip6_port_bs = IPv6Address("2001:db8:85a3::8a2e:370:7334").packed + port_bs
        id_bs = b"\xab" * 20

        nodes_bs = id_bs + ip4_port_bs + id_bs + ip4_port_bs
        nodes6_bs = id_bs + ip6_port_bs
        values = [ip4_port_bs, ip4_port_bs]
        samples_bs = id_bs + id_bs + id_bs
        token_bs = b"token_bs"
        y_bs = b"y_bs"
        q_bs = b"q_bs"
        t_bs = b"t_bs"

        raw = {
            b"ip": ip4_port_bs,
            b"r": {
                b"id": id_bs,
                b"nodes": nodes_bs,
                b"nodes6": nodes6_bs,
                b"values": values[:],
                b"samples": samples_bs,
                b"token": token_bs,
            },
            b"e": [201, b"Generic Error"],
            b"y": y_bs,
            b"q": q_bs,
            b"t": t_bs,
        }

        msg = convert_reply(raw)
        r = msg["r"]

        assert msg["ip"] == InetAddr.from_compact(ip4_port_bs)
        assert r["id"] == NodeId(id_bs)
        assert r["nodes"] == [
            Node.from_compact(id_bs + ip4_port_bs),
            Node.from_compact(id_bs + ip4_port_bs),
        ]
        assert r["nodes6"] == [Node.from_compact(nodes6_bs)]
        assert r["values"] == [
            InetAddr.from_compact(values[0]),
            InetAddr.from_compact(values[1]),
        ]
        assert r["samples"] == [InfoHash(id_bs), InfoHash(id_bs), InfoHash(id_bs)]
        assert r["token"] == PrettyBytes(token_bs)
        assert msg["e"] == [201, "Generic Error"]
        assert msg["y"] == y_bs.decode("utf-8")
        assert msg["q"] == q_bs.decode("utf-8")
        assert msg["t"] == PrettyBytes(t_bs)

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

    @classmethod
    def get_test_reply_dict(cls, key: bytes, value: Any) -> dict[bytes, Any]:
        raw: dict[bytes, Any]
        nested_dict_keys = [b"id", b"nodes", b"nodes6", b"values", b"samples", b"token"]

        if key in nested_dict_keys:
            raw = {b"r": {key: value}}
        else:
            raw = {key: value}

        return raw


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


@pytest.fixture
def raw_message() -> dict:
    port_bs = (1234).to_bytes(2, byteorder="big")
    ip4_port_bs = IPv4Address("127.0.0.1").packed + port_bs
    ip6_port_bs = IPv6Address("2001:db8:85a3::8a2e:370:7334").packed + port_bs
    id_bs = b"\xab" * 20

    nodes_bs = id_bs + ip4_port_bs + id_bs + ip4_port_bs
    nodes6_bs = id_bs + ip6_port_bs
    values = [ip4_port_bs, ip4_port_bs]
    samples_bs = id_bs + id_bs + id_bs
    token_bs = b"token_bs"
    y_bs = b"y_bs"
    q_bs = b"q_bs"
    t_bs = b"t_bs"

    return {
        b"ip": ip4_port_bs,
        b"r": {
            b"id": id_bs,
            b"nodes": nodes_bs,
            b"nodes6": nodes6_bs,
            b"values": values[:],
            b"samples": samples_bs,
            b"token": token_bs,
        },
        b"e": [201, b"Generic Error"],
        b"y": y_bs,
        b"q": q_bs,
        b"t": t_bs,
    }


def test_pretty_printing(raw_message: dict) -> None:
    msg = convert_reply(raw_message)

    expected = """{'e': [201, 'Generic Error'],
 'ip': InetAddr(host=IPv4Address('127.0.0.1'), port=1234),
 'q': 'q_bs',
 'r': {'id': NodeId('abababababababababababababababababababab'),
       'nodes': [Node(id=NodeId('abababababababababababababababababababab'),
                      ip=IPv4Address('127.0.0.1'),
                      port=1234),
                 Node(id=NodeId('abababababababababababababababababababab'),
                      ip=IPv4Address('127.0.0.1'),
                      port=1234)],
       'nodes6': [Node(id=NodeId('abababababababababababababababababababab'),
                       ip=IPv6Address('2001:db8:85a3::8a2e:370:7334'),
                       port=1234)],
       'samples': [InfoHash('abababababababababababababababababababab'),
                   InfoHash('abababababababababababababababababababab'),
                   InfoHash('abababababababababababababababababababab')],
       'token': bytes.fromhex('746f6b656e5f6273'),
       'values': [InetAddr(host=IPv4Address('127.0.0.1'), port=1234),
                  InetAddr(host=IPv4Address('127.0.0.1'), port=1234)]},
 't': bytes.fromhex('745f6273'),
 'y': 'y_bs'}"""

    # We pass all default parameters explicitly to ensure the test remains independent
    # of the Python version and future changes to pformat defaults.
    formatted = pprint.pformat(
        msg,
        indent=1,
        width=80,
        depth=None,
        compact=False,
        sort_dicts=True,
        underscore_numbers=False,
    )

    assert formatted == expected


def test_jsonify(raw_message: dict) -> None:
    msg = convert_reply(raw_message)
    expected = """{
    "ip": "127.0.0.1:1234",
    "r": {
        "id": "abababababababababababababababababababab",
        "nodes": [
            {
                "id": "abababababababababababababababababababab",
                "ip": "127.0.0.1",
                "port": 1234
            },
            {
                "id": "abababababababababababababababababababab",
                "ip": "127.0.0.1",
                "port": 1234
            }
        ],
        "nodes6": [
            {
                "id": "abababababababababababababababababababab",
                "ip": "2001:db8:85a3::8a2e:370:7334",
                "port": 1234
            }
        ],
        "values": [
            "127.0.0.1:1234",
            "127.0.0.1:1234"
        ],
        "samples": [
            "abababababababababababababababababababab",
            "abababababababababababababababababababab",
            "abababababababababababababababababababab"
        ],
        "token": "746f6b656e5f6273"
    },
    "e": [
        201,
        "Generic Error"
    ],
    "y": "y_bs",
    "q": "q_bs",
    "t": "745f6273"
}"""

    assert jsonify(msg) == expected


class JsonMe:
    def for_json(self) -> str:
        return "{data: json}"


@pytest.mark.parametrize(
    "obj, expected", [(JsonMe(), "{data: json}"), (b"hello", b"hello".hex())]
)
def test_for_json_valid(obj: Any, expected: str) -> None:
    assert for_json(obj) == expected


def test_for_json_type_error() -> None:
    bad_obj = BadType()
    with pytest.raises(TypeError) as e:
        for_json(bad_obj)
    assert str(e.value) == "BadType"
