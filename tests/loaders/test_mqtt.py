from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from struct import pack
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator


class MqttMock(MagicMock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.disks: list = []
        self.hostname: str = ""

    def fill_disks(self, sizes: list[int]) -> None:
        self.disks = []
        pattern = list(range(8))
        for size in sizes:
            self.disks.append(bytearray(pattern) * 64 * size)  # sizes in sectors of 512

    def publish(self, topic: str, *args) -> None:
        response = MagicMock()
        tokens = topic.split("/")
        command = tokens[2]
        if command == "TOPO":
            tokens[2] = "ID"
            response.topic = "/".join(tokens)
            for host in self.hostnames:
                response.payload = host.encode("utf-8")
                self.on_message(self, None, response)
        elif tokens[2] == "INFO":
            tokens[2] = "DISKS"
            response.topic = "/".join(tokens)
            response.payload = pack("<B", len(self.disks))
            for disk in self.disks:
                response.payload += pack("<IQ", 512, len(disk))
        elif tokens[2] == "SEEK":
            tokens[2] = "READ"
            response.topic = "/".join(tokens)
            begin = int(tokens[4], 16)
            end = int(tokens[5], 16)
            response.payload = self.disks[int(tokens[3])][begin : begin + end]
        else:
            return
        self.on_message(self, None, response)


@pytest.fixture
def mock_paho(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        if "dissect.target.loaders.mqtt" in sys.modules:
            m.delitem(sys.modules, "dissect.target.loaders.mqtt")

        mock_paho = MagicMock()
        m.setitem(sys.modules, "paho", mock_paho)
        m.setitem(sys.modules, "paho.mqtt", mock_paho.mqtt)
        m.setitem(sys.modules, "paho.mqtt.client", mock_paho.mqtt.client)

        yield mock_paho


@dataclass
class MockSeekMessage:
    data: bytes = b""


class MockBroker(MagicMock):
    _seek = False

    def seek(self, *args) -> None:
        self._seek = True

    def read(self, *args) -> MockSeekMessage | None:
        if self._seek:
            self._seek = False
            return MockSeekMessage(data=b"010101")
        return None


@pytest.fixture
def mock_broker() -> MockBroker:
    return MockBroker()


@pytest.mark.parametrize(
    ("alias", "hosts", "disks", "disk", "seek", "read", "expected"),
    [
        ("host1", ["host1"], [3], 0, 0, 3, b"\x00\x01\x02"),  # basic
        ("host2", ["host2"], [10], 0, 1, 3, b"\x01\x02\x03"),  # + use offset
        ("group1", ["host3"], [10], 0, 1, 3, b"\x01\x02\x03"),  # + use alias
        ("group2", ["host4"], [10, 10, 1], 1, 1, 3, b"\x01\x02\x03"),  # + use disk 2
        ("group3", ["host4", "host5"], [10, 10, 1], 1, 1, 3, b"\x01\x02\x03"),  # + use disk 2
    ],
)
@patch.object(time, "sleep")  # improve speed during test, no need to wait for peers
def test_remote_loader_stream(
    time: MagicMock,
    mock_paho: MagicMock,
    alias: str,
    hosts: list[str],
    disks: list[int],
    disk: int,
    seek: int,
    read: int,
    expected: bytes,
) -> None:
    mock_paho.mqtt.client.Client.return_value = MqttMock()

    from dissect.target.loaders.mqtt import Broker, MqttLoader

    broker = Broker("0.0.0.0", "1884", "key", "crt", "ca", "case1", "user", "pass")
    broker.connect()
    broker.mqtt_client.fill_disks(disks)
    broker.mqtt_client.hostnames = hosts

    with (
        patch.dict("dissect.target.loader.LOADERS_BY_SCHEME", {"mqtt": MqttLoader}),
        patch.object(MqttLoader, "broker", broker),
    ):
        targets = list(
            Target.open_all(
                [f"mqtt://{alias}?broker=0.0.0.0&port=1884&key=key&crt=crt&ca=ca&peers=1&case=case1"],
            )
        )
        assert len(targets) == len(hosts)
        target = targets[-1]
        target.disks[disk].seek(seek)
        data = target.disks[disk].read(read)
        assert data == expected


def test_mqtt_loader_prefetch(mock_broker: MockBroker, mock_paho: MagicMock) -> None:
    from dissect.target.loaders.mqtt import MqttConnection

    connection = MqttConnection(mock_broker, "")
    connection.prefetch_factor_inc = 10
    assert connection.factor == 1
    assert connection.prev == -1
    connection.read(1, 0, 100, 0)
    assert connection.factor == 1
    assert connection.prev == 0
    connection.read(1, 100, 100, 0)
    assert connection.factor == connection.prefetch_factor_inc + 1
    assert connection.prev == 100
    connection.read(1, 1200, 100, 0)
    assert connection.factor == (connection.prefetch_factor_inc * 2) + 1
    assert connection.prev == 1200


@pytest.mark.parametrize(
    ("case_name", "parse_result"),
    [
        ("valid_case_name", "valid_case_name"),
        ("ValidCase123", "ValidCase123"),
        ("valid_case_123", "valid_case_123"),
        ("invalid-case", pytest.raises(argparse.ArgumentTypeError)),
        ("invalid case", pytest.raises(argparse.ArgumentTypeError)),
        ("invalid.case", pytest.raises(argparse.ArgumentTypeError)),
        ("invalid@case", pytest.raises(argparse.ArgumentTypeError)),
        ("", pytest.raises(argparse.ArgumentTypeError)),
    ],
    ids=[
        "valid_case_lower",
        "valid_case_mixed",
        "valid_case_with_numbers",
        "invalid_case_hyphen",
        "invalid_case_space",
        "invalid_case_dot",
        "invalid_case_special_char",
        "invalid_case_empty",
    ],
)
def test_case(
    case_name: str, parse_result: str | pytest.RaisesContext[argparse.ArgumentTypeError], mock_paho: MagicMock
) -> None:
    from dissect.target.loaders.mqtt import case

    if isinstance(parse_result, str):
        assert case(case_name) == parse_result
    else:
        with parse_result:
            case(case_name)
