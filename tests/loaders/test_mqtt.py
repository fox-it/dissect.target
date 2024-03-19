import sys
import time
from struct import pack
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest

from dissect.target import Target


class MQTTMock(MagicMock):
    disks = []
    hostname = ""

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
            response.payload = self.hostname.encode("utf-8")
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
        self.on_message(self, None, response)


@pytest.fixture
def mock_paho(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_paho = MagicMock()
        m.setitem(sys.modules, "paho", mock_paho)
        m.setitem(sys.modules, "paho.mqtt", mock_paho.mqtt)
        m.setitem(sys.modules, "paho.mqtt.client", mock_paho.mqtt.client)

        yield mock_paho


@pytest.fixture
def mock_client(mock_paho: MagicMock) -> Iterator[MagicMock]:
    mock_client = MQTTMock()
    mock_paho.mqtt.client.Client.return_value = mock_client
    yield mock_client


@pytest.mark.parametrize(
    "alias, host, disks, disk, seek, read, expected",
    [
        ("host1", "host1", [3], 0, 0, 3, b"\x00\x01\x02"),  # basic
        ("host2", "host2", [10], 0, 1, 3, b"\x01\x02\x03"),  # + use offset
        ("group1", "host3", [10], 0, 1, 3, b"\x01\x02\x03"),  # + use alias
        ("group2", "host4", [10, 10, 1], 1, 1, 3, b"\x01\x02\x03"),  # + use disk 2
    ],
)
@patch.object(time, "sleep")  # improve speed during test, no need to wait for peers
def test_remote_loader_stream(
    time: MagicMock,
    mock_client: MagicMock,
    alias: str,
    host: str,
    disks: list[int],
    disk: int,
    seek: int,
    read: int,
    expected: bytes,
) -> None:
    from dissect.target.loaders.mqtt import Broker

    broker = Broker("0.0.0.0", "1884", "key", "crt", "ca", "case1")
    broker.connect()
    broker.mqtt_client.fill_disks(disks)
    broker.mqtt_client.hostname = host

    with patch("dissect.target.loaders.mqtt.MQTTLoader.broker", broker):
        targets = list(
            Target.open_all(
                [f"mqtt://{alias}?broker=0.0.0.0&port=1884&key=key&crt=crt&ca=ca&peers=1&case=case1"],
                include_children=True,
            )
        )
        target = targets[-1]
        target.disks[disk].seek(seek)
        data = target.disks[disk].read(read)
        assert data == expected
