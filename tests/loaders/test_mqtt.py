import time
from struct import pack
from unittest.mock import MagicMock, patch

import paho.mqtt.client as mqtt
import pytest

from dissect.target import Target
from dissect.target.loaders.mqtt import Broker, MQTTLoader


class MQTTMock(MagicMock):
    disks = []
    hostname = ""

    def fill_disks(self, sizes: list[int]) -> None:
        self.disks = []
        pattern = list(range(8))
        for size in sizes:
            self.disks.append(bytearray(pattern) * 64 * size)  # sizes in sectors of 512

    def publish(self, topic: str, *args) -> None:
        response = mqtt.MQTTMessage()
        tokens = topic.split("/")
        command = tokens[2]
        if command == "TOPO":
            tokens[2] = "ID"
            response.topic = "/".join(tokens).encode("utf-8")
            response.payload = self.hostname.encode("utf-8")
        elif tokens[2] == "INFO":
            tokens[2] = "DISKS"
            response.topic = "/".join(tokens).encode("utf-8")
            response.payload = pack("<B", len(self.disks))
            for disk in self.disks:
                response.payload += pack("<IQ", 512, len(disk))
        elif tokens[2] == "SEEK":
            tokens[2] = "READ"
            response.topic = "/".join(tokens).encode("utf-8")
            begin = int(tokens[4], 16)
            end = int(tokens[5], 16)
            response.payload = self.disks[int(tokens[3])][begin : begin + end]
        self.on_message(self, None, response)


@pytest.mark.parametrize(
    "alias, host, disks, disk, seek, read, expected",
    [
        ("host1", "host1", [3], 0, 0, 3, b"\x00\x01\x02"),  # basic
        ("host1", "host1", [10], 0, 1, 3, b"\x01\x02\x03"),  # + use offset
        ("group1", "host1", [10], 0, 1, 3, b"\x01\x02\x03"),  # + use alias
        ("group1", "host1", [10, 10, 1], 1, 1, 3, b"\x01\x02\x03"),  # + use disk 2
    ],
)
@patch.object(mqtt, "Client", return_value=MQTTMock())
@patch.object(time, "sleep")  # improve speed during test, no need to wait for peers
def test_remote_loader_stream(
    time: MagicMock,
    Client: MagicMock,
    alias: str,
    host: str,
    disks: list[int],
    disk: int,
    seek: int,
    read: int,
    expected: bytes,
) -> None:
    broker = Broker("0.0.0.0", "1884", "key", "crt", "ca", "case1")
    broker.connect()
    broker.mqtt_client.fill_disks(disks)
    broker.mqtt_client.hostname = host
    MQTTLoader.broker = broker
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
