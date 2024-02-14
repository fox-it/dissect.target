from __future__ import annotations

import logging
import ssl
import time
import urllib
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from struct import pack, unpack_from
from typing import Any, Optional, Union

import paho.mqtt.client as mqtt
from dissect.util.stream import AlignedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.plugin import arg
from dissect.target.target import Target

log = logging.getLogger(__name__)


def suppress(func):
    def suppressed(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            return

    return suppressed


@dataclass
class InfoMessage:
    disks: list[DiskMessage]


@dataclass
class DiskMessage:
    index: int = 0
    sector_size: int = 0
    total_size: int = 0


@dataclass
class SeekMessage:
    data: bytes = b""


class RemoteStream(AlignedStream):
    def __init__(self, stream: RemoteConnection, disk_id: int, size: Optional[int] = None):
        self.stream = stream
        self.disk_id = disk_id
        super().__init__(size)

    def _read(self, offset: int, length: int, optimization_strategy: Optional[int] = None) -> bytes:
        data = self.stream.read(self.disk_id, offset, length, optimization_strategy)
        return data


class RemoteConnection:
    broker = None
    host = None

    def __init__(self, broker: Broker, host: str):
        self.broker = broker
        self.host = str(host)

    def topo(self, peers: int):
        self.broker.topology(self.host)
        while len(self.broker.peers(self.host)) < peers:
            self.broker.topology(self.host)
            time.sleep(1)
        return self.broker.peers(self.host)

    @lru_cache(maxsize=128)
    def info(self) -> list[RemoteStream]:
        disks = []
        self.broker.info(self.host)
        message = None
        while message is None:
            message = self.broker.disk(self.host)
        for i in range(0, len(message.disks)):
            disks.append(RemoteStream(self, i, message.disks[i].total_size))
        return disks

    @lru_cache(maxsize=128)
    def read(self, disk_id: int, offset: int, length: int, optimization_strategy: int) -> bytes:
        message = None
        self.broker.seek(self.host, disk_id, offset, length, optimization_strategy)
        while message is None:
            message = self.broker.read(self.host, disk_id, offset, length)
            self.broker.read(self.host, disk_id, offset, length, optimization_strategy)

        return message.data


class Broker:
    broker_host = None
    broker_port = None
    private_key_file = None
    certificate_file = None
    cacert_file = None
    mqtt_client = None
    connected = False
    case = None

    diskinfo = {}
    index = {}
    topo = {}

    def __init__(self, broker: Broker, port: str, key: str, crt: str, ca: str, case: str, **kwargs):
        self.broker_host = broker
        self.broker_port = int(port)
        self.private_key_file = key
        self.certificate_file = crt
        self.cacert_file = ca
        self.case = case

    @suppress
    def read(self, host: str, disk_id: int, seek_address: int, read_length: int) -> SeekMessage:
        key = f"{host}-{disk_id}-{seek_address}-{read_length}"
        message = self.index[key]
        del self.index[key]
        return message

    @suppress
    def disk(self, host: str) -> DiskMessage:
        return self.diskinfo[host]

    def peers(self, host: str) -> int:
        return self.topo[host]

    def _on_disk(self, hostname: str, payload: bytes) -> None:
        (num_of_disks,) = unpack_from("<B", payload, offset=0)
        disks = []
        for disk_index in range(0, num_of_disks):
            (
                sector_size,
                total_size,
            ) = unpack_from("<IQ", payload, offset=1 + (disk_index * 9))
            disks.append(DiskMessage(index=disk_index, sector_size=sector_size, total_size=total_size))
        self.diskinfo[hostname] = InfoMessage(disks=disks)

    def _on_read(self, hostname: str, tokens: list[str], payload: bytes) -> None:
        disk_id = tokens[3]
        seek_address = int(tokens[4], 16)
        read_length = int(tokens[5], 16)
        msg = SeekMessage(data=payload)
        key = f"{hostname}-{disk_id}-{seek_address}-{read_length}"
        if key in self.index:
            return
        self.index[key] = msg

    def _on_id(self, hostname: str, payload: bytes) -> None:
        key = hostname
        host = payload.decode("utf-8")
        if host not in self.topo[key]:
            self.topo[key].append(payload.decode("utf-8"))
            self.mqtt_client.subscribe(f"{self.case}/{host}/DISKS")
            self.mqtt_client.subscribe(f"{self.case}/{host}/READ/#")
            time.sleep(1)

    def _on_log(self, client: mqtt.Client, userdata: Any, log_level: int, message: str):
        log.debug(message)

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: dict, rc: int) -> None:
        self.connected = True

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.client.MQTTMessage) -> None:
        tokens = msg.topic.split("/")
        hostname = tokens[1]
        response = tokens[2]
        if response == "DISKS":
            self._on_disk(hostname, msg.payload)
        elif response == "READ":
            self._on_read(hostname, tokens, msg.payload)
        elif response == "ID":
            self._on_id(hostname, msg.payload)

    def seek(self, host: str, disk_id: int, offset: int, length: int, optimization_strategy: int) -> None:
        self.mqtt_client.publish(
            f"{self.case}/{host}/SEEK/{disk_id}/{hex(offset)}/{hex(length)}", pack("<I", optimization_strategy or 0)
        )

    def info(self, host: str) -> None:
        self.mqtt_client.publish(f"{self.case}/{host}/INFO")

    def topology(self, host: str) -> None:
        self.topo[host] = []
        self.mqtt_client.subscribe(f"{self.case}/{host}/ID")
        time.sleep(1)  # need some time to avoid race condition, i.e. MQTT might react too fast
        self.mqtt_client.publish(f"{self.case}/{host}/TOPO")

    def connect(self) -> None:
        self.mqtt_client = mqtt.Client(
            client_id="", clean_session=True, userdata=None, protocol=mqtt.MQTTv311, transport="tcp"
        )
        self.mqtt_client.tls_set(
            ca_certs=self.cacert_file,
            certfile=self.certificate_file,
            keyfile=self.private_key_file,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS,
            ciphers=None,
        )
        self.mqtt_client.tls_insecure_set(True)  # merely having the correct cert is ok
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message
        if log.getEffectiveLevel() == logging.DEBUG:
            self.mqtt_client.on_log = self._on_log
        self.mqtt_client.connect(self.broker_host, port=self.broker_port, keepalive=60)
        self.mqtt_client.loop_start()


@arg("--remote-peers", type=int, dest="peers", help="minimum number of peers to await for first alias")
@arg("--remote-case", dest="case", help="case name (broker will determine if you are allowed to access this data)")
@arg("--remote-host", dest="host", help="hostname of target")
@arg("--remote-port", type=int, dest="port", help="broker connection port")
@arg("--remote-broker", dest="broker", help="broker ip-address")
@arg("--remote-key", dest="key", help="private key file")
@arg("--remote-crt", dest="crt", help="client certificate file")
@arg("--remote-ca", dest="ca", help="certificate authority file")
class RemoteLoader(Loader):
    """Load remote targets through a broker."""

    PATH = "/remote/data/children.txt"
    FOLDER = "/remote/children"

    connection = None
    broker = None
    peers = []

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)
        cls = RemoteLoader

        if str(path).startswith("/remote/children/child"):
            self.path = path.read_text()  # update path to reflect the resolved host

        num_peers = 1
        if cls.broker is None:
            uri = kwargs.get("parsed_path")
            if uri is None:
                raise LoaderError("No URI connection details has been passed.")
            options = dict(urllib.parse.parse_qsl(uri.query, keep_blank_values=True))
            cls.broker = Broker(**options)
            cls.broker.connect()
            num_peers = int(options.get("peers", 1))

        self.broker = cls.broker
        self.connection = RemoteConnection(self.broker, self.path)
        self.peers = self.connection.topo(num_peers)

    def map(self, target: Target) -> None:
        if len(self.peers) == 1 and self.peers[0] == str(self.path):
            target.path = Path(str(self.path))
            for disk in self.connection.info():
                target.disks.add(RawContainer(disk))
        else:
            vfs = VirtualFilesystem()
            vfs.map_file_fh(self.PATH, BytesIO("\n".join(self.peers).encode("utf-8")))
            for index, peer in enumerate(self.peers):
                vfs.map_file_fh(f"{self.FOLDER}/child{index}.txt", BytesIO(peer.encode("utf-8")))

            target.fs.mount("/data", vfs)
            target.filesystems.add(vfs)

    @staticmethod
    def detect(path: Path) -> bool:
        return str(path).startswith("/remote/children/child")
