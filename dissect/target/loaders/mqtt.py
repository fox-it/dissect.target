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
from typing import Any, Callable, Optional, Union

import paho.mqtt.client as mqtt
from dissect.util.stream import AlignedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.plugin import arg
from dissect.target.target import Target

log = logging.getLogger(__name__)

DISK_INDEX_OFFSET = 9


def suppress(func: Callable) -> Callable:
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


class MQTTStream(AlignedStream):
    def __init__(self, stream: MQTTConnection, disk_id: int, size: Optional[int] = None):
        self.stream = stream
        self.disk_id = disk_id
        super().__init__(size)

    def _read(self, offset: int, length: int, optimization_strategy: int = 0) -> bytes:
        data = self.stream.read(self.disk_id, offset, length, optimization_strategy)
        return data


class MQTTConnection:
    broker = None
    host = None

    def __init__(self, broker: Broker, host: str):
        self.broker = broker
        self.host = str(host)
        self.info = lru_cache(128)(self.info)
        self.read = lru_cache(128)(self.read)

    def topo(self, peers: int):
        self.broker.topology(self.host)

        while len(self.broker.peers(self.host)) < peers:
            self.broker.topology(self.host)
            time.sleep(1)
        return self.broker.peers(self.host)

    def info(self) -> list[MQTTStream]:
        disks = []
        self.broker.info(self.host)

        message = None
        while message is None:
            message = self.broker.disk(self.host)

        for idx, disk in enumerate(message.disks):
            disks.append(MQTTStream(self, idx, disk.total_size))

        return disks

    def read(self, disk_id: int, offset: int, length: int, optimization_strategy: int) -> bytes:
        message = None
        self.broker.seek(self.host, disk_id, offset, length, optimization_strategy)

        attempts = 0
        while True:
            message = self.broker.read(self.host, disk_id, offset, length)
            # don't waste time with sleep if we have a response
            if message:
                break

            attempts += 1
            time.sleep(0.01)
            if attempts > 100:
                # message might have not reached agent, resend...
                self.broker.seek(self.host, disk_id, offset, length, optimization_strategy)
                attempts = 0

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
        self.command = kwargs.get("command", None)

    @suppress
    def read(self, host: str, disk_id: int, seek_address: int, read_length: int) -> SeekMessage:
        key = f"{host}-{disk_id}-{seek_address}-{read_length}"
        return self.index.pop(key)

    @suppress
    def disk(self, host: str) -> DiskMessage:
        return self.diskinfo[host]

    def peers(self, host: str) -> int:
        return self.topo[host]

    def _on_disk(self, hostname: str, payload: bytes) -> None:
        (num_of_disks,) = unpack_from("<B", payload, offset=0)
        disks = []
        for disk_index in range(num_of_disks):
            (
                sector_size,
                total_size,
            ) = unpack_from("<IQ", payload, offset=1 + (disk_index * DISK_INDEX_OFFSET))
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
            if self.command is not None:
                self.mqtt_client.publish(f"{self.case}/{host}/COMM", self.command.encode("utf-8"))
            time.sleep(1)

    def _on_log(self, client: mqtt.Client, userdata: Any, log_level: int, message: str) -> None:
        log.debug(message)

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: dict, rc: int) -> None:
        self.connected = True

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.client.MQTTMessage) -> None:
        tokens = msg.topic.split("/")
        casename, hostname, response, *_ = tokens
        if casename != self.case:
            return

        if response == "DISKS":
            self._on_disk(hostname, msg.payload)
        elif response == "READ":
            self._on_read(hostname, tokens, msg.payload)
        elif response == "ID":
            self._on_id(hostname, msg.payload)

    def seek(self, host: str, disk_id: int, offset: int, length: int, optimization_strategy: int) -> None:
        self.mqtt_client.publish(
            f"{self.case}/{host}/SEEK/{disk_id}/{hex(offset)}/{hex(length)}", pack("<I", optimization_strategy)
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


@arg("--mqtt-peers", type=int, dest="peers", help="minimum number of peers to await for first alias")
@arg("--mqtt-case", dest="case", help="case name (broker will determine if you are allowed to access this data)")
@arg("--mqtt-port", type=int, dest="port", help="broker connection port")
@arg("--mqtt-broker", dest="broker", help="broker ip-address")
@arg("--mqtt-key", dest="key", help="private key file")
@arg("--mqtt-crt", dest="crt", help="client certificate file")
@arg("--mqtt-ca", dest="ca", help="certificate authority file")
@arg("--mqtt-command", dest="command", help="direct command to client(s)")
class MQTTLoader(Loader):
    """Load remote targets through a broker."""

    PATH = "/remote/data/hosts.txt"
    FOLDER = "/remote/hosts"

    connection = None
    broker = None
    peers = []

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)
        cls = MQTTLoader

        if str(path).startswith("/remote/hosts/host"):
            self.path = path.read_text()  # update path to reflect the resolved host

        num_peers = 1
        if cls.broker is None:
            if (uri := kwargs.get("parsed_path")) is None:
                raise LoaderError("No URI connection details have been passed.")
            options = dict(urllib.parse.parse_qsl(uri.query, keep_blank_values=True))
            cls.broker = Broker(**options)
            cls.broker.connect()
            num_peers = int(options.get("peers", 1))

        self.broker = cls.broker
        self.connection = MQTTConnection(self.broker, self.path)
        self.peers = self.connection.topo(num_peers)

    def map(self, target: Target) -> None:
        if len(self.peers) == 1 and self.peers[0] == str(self.path):
            target.path = Path(str(self.path))
            for disk in self.connection.info():
                target.disks.add(RawContainer(disk))
        else:
            target.props["mqtt"] = True

            vfs = VirtualFilesystem()
            vfs.map_file_fh(self.PATH, BytesIO("\n".join(self.peers).encode("utf-8")))
            for index, peer in enumerate(self.peers):
                vfs.map_file_fh(f"{self.FOLDER}/host{index}-{peer}", BytesIO(peer.encode("utf-8")))

            target.fs.mount("/data", vfs)
            target.filesystems.add(vfs)

    @staticmethod
    def detect(path: Path) -> bool:
        return str(path).startswith("/remote/hosts/host")
