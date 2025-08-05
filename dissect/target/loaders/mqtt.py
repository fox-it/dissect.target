from __future__ import annotations

import argparse
import atexit
import logging
import math
import os
import re
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass
from functools import lru_cache
from getpass import getpass
from pathlib import Path
from struct import pack, unpack_from
from threading import Thread
from typing import TYPE_CHECKING, Any, Callable, ClassVar, TypeVar

import paho.mqtt.client as mqtt
from dissect.util.stream import AlignedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.loader import Loader
from dissect.target.plugin import arg

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

log = logging.getLogger(__name__)

DISK_INDEX_OFFSET = 9

R = TypeVar("R")


def suppress(func: Callable[..., R]) -> Callable[..., R | None]:
    def suppressed(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception:
            return None

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


class MqttTransferRatePerSecond:
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.timestamps = []
        self.bytes = []

    def record(self, timestamp: float, byte_count: int) -> MqttTransferRatePerSecond:
        while self.timestamps and (timestamp - self.timestamps[0] > self.window_size):
            self.timestamps.pop(0)
            self.bytes.pop(0)

        self.timestamps.append(timestamp)
        self.bytes.append(byte_count)
        return self

    def value(self, current_time: float) -> float:
        if not self.timestamps:
            return 0

        elapsed_time = current_time - self.timestamps[0]
        if elapsed_time == 0:
            return 0

        total_bytes = self.bytes[-1] - self.bytes[0]

        return total_bytes / elapsed_time


class MqttStream(AlignedStream):
    def __init__(self, stream: MqttConnection, disk_id: int, size: int | None = None):
        self.stream = stream
        self.disk_id = disk_id
        super().__init__(size)

    def _read(self, offset: int, length: int, optimization_strategy: int = 0) -> bytes:
        return self.stream.read(self.disk_id, offset, length, optimization_strategy)


class MqttDiagnosticLine:
    def __init__(self, connection: MqttConnection, total_peers: int):
        self.connection = connection
        self.total_peers = total_peers
        self._columns, self._rows = os.get_terminal_size(0)
        atexit.register(self._detach)
        self._attach()

    def _attach(self) -> None:
        # save cursor position
        sys.stderr.write("\0337")
        # set top and bottom margins of the scrolling region to default
        sys.stderr.write("\033[r")
        # restore cursor position
        sys.stderr.write("\0338")
        # move cursor down one line in the same column; if at the bottom, the screen scrolls up
        sys.stderr.write("\033D")
        # move cursor up one line in the same column; if at the top, screen scrolls down
        sys.stderr.write("\033M")
        # save cursor position again
        sys.stderr.write("\0337")
        # restrict scrolling to a region from the first line to one before the last line
        sys.stderr.write(f"\033[1;{self._rows - 1}r")
        # restore cursor position after setting scrolling region
        sys.stderr.write("\0338")

    def _detach(self) -> None:
        # save cursor position
        sys.stderr.write("\0337")
        # move cursor to the specified position (last line, first column)
        sys.stderr.write(f"\033[{self._rows};1H")
        # clear from cursor to end of the line
        sys.stderr.write("\033[K")
        # reset scrolling region to include the entire display
        sys.stderr.write("\033[r")
        # restore cursor position
        sys.stderr.write("\0338")
        # ensure the written content is displayed (flush output)
        sys.stderr.flush()

    def display(self) -> None:
        # prepare: set background color to blue and text color to white at the beginning of the line
        prefix = "\x1b[44m\x1b[37m\r"
        # reset all attributes (colors, styles) to their defaults afterwards
        suffix = "\x1b[0m"
        # separator to set background color to red and text style to bold
        separator = "\x1b[41m\x1b[1m"
        logo = "TARGETD"

        start = time.time()
        transfer_rate = MqttTransferRatePerSecond(window_size=7)

        while True:
            time.sleep(0.05)
            peers = "?"
            try:
                peers = len(self.connection.broker.peers(self.connection.host))
            except Exception:
                pass

            recv = self.connection.broker.bytes_received
            now = time.time()
            transfer = transfer_rate.record(now, recv).value(now) / 1000  # convert to KB/s
            failures = self.connection.retries
            seconds_elapsed = round(now - start) % 60
            minutes_elapsed = math.floor((now - start) / 60) % 60
            hours_elapsed = math.floor((now - start) / 60**2)
            timer = f"{hours_elapsed:02d}:{minutes_elapsed:02d}:{seconds_elapsed:02d}"
            display = f"{timer} {peers}/{self.total_peers} peers {transfer:>8.2f} KB p/s {failures:>4} failures"
            rest = self._columns - len(display)
            padding = (rest - len(logo)) * " "

            # save cursor position
            sys.stderr.write("\0337")
            # move cursor to specified position (last line, first column)
            sys.stderr.write(f"\033[{self._rows};1H")
            # disable line wrapping
            sys.stderr.write("\033[?7l")
            # reset all attributes
            sys.stderr.write("\033[0m")
            # write the display line with prefix, calculated display content, padding, separator, and logo
            sys.stderr.write(prefix + display + padding + separator + logo + suffix)
            # enable line wrapping again
            sys.stderr.write("\033[?7h")
            # restore cursor position
            sys.stderr.write("\0338")
            # flush output to ensure it is displayed
            sys.stderr.flush()

    def start(self) -> None:
        t = Thread(target=self.display)
        t.daemon = True
        t.start()


class MqttConnection:
    broker = None
    host = None
    prev = -1
    factor = 1
    prefetch_factor_inc = 10
    retries = 0

    def __init__(self, broker: Broker, host: str):
        self.broker = broker
        self.host = str(host)
        self.info = lru_cache(128)(self.info)
        self.read = lru_cache(128)(self.read)

    def topo(self, peers: int) -> list[str]:
        self.broker.topology(self.host)

        while len(self.broker.peers(self.host)) < peers:
            self.broker.topology(self.host)
            time.sleep(1)
        return self.broker.peers(self.host)

    def info(self) -> list[MqttStream]:
        disks = []
        self.broker.info(self.host)

        message = None
        while message is None:
            message = self.broker.disk(self.host)

        for idx, disk in enumerate(message.disks):
            disks.append(MqttStream(self, idx, disk.total_size))

        return disks

    def read(self, disk_id: int, offset: int, length: int, optimization_strategy: int) -> bytes:
        message = None

        message = self.broker.read(self.host, disk_id, offset, length)
        if message:
            return message.data

        if self.prev == offset - (length * self.factor):
            if self.factor < 500:
                self.factor += self.prefetch_factor_inc
        else:
            self.factor = 1

        self.prev = offset
        flength = length * self.factor
        self.broker.factor = self.factor
        self.broker.seek(self.host, disk_id, offset, flength, optimization_strategy)
        attempts = 0
        while True:
            if message := self.broker.read(self.host, disk_id, offset, length):
                # don't waste time with sleep if we have a response
                break

            attempts += 1
            time.sleep(0.1)
            if attempts > 300:
                # message might have not reached agent, resend...
                self.broker.seek(self.host, disk_id, offset, flength, optimization_strategy)
                attempts = 0
                self.retries += 1

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
    bytes_received = 0
    monitor = False
    username = None
    password = None

    diskinfo: ClassVar[dict] = {}
    index: ClassVar[dict] = {}
    topo: ClassVar[dict] = {}
    factor = 1

    def __init__(
        self, broker: str, port: str, key: str, crt: str, ca: str, case: str, username: str, password: str, **kwargs
    ):
        self.broker_host = broker
        self.broker_port = int(port)
        self.private_key_file = key
        self.certificate_file = crt
        self.cacert_file = ca
        self.case = case
        self.username = username
        self.password = password
        self.command = kwargs.get("command")

    def clear_cache(self) -> None:
        self.index = {}

    @suppress
    def read(self, host: str, disk_id: int, seek_address: int, read_length: int) -> SeekMessage:
        key = f"{host}-{disk_id}-{seek_address}-{read_length}"
        return self.index.get(key)

    @suppress
    def disk(self, host: str) -> DiskMessage:
        return self.diskinfo[host]

    def peers(self, host: str) -> list[str]:
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

        for i in range(self.factor):
            sublength = int(read_length / self.factor)
            start = i * sublength
            key = f"{hostname}-{disk_id}-{seek_address + start}-{sublength}"
            if key in self.index:
                continue

            self.index[key] = SeekMessage(data=payload[start : start + sublength])

    def _on_id(self, hostname: str, payload: bytes) -> None:
        key = hostname
        host = payload.decode("utf-8")
        if host not in self.topo[key]:
            self.topo[key].append(payload.decode("utf-8"))
            self.mqtt_client.subscribe(f"{self.case}/{host}/DISKS")
            self.mqtt_client.subscribe(f"{self.case}/{host}/READ/#")
            if self.command is not None:
                self.mqtt_client.subscribe(f"{self.case}/{host}/CALLID")
                self.mqtt_client.publish(f"{self.case}/{host}/COMM", self.command.encode("utf-8"))
            time.sleep(1)

    def _on_call_id(self, hostname: str, payload: bytes) -> None:
        try:
            decoded_payload = payload.decode("utf-8")
        except UnicodeDecodeError as e:
            log.exception("Failed to decode payload for hostname %s: %s", hostname, e)  # noqa: TRY401
            return

        print(decoded_payload)

    def _on_log(self, client: mqtt.Client, userdata: Any, log_level: int, message: str) -> None:
        log.debug(message)

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: dict, rc: int) -> None:
        self.connected = True

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.client.MQTTMessage) -> None:
        tokens = msg.topic.split("/")
        casename, hostname, response, *_ = tokens
        if casename != self.case:
            return

        if self.monitor:
            self.bytes_received += len(msg.payload)

        if response == "DISKS":
            self._on_disk(hostname, msg.payload)
        elif response == "READ":
            self._on_read(hostname, tokens, msg.payload)
        elif response == "ID":
            self._on_id(hostname, msg.payload)
        elif response == "CALLID":
            self._on_call_id(hostname, msg.payload)

    def seek(self, host: str, disk_id: int, offset: int, flength: int, optimization_strategy: int) -> None:
        length = int(flength / self.factor)
        key = f"{host}-{disk_id}-{offset}-{length}"
        if key in self.index:
            return

        self.mqtt_client.publish(
            f"{self.case}/{host}/SEEK/{disk_id}/{hex(offset)}/{hex(flength)}", pack("<I", optimization_strategy)
        )

    def info(self, host: str) -> None:
        self.mqtt_client.publish(f"{self.case}/{host}/INFO")

    def topology(self, host: str) -> None:
        if host not in self.topo:
            self.topo[host] = []
        self.mqtt_client.subscribe(f"{self.case}/{host}/ID")
        time.sleep(1)  # need some time to avoid race condition, i.e. MQTT might react too fast
        # send a simple clear command (invalid, just clears the prev. msg) just in case TOPO is stale
        self.mqtt_client.publish(f"{self.case}/{host}/CLR")
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
        self.mqtt_client.username_pw_set(self.username, self.password)
        self.mqtt_client.tls_insecure_set(True)  # merely having the correct cert is ok
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message
        if log.getEffectiveLevel() == logging.DEBUG:
            self.mqtt_client.on_log = self._on_log
        self.mqtt_client.connect(self.broker_host, port=self.broker_port, keepalive=60)
        self.mqtt_client.loop_start()


def strictly_positive(value: str) -> int:
    """Validates that the provided value is a strictly positive integer.

    This function is intended to be used as a type for argparse arguments.

    Args:
        value (str): The value to validate.

    Returns:
        int: The validated integer value.

    Raises:
        argparse.ArgumentTypeError: If the value is not a strictly positive integer.
    """
    try:
        strictly_positive_value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer value specified: '{value}'")

    if strictly_positive_value < 1:
        raise argparse.ArgumentTypeError("Value must be larger than or equal to 1.")
    return strictly_positive_value


def port(value: str) -> int:
    """Convert a string value to an integer representing a valid port number.

    This function is intended to be used as a type for argparse arguments.

    Args:
        value (str): The string representation of the port number.
    Returns:
        int: The port number as an integer.
    Raises:
        argparse.ArgumentTypeError: If the port number is not an integer or out of the valid range (1-65535).
    """

    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid port number specified: '{value}'")

    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("Port number must be between 1 and 65535.")
    return port


def case(value: str) -> str:
    """Validates that the given value is a valid case name consisting of
    alphanumeric characters and underscores only.

    This function is intended to be used as a type for argparse arguments.

    Args:
        value (str): The case name to validate.

    Returns:
        str: The validated case name if it matches the required pattern.

    Raises:
        argparse.ArgumentTypeError: If the case name does not match the required pattern.
    """

    if re.match(r"^[a-zA-Z0-9_]+$", value):
        return value

    raise argparse.ArgumentTypeError(f"Invalid case name specified: '{value}'")


@arg(
    "--mqtt-peers",
    type=strictly_positive,
    dest="peers",
    default=1,
    help="minimum number of peers to await for first alias",
)
@arg(
    "--mqtt-case",
    type=case,
    dest="case",
    help="case name (broker will determine if you are allowed to access this data)",
)
@arg("--mqtt-port", type=port, dest="port", default=443, help="broker connection port")
@arg("--mqtt-broker", default="localhost", dest="broker", help="broker ip-address")
@arg("--mqtt-key", type=Path, dest="key", required=True, help="private key file")
@arg("--mqtt-crt", type=Path, dest="crt", required=True, help="client certificate file")
@arg("--mqtt-ca", type=Path, dest="ca", required=True, help="certificate authority file")
@arg("--mqtt-command", dest="command", help="direct command to client(s)")
@arg("--mqtt-diag", action="store_true", dest="diag", help="show MQTT diagnostic information")
@arg("--mqtt-username", dest="username", default="mqtt-loader", help="Username for connection")
@arg("--mqtt-password", action="store_true", dest="password", help="Ask for password before connecting")
class MqttLoader(Loader):
    """Load remote targets through a broker."""

    connection = None
    broker = None
    peers: ClassVar[list] = []

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs, resolve=False)
        cls = MqttLoader
        self.broker = cls.broker
        self.connection = MqttConnection(self.broker, path)

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    @staticmethod
    def find_all(path: Path, parsed_path: urllib.parse.ParseResult | None = None) -> Iterator[str]:
        cls = MqttLoader
        num_peers = 1

        if parsed_path is None:
            raise LoaderError("No URI connection details have been passed.")

        if cls.broker is None:
            options = dict(urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True))
            if options.get("password"):
                options["password"] = getpass()
            cls.broker = Broker(**options)
            cls.broker.connect()
            num_peers = int(options.get("peers", 1))
            cls.connection = MqttConnection(cls.broker, path)
            if options.get("diag"):
                cls.broker.monitor = True
                MqttDiagnosticLine(cls.connection, num_peers).start()
        else:
            cls.connection = MqttConnection(cls.broker, path)

        cls.peers = cls.connection.topo(num_peers)
        yield from (f"mqtt://{peer}?{parsed_path.query}" for peer in cls.peers)

    def map(self, target: Target) -> None:
        for disk in self.connection.info():
            target.disks.add(RawContainer(disk))
