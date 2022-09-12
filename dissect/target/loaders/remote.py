from __future__ import annotations

import logging
import socket
import ssl

from io import DEFAULT_BUFFER_SIZE
from pathlib import Path
from struct import pack, unpack
from urllib.parse import urlparse
from typing import Optional, Union, List

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader
from dissect.target.target import Target
from dissect.util.stream import AlignedStream

log = logging.getLogger(__name__)


class RemoteStream(AlignedStream):
    def __init__(self, stream: RemoteStreamConnection, disk_id: int, size: Optional[int] = -1):
        self.stream = stream
        self.disk_id = disk_id
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        return self.stream.read(self.disk_id, offset, length)


class RemoteStreamConnection:

    # Max. number of times we try to reconnect (still tweaking this)
    MAX_RECONNECTS = 3

    # Max. number of read retries
    MAX_RETRY_READ = 3

    # Socket timeout, connections can be slow, so not too low
    # Also there might be an initial waiting time of 10s because of the
    # previous connection! So it must be at least 10s.
    SOCKET_TIMEOUT = 60

    COMMAND_INFO = 1
    COMMAND_QUIT = 2
    COMMAND_READ = 50

    def __init__(self, hostname: str, port: int):
        self.hostname = hostname
        self.port = port
        self._is_connected = False
        self._socket = None
        self._ssl_sock = None
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # Insecure version for PoC, needs to change!
        self._context.verify_mode = ssl.CERT_NONE
        self._context.check_hostname = False
        self._context.load_default_certs()

    def connect(self) -> None:
        if self._is_connected:
            return

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.SOCKET_TIMEOUT)
        ssl_sock = self._context.wrap_socket(self._socket, server_hostname=self.hostname)
        ssl_sock.connect((self.hostname, self.port))
        self._ssl_sock = ssl_sock
        self._is_connected = True

    def is_connected(self) -> bool:
        return self._is_connected

    def _receive_bytes(self, length: int) -> bytes:
        timeout = 0
        data = b""
        received = 0

        while received < length and timeout < self.MAX_RETRY_READ:
            packet = self._ssl_sock.recv(min(length - received, DEFAULT_BUFFER_SIZE))
            packet_size = len(packet)
            data += packet
            received += packet_size
            if packet_size == 0:
                timeout += 1
        if timeout >= self.MAX_RETRY_READ:
            return None
        return data

    def read(self, disk_id: int, offset: int, length: int) -> Union[bytes, None]:
        if length < 1:
            raise NotImplementedError("RemoteStreamConnection does not support size = -1")

        def _reader(disk_id, offset, length):
            self.connect()
            self._ssl_sock.send(pack(">BQQ", self.COMMAND_READ + disk_id, offset, length))
            return self._receive_bytes(length)

        data = None
        reconnects = 0
        while data is None and reconnects < self.MAX_RECONNECTS:
            try:
                data = _reader(disk_id, offset, length)
            except Exception as exc_reader_error:
                log.error("Error while reading data from remote disk #%d.", disk_id, exc_info=exc_reader_error)
                self._ssl_sock.close()
                self._is_connected = False
                reconnects += 1
                continue

        if reconnects >= self.MAX_RECONNECTS:
            raise ConnectionError("Unable to establish connection with remote agent")

        return data

    def close(self) -> None:
        if self.is_connected:
            self._ssl_sock.send(pack(">BQQ", self.COMMAND_QUIT, 0, 0))

    def info(self) -> list[RemoteStream]:
        self.connect()
        self._ssl_sock.send(pack(">BQQ", self.COMMAND_INFO, 0, 0))
        number_of_disks = unpack("<B", self._ssl_sock.recv(1))[0]
        remainder = number_of_disks * 16
        data = self._receive_bytes(remainder)
        disks = []

        for i in range(0, number_of_disks, 16):
            part = data[i : i + 16]
            (disk_size, _) = unpack("<QQ", part)
            disks.append(RemoteStream(self, i, disk_size))

        return disks


class RemoteLoader(Loader):
    def __init__(self, path: Union[Path, str]):
        super().__init__(path)

        # Temporary fix, wait for URI handling feature...
        def _temp_fix_path(path: Union[Path, str]):
            return str(path).replace("remote:/", "remote://")

        url = urlparse(_temp_fix_path(self.path))
        self.stream = RemoteStreamConnection(url.hostname, url.port)

    def map(self, target: Target) -> None:
        for disk in self.stream.info():
            target.disks.add(RawContainer(disk))

    @staticmethod
    def detect(path: Path) -> bool:
        return str(path).startswith("remote:")
