from __future__ import annotations

import logging
import socket
import ssl
import time

from io import DEFAULT_BUFFER_SIZE
from pathlib import Path
from struct import pack, unpack
from typing import Optional, Union

from dissect.util.stream import AlignedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.loader import Loader
from dissect.target.target import Target


log = logging.getLogger(__name__)


class RemoteStream(AlignedStream):
    def __init__(self, stream: RemoteStreamConnection, disk_id: int, size: Optional[int] = None):
        self.stream = stream
        self.disk_id = disk_id
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        return self.stream.read(self.disk_id, offset, length)


class RemoteStreamConnection:

    # Max. number of times we try to reconnect (still tweaking this)
    MAX_RECONNECTS = 30

    # Time to wait before attempting to reconnect
    RECONNECT_WAIT = 10

    # Socket timeout, connections can be slow, so not too low
    # Also there might be an initial waiting time of 10s because of the
    # previous connection! So it must be at least 10s.
    SOCKET_TIMEOUT = 30

    # Remote agent understands 3 commands:
    # 1      INFO: return disk size and sector size for each remote disk
    # 2      QUIT: shutdown remote agent
    # 50 + X READ: read disk number X (starts with 0)
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
        self._context.load_default_certs()
        self.log = log

    def is_connected(self) -> bool:
        return self._is_connected

    def connect(self) -> None:
        if self._is_connected:
            return

        reconnects = 0
        while self._is_connected is False:
            self.log.debug("Connecting to agent")
            # Even during the handshake things can go wrong with unreliable connections
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.SOCKET_TIMEOUT)
                ssl_sock = self._context.wrap_socket(self._socket, server_hostname=self.hostname)
                ssl_sock.connect((self.hostname, self.port))
                self._ssl_sock = ssl_sock
                self._is_connected = True
                self.log.debug("Connection established with agent")
            except Exception:
                # If the max. connections are exceeded it is probably no use anymore because
                # the remote system has become unreachable and we need to report back to the
                # user that we can no longer contact the remote machine.
                if reconnects > self.MAX_RECONNECTS:
                    raise ConnectionError("Unable to reconnect with remote agent.")
                if self._ssl_sock is not None:
                    self._ssl_sock.close()
                if self._socket is not None:
                    self._socket.close()
                # Directly re-connecting seem to be less succesful, allow some time to re-connect
                # seems to yield best results in practice
                self.log.debug("Unable to connect to agent, next attempt in %d sec.", self.RECONNECT_WAIT)
                time.sleep(self.RECONNECT_WAIT)
                reconnects += 1

    def _receive_bytes(self, length: int) -> bytes:
        data = b""
        received = 0
        while received < length:
            packet = self._ssl_sock.recv(min(length - received, DEFAULT_BUFFER_SIZE))
            packet_size = len(packet)
            data += packet
            received += packet_size

        return data

    def read(self, disk_id: int, offset: int, length: int) -> bytes:
        # In practice this should not occur but if one uses this stream directly we will
        # be kind and inform the user about the limitations of this logic
        if length < 0:
            raise NotImplementedError("RemoteStreamConnection does not support length = -1")

        if length == 0:
            return b""

        data = b""
        received = 0
        while received < length:
            self.connect()
            self._ssl_sock.send(pack(">BQQ", self.COMMAND_READ + disk_id, offset, length))
            try:
                data += self._receive_bytes(length)
                received += length
            except Exception:
                self.log.debug("Unable to read data from agent, re-connecting")
                self._ssl_sock.close()
                self._socket.close()
                self._is_connected = False

        return data

    def close(self) -> None:
        if self.is_connected:
            self._ssl_sock.send(pack(">BQQ", self.COMMAND_QUIT, 0, 0))

    def info(self) -> list[RemoteStream]:
        self.connect()
        response_size = 16
        self._ssl_sock.send(pack(">BQQ", self.COMMAND_INFO, 0, 0))
        number_of_disks = unpack("<B", self._ssl_sock.recv(1))[0]
        remainder = number_of_disks * response_size
        data = self._receive_bytes(remainder)
        disks = []
        for i in range(0, number_of_disks * response_size, response_size):
            part = data[i : i + response_size]
            (disk_size, _) = unpack("<QQ", part)
            disks.append(RemoteStream(self, i // response_size, disk_size))

        return disks


class RemoteLoader(Loader):
    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)
        uri = kwargs.get("parsed_path")
        if uri is None:
            raise LoaderError("No URI connection details has been passed.")
        self.stream = RemoteStreamConnection(uri.hostname, uri.port)

    def map(self, target: Target) -> None:
        self.stream.log = target.log
        for disk in self.stream.info():
            target.disks.add(RawContainer(disk))

    @staticmethod
    def detect(path: Path) -> bool:
        # You can only activate this loader by URI-scheme "remote://"
        return False
