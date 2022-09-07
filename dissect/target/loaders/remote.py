from io import BufferedReader
from urllib.parse import urlparse
import socket
import ssl
from struct import pack, unpack

from dissect.util.stream import BufferedStream

from dissect.target.containers.raw import RawContainer, AlignedStream, BufferedStream
from dissect.target.loader import Loader
from dissect.target.helpers.utils import parse_path_uri


class RemoteStream(AlignedStream):
    def __init__(self, stream, disk_id, size=-1):
        self.stream = stream
        self.disk_id = disk_id
        self._pos = 0
        super().__init__(size)

    def _read(self, offset, length):
        length = min(length, max(0, self.size - offset)) if self.size else length
        data = self.stream.read(self.disk_id, offset, length)
        return data


class RemoteStreamConnection:
    def __init__(self, hostname, port):
        self._is_connected = False
        self._hostname = hostname
        self._port = port
        self._socket = None
        self._ssl_sock = None
        self._reconnects = 0

    def connect(self):

        if self._is_connected:
            return

        if self._reconnects >= 3:
            raise ConnectionError("Maximum number of reconnects has been reached.")

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # Insecure version for PoC, needs to change!
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
        context.load_default_certs()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(30)
        ssl_sock = context.wrap_socket(self._socket, server_hostname=self._hostname)
        ssl_sock.connect((self._hostname, self._port))
        self._ssl_sock = ssl_sock
        self._is_connected = True

    def is_connected(self):
        return self._is_connected

    def _receive_bytes(self, length):
        timeout = 0
        data = b""
        received = 0
        timemax = 3
        while received < length and timeout < timemax:
            packet = self._ssl_sock.recv(min(length - received, 2048))
            packet_size = len(packet)
            data += packet
            received += packet_size
            remainder = length - received
            if packet_size == 0:
                timeout += 1
        if timeout >= timemax:
            return None
        return data

    def read(self, disk_id, offset, length):

        if length < 1:
            raise NotImplementedError("RemoteStreamConnection does not support size = -1")

        def _reader(disk_id, offset, length):
            self.connect()
            self._ssl_sock.send(pack(">BQQ", 50 + disk_id, offset, length))
            return self._receive_bytes(length)

        data = None

        while data is None and self._reconnects < 3:
            try:
                data = _reader(disk_id, offset, length)
            except Exception as e:
                self._ssl_sock.close()
                self._is_connected = False
                self._reconnects += 1
                continue

        if self._reconnects >= 3:
            raise ConnectionError("Unable to establish connection with remote agent")

        return data

    def close(self):
        if self.is_connected:
            self._ssl_sock.send(pack(">BQQ", 2, 0, 0))
        return True

    def info(self):
        self.connect()
        self._ssl_sock.send(pack(">BQQ", 1, 0, 0))
        number_of_disks = unpack("<B", self._ssl_sock.recv(1))[0]
        remainder = number_of_disks * 16
        data = self._receive_bytes(remainder)
        disks = []

        for i in range(0, number_of_disks):
            part = data[(i * 16) : ((i * 16) + 16)]
            info = unpack("<QQ", part)
            disks.append(RemoteStream(self, i, info[0] * info[1]))

        return disks


class RemoteLoader(Loader):
    def map(self, target):

        # Temporary fix, wait for URI handling feature...
        def _temp_fix_path(path):
            return str(path).replace("remote:/", "remote://")

        url = urlparse(_temp_fix_path(self.path))
        stream = RemoteStreamConnection(url.hostname, url.port)
        disks = stream.info()

        for disk in disks:
            target.disks.add(RawContainer(disk))

    @staticmethod
    def detect(path):
        return str(path).startswith("remote:")
