from io import BufferedReader
from urllib.parse import urlparse
import socket
import ssl
from struct import pack

from dissect.util.stream import BufferedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader
from dissect.target.helpers.utils import parse_path_uri


class RemoteStream(BufferedReader):
    def __init__(self, address):
        self._is_connected = False
        parsed_address = urlparse(address)
        self._hostname = parsed_address.hostname
        self._port = parsed_address.port
        self._file_pointer = 0
        self._socket = None
        self._ssl_sock = None

    def connect(self):
        if self._is_connected:
            return
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
        context.load_default_certs()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(self._socket, server_hostname=self._hostname)
        ssl_sock.connect((self._hostname, self._port))
        self._ssl_sock = ssl_sock
        self._is_connected = True

    def is_connected(self):
        return self._is_connected

    def read(self, size=-1):
        if size < 1:
            raise NotImplementedError("RemoteStream does not support size = -1")
        self.connect()
        self._ssl_sock.send(pack(">BQQ", 3, self._file_pointer, size))
        received = 0
        data = b""
        remainder = size
        while received < size:
            packet = self._ssl_sock.recv(remainder)
            packet_size = len(packet)
            data += packet
            received += packet_size
            remainder = size - received
        return data

    def tell(self):
        return self._file_pointer

    def close(self):
        if self.is_connected:
            self._ssl_sock.send(pack(">BQQ", 99, 0, 0))
        return True

    def seek(self, position, whence=0):
        if whence != 0:
            raise NotImplementedError("RemoteStream does not support whence != 0")
        self._file_pointer = position


class RemoteLoader(Loader):
    def map(self, target):
        uri, ports = str(self.path).replace("remote:/", "").split(":", 1)
        base_uri = f"remote://{uri}"
        ports = ports.split(":")
        for port in ports:
            stream = RemoteStream(f"{base_uri}:{port}")
            disk = BufferedStream(stream)
            target.disks.add(RawContainer(disk))

    @staticmethod
    def detect(path):
        # In this case the path is actually an URI it will look like "remote:/xx.xx.xx.xx:yyyy"
        scheme, _, _ = parse_path_uri(path)
        return scheme == "remote"
