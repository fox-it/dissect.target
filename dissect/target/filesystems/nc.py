from __future__ import annotations

import logging
import random
import socket
from typing import BinaryIO

from dissect.target.filesystems.shell import ShellFilesystem

log = logging.getLogger(__name__)

SOCKET_BUFFER_SIZE = 4096


class NetcatListenerFilesystem(ShellFilesystem):
    """A filesystem that uses a netcat listener to execute shell commands.

    Args:
        host: The hostname or IP address to listen on.
        port: The port number to listen on (default is 4444).
        dialect: The shell dialect to use (default is "auto").
    """

    __type__ = "nc"

    def __init__(self, host: str, port: int = 4444, dialect: str = "auto", *args, **kwargs):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(1)
        log.info("Listening on %s:%d", host, port)
        self.client_socket, self.client_address = self.socket.accept()
        log.info("Connection established with %s:%d", self.client_address[0], self.client_address[1])

        super().__init__(dialect, *args, **kwargs)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on NetcatListenerFilesystem class")

    def execute(self, command: str) -> tuple[bytes, bytes]:
        n = random.randint(0, 1000)
        start_token = random.randbytes(8).hex()
        end_token = random.randbytes(8).hex()
        stderr_token = random.randbytes(8).hex()

        # Some shell magic to separate stdout and stderr
        command = f"({command}) 2> >(sed 's/^/{stderr_token}/;s/$/{stderr_token}/')"
        command = f"\necho -n {start_token}$(({n})); {command}; echo -n {end_token}$(({n}))\n"

        self.client_socket.sendall(command.encode())

        start_marker = f"{start_token}{n}".encode()
        end_marker = f"{end_token}{n}".encode()

        data = b""
        while True:
            if not (buf := self.client_socket.recv(SOCKET_BUFFER_SIZE)):
                continue
            data += buf
            if end_marker in data:
                break

        _, _, data = data.partition(start_marker)
        data, _, _ = data.partition(end_marker)

        stdout, _, data = data.partition(stderr_token.encode())
        data, _, stdout_maybe = data.partition(f"{stderr_token}\n".encode())

        return stdout + stdout_maybe, data
