from __future__ import annotations

import logging
from typing import BinaryIO

from dissect.target.exceptions import FilesystemError
from dissect.target.filesystems.shell import ShellFilesystem

try:
    from adbutils import AdbClient

    HAS_ADB = True
except ImportError:
    HAS_ADB = False

log = logging.getLogger(__name__)


class AdbFilesystem(ShellFilesystem):
    """A filesystem that uses Android Debug Bridge to execute shell commands.

    Args:
        host: The ADB hostname to connect to
        port: The ADB port to connect to
        serial: The device serial number
    """

    __type__ = "adb"

    def __init__(self, host: str, port: int, serial: str | None, dialect: str = "auto", *args, **kwargs):
        if not HAS_ADB:
            raise ImportError("Required dependency 'adbutils' is missing")

        self.client = AdbClient(host, port)
        devices = self.client.list(extended=True)

        if serial is not None:
            if (matching_device := next((d for d in devices if d.serial == serial), None)) is None:
                raise FilesystemError(f"Device with serial {serial} not found")
        else:
            if not devices:
                raise FilesystemError("No connected ADB devices found")

            if len(devices) > 1:
                raise FilesystemError("Multiple ADB devices connected; please specify a serial")

            serial = devices[0].serial

        self.device = self.client.device(serial)

        # Only shell_v2 seperates stdout and stderr
        if "shell_v2" not in self.device.get_features():
            raise FilesystemError("Device does not support shell_v2 feature")

        log.info("Connection established with %s", self.device.serial)

        super().__init__(dialect, *args, **kwargs)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on AdbFilesystem class")

    def execute(self, command: str) -> tuple[bytes, bytes]:
        ret = self.device.shell2(command, encoding=None, v2=True)
        return ret.stdout, ret.stderr
