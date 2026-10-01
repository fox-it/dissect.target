from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.adb import AdbFilesystem
from dissect.target.loaders.shell import ShellLoader, map_shell

if TYPE_CHECKING:
    from dissect.target.target import Target

DEFAULT_ADB_HOST = "127.0.0.1"
DEFAULT_ADB_PORT = 5037


class AdbLoader(ShellLoader):
    """A loader that sets up a connection to an Android device via ADB.

    By default connects to localhost on default ADB port 5037.

    Connecting to a specific device can be done by specifying its serial::

        target-shell adb://serial

    If no serial is specified and only one device is connected, it will be used automatically.
    """

    def map(self, target: Target) -> None:
        serial = self.parsed_path.hostname
        if not serial or serial == "-":
            serial = None

        host = self._params.get("host", DEFAULT_ADB_HOST)
        port = int(self._params.get("port", DEFAULT_ADB_PORT))
        dialect = self._params.get("dialect", "auto").lower()
        fs = AdbFilesystem(host, port, serial, dialect)

        map_shell(
            target,
            fs,
            self.parsed_path.path,
            self._params.get("map", "dir").lower(),
            self._params.get("os", "auto").lower(),
        )
