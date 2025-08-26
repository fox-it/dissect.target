from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.nc import NetcatListenerFilesystem
from dissect.target.loaders.shell import ShellLoader, map_shell

if TYPE_CHECKING:
    from dissect.target.target import Target


class NetcatListenerLoader(ShellLoader):
    """A loader that accepts reverse TCP shell connections.

    Sets up a TCP listener on the specified host and port and waits for a connection::

        target-shell nc://0.0.0.0:4444

    """

    def map(self, target: Target) -> None:
        host = self.parsed_path.hostname
        port = self.parsed_path.port or 4444
        dialect = self._params.get("dialect", "auto").lower()

        fs = NetcatListenerFilesystem(host, port, dialect)

        map_shell(
            target,
            fs,
            self.parsed_path.path,
            self._params.get("map", "dir").lower(),
            self._params.get("os", "auto").lower(),
        )
