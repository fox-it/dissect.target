from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import ParseResult, parse_qsl

from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.nc import NetcatListenerFilesystem
from dissect.target.loader import Loader
from dissect.target.loaders.ssh import map_shell

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class NetcatListenerLoader(Loader):
    def __init__(self, path: Path, parsed_path: ParseResult | None = None):
        super().__init__(path, parsed_path, resolve=False)
        if parsed_path is None:
            raise LoaderError("Missing URI connection details")

        self._params = dict(parse_qsl(parsed_path.query, keep_blank_values=False))

    @staticmethod
    def detect(path: Path) -> bool:
        return False

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
