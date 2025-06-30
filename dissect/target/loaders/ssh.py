from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.filesystems.ssh import SshFilesystem
from dissect.target.loader import DirLoader, Loader, RawLoader, find_loader
from dissect.target.loaders.local import LINUX_DRIVE_REGEX, SOLARIS_DRIVE_REGEX
from dissect.target.plugin import os_plugins

if TYPE_CHECKING:
    from pathlib import Path
    from urllib.parse import ParseResult

    from dissect.target.filesystems.shell import ShellFilesystem
    from dissect.target.target import Target


class SshLoader(Loader):
    def __init__(self, path: Path, parsed_path: ParseResult | None = None):
        super().__init__(path, parsed_path, resolve=False)
        if parsed_path is None:
            raise LoaderError("Missing URI connection details")

        self._params = dict(parse_qsl(parsed_path.query, keep_blank_values=False))

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        hostname = self.parsed_path.hostname
        username = self.parsed_path.username
        password = self.parsed_path.password
        port = self.parsed_path.port or 22
        key_filename = self._params.get("key_filename")
        key_passphrase = self._params.get("key_passphrase")
        isolate = self._params.get("isolate", "true").lower() in ("true", "1", "yes")
        dialect = self._params.get("dialect", "auto").lower()

        fs = SshFilesystem(
            host=hostname,
            port=port,
            username=username,
            password=password,
            key_filename=key_filename,
            key_passphrase=key_passphrase,
            isolate=isolate,
            dialect=dialect,
        )

        map_shell(
            target,
            fs,
            self.parsed_path.path,
            self._params.get("map", "dir").lower(),
            self._params.get("os", "auto").lower(),
        )


def map_shell(target: Target, fs: ShellFilesystem, path: str, map: str, os: str) -> None:
    # If we have a path component, use that and try to find a loader for it
    if path not in ("", "/"):
        path = fs.path(path)

        if loader := find_loader(path, fallbacks=[DirLoader, RawLoader]):
            ldr = loader(path)
            ldr.map(target)
    # Otherwise, try one of the mapping methods
    elif map == "dir":
        target.filesystems.add(fs)
    # Try to load the local disks, emulating the local loader
    elif map == "local":
        # ESXi
        if (path := fs.path("/vmfs/devices/disks")).exists():
            for drive in path.glob("vml.*"):
                if ":" in drive.name:
                    continue
                target.disks.add(RawContainer(drive.open("rb")))

        # Solaris
        elif (path := fs.path("/dev/dsk")).exists():
            for drive in path.iterdir():
                if not SOLARIS_DRIVE_REGEX.match(drive.name):
                    continue
                target.disks.add(RawContainer(drive.open("rb")))

        # Linux
        elif (path := fs.path("/dev")).exists() and (
            drives := [d for d in path.iterdir() if LINUX_DRIVE_REGEX.match(d.name)]
        ):
            for drive in drives:
                target.disks.add(RawContainer(drive.open("rb")))

            for path in [fs.path("/proc"), fs.path("/sys")]:
                if path.exists():
                    dirfs = DirectoryFilesystem(path)
                    target.filesystems.add(dirfs)
                    target.fs.mount(str(path), dirfs)

    if os != "auto":
        for descriptor in os_plugins():
            if descriptor.module.split(".")[-2] == os:
                target._os_plugin = descriptor.cls
                break
