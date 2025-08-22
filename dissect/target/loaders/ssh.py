from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.ssh import SshFilesystem
from dissect.target.loader import DirLoader, Loader, RawLoader, find_loader
from dissect.target.loaders.local import (
    map_esxi_drives,
    map_linux_drives,
    map_solaris_drives,
)
from dissect.target.plugin import os_plugins

if TYPE_CHECKING:
    from pathlib import Path
    from urllib.parse import ParseResult

    from dissect.target.filesystems.shell import ShellFilesystem
    from dissect.target.target import Target


class SshLoader(Loader):
    """A loader that connects to a remote SSH server and maps the filesystem.

    Will use SFTP by default, but can be configured to use other shell dialects.

    Basic connection::

        ssh://user:password@host

    Connect with a key file and passphrase::

        ssh://user@host?key_filename=/path/to/keyfile&key_passphrase=secret

    Connect with a specific shell dialect::

        ssh://user@host?dialect=linux

    Load the local disks, emulating the local loader::

        ssh://user@host?map=local

    Open a specific path on the remote server as target, invoking another loader::

        ssh://user@host/path/to/file.vmdk

    Use the local SSH agent, private keys or host keys::

        ssh://user@host?isolate=false

    Specify a specific OS plugin to use (for performance reasons you may want to do this)::

        ssh://user@host?os=default

    """

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
            loader(path).map(target)

    # Otherwise, try one of the mapping methods
    elif map == "dir":
        target.filesystems.add(fs)

    # Try to load the local disks, emulating the local loader
    elif map == "local":
        root = fs.path("/")

        # ESXi
        if root.joinpath("vmfs/devices/disks").exists():
            map_esxi_drives(root, target)

        # Solaris
        elif root.joinpath("dev/dsk").exists():
            map_solaris_drives(root, target)

        # Linux
        elif root.joinpath("dev").exists():
            map_linux_drives(root, target)

    if os != "auto":
        for descriptor in os_plugins():
            if descriptor.module.split(".")[-2] == os:
                target._os_plugin = descriptor.cls
                break
