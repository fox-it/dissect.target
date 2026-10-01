from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.ssh import SshFilesystem
from dissect.target.loaders.shell import ShellLoader, map_shell

if TYPE_CHECKING:
    from dissect.target.target import Target


class SshLoader(ShellLoader):
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
