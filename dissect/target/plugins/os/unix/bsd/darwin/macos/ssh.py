from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


KnownHostsRecord = TargetRecordDescriptor(
    "macos/ssh/known_hosts",
    [
        ("string", "host"),
        ("string", "key_type"),
        ("string", "key_data"),
        ("path", "source"),
    ],
)

SSHConfigRecord = TargetRecordDescriptor(
    "macos/ssh/config",
    [
        ("string", "host"),
        ("string", "setting"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class SSHPlugin(Plugin):
    """Plugin to parse macOS SSH configuration and known hosts.

    Parses:
    - ~/.ssh/known_hosts — previously connected hosts
    - ~/.ssh/config, /etc/ssh/ssh_config — SSH client configuration
    - ~/.ssh/authorized_keys — keys authorized for login
    """

    __namespace__ = "ssh"

    KNOWN_HOSTS_GLOBS = [
        "Users/*/.ssh/known_hosts",
        "Users/*/%2Essh/known_hosts",
    ]

    CONFIG_GLOBS = [
        "Users/*/.ssh/config",
        "Users/*/%2Essh/config",
        "etc/ssh/ssh_config",
        "private/etc/ssh/ssh_config",
    ]

    AUTHORIZED_KEYS_GLOBS = [
        "Users/*/.ssh/authorized_keys",
        "Users/*/%2Essh/authorized_keys",
    ]

    def __init__(self, target):
        super().__init__(target)
        root = self.target.fs.path("/")

        self._known_hosts_paths = []
        for pattern in self.KNOWN_HOSTS_GLOBS:
            self._known_hosts_paths.extend(root.glob(pattern))

        self._config_paths = []
        for pattern in self.CONFIG_GLOBS:
            self._config_paths.extend(root.glob(pattern))

        self._authorized_keys_paths = []
        for pattern in self.AUTHORIZED_KEYS_GLOBS:
            self._authorized_keys_paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._known_hosts_paths and not self._config_paths and not self._authorized_keys_paths:
            raise UnsupportedPluginError("No SSH files found")

    @export(record=KnownHostsRecord)
    def known_hosts(self) -> Iterator[KnownHostsRecord]:
        """Parse SSH known_hosts files for previously connected hosts."""
        for path in self._known_hosts_paths:
            try:
                with path.open("r", errors="replace") as fh:
                    content = fh.read()
            except Exception as e:
                self.target.log.warning("Error reading %s: %s", path, e)
                continue

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(None, 2)
                if len(parts) >= 3:
                    yield KnownHostsRecord(
                        host=parts[0],
                        key_type=parts[1],
                        key_data=parts[2],
                        source=path,
                        _target=self.target,
                    )
                elif len(parts) == 2:
                    yield KnownHostsRecord(
                        host=parts[0],
                        key_type=parts[1],
                        key_data="",
                        source=path,
                        _target=self.target,
                    )

        # Also parse authorized_keys (same format: key_type key_data comment)
        for path in self._authorized_keys_paths:
            try:
                with path.open("r", errors="replace") as fh:
                    content = fh.read()
            except Exception as e:
                self.target.log.warning("Error reading %s: %s", path, e)
                continue

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(None, 2)
                if len(parts) >= 2:
                    yield KnownHostsRecord(
                        host=parts[2] if len(parts) >= 3 else "",
                        key_type=parts[0],
                        key_data=parts[1],
                        source=path,
                        _target=self.target,
                    )

    @export(record=SSHConfigRecord)
    def config(self) -> Iterator[SSHConfigRecord]:
        """Parse SSH config files and extract Host blocks with their settings."""
        for path in self._config_paths:
            try:
                with path.open("r", errors="replace") as fh:
                    content = fh.read()
            except Exception as e:
                self.target.log.warning("Error reading %s: %s", path, e)
                continue

            current_host = "*"

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Split on first whitespace or '='
                if "=" in line and (" " not in line or line.index("=") < line.index(" ")):
                    key, _, value = line.partition("=")
                else:
                    key, _, value = line.partition(" ")

                key = key.strip()
                value = value.strip()

                if not key:
                    continue

                if key.lower() == "host":
                    current_host = value
                    continue

                if key.lower() == "match":
                    current_host = f"Match {value}"
                    continue

                yield SSHConfigRecord(
                    host=current_host,
                    setting=key,
                    value=value,
                    source=path,
                    _target=self.target,
                )
