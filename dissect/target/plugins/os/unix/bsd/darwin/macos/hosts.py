from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


HostFileRecord = TargetRecordDescriptor(
    "macos/hostfile/entry",
    [
        ("string", "ip"),
        ("string", "hostnames"),
        ("path", "source"),
    ],
)


class MacOSHostFilePlugin(Plugin):
    """Plugin to parse /etc/hosts entries on macOS.

    Locations:
        /etc/hosts
        /private/etc/hosts
    """

    __namespace__ = "hostfile"

    PATHS = [
        "etc/hosts",
        "private/etc/hosts",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._host_paths = []
        seen = set()
        for p in self.PATHS:
            path = self.target.fs.path("/").joinpath(p)
            if path.exists() and path.name not in seen:
                seen.add(path.name)
                self._host_paths.append(path)

    def check_compatible(self) -> None:
        if not self._host_paths:
            raise UnsupportedPluginError("No hosts files found")

    @export(record=HostFileRecord)
    def entries(self) -> Iterator[HostFileRecord]:
        """Parse /etc/hosts entries."""
        for host_path in self._host_paths:
            try:
                with host_path.open("r") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) < 2:
                            continue
                        yield HostFileRecord(
                            ip=parts[0],
                            hostnames=parts[1],
                            source=host_path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing hosts file %s: %s", host_path, e)
