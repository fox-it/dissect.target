from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


EtcFileRecord = TargetRecordDescriptor(
    "macos/etcfiles/entry",
    [
        ("string", "filename"),
        ("string", "line"),
        ("varint", "line_number"),
        ("path", "source"),
    ],
)


class MacOSEtcFilesPlugin(Plugin):
    """Plugin to read common /etc configuration files on macOS.

    Locations:
        /etc/hosts, /etc/resolv.conf, /etc/nfs.conf, /etc/fstab, /etc/exports
        /private/etc/hosts, /private/etc/resolv.conf, /private/etc/nfs.conf
    """

    __namespace__ = "etcfiles"

    PATHS = [
        "etc/hosts",
        "etc/resolv.conf",
        "etc/nfs.conf",
        "etc/fstab",
        "etc/exports",
        "private/etc/hosts",
        "private/etc/resolv.conf",
        "private/etc/nfs.conf",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._etc_paths = []
        seen = set()
        for p in self.PATHS:
            path = self.target.fs.path("/").joinpath(p)
            if path.exists() and path.name not in seen:
                seen.add(path.name)
                self._etc_paths.append(path)

    def check_compatible(self) -> None:
        if not self._etc_paths:
            raise UnsupportedPluginError("No etc configuration files found")

    @export(record=EtcFileRecord)
    def entries(self) -> Iterator[EtcFileRecord]:
        """Read common /etc configuration files as raw lines."""
        for etc_path in self._etc_paths:
            try:
                with etc_path.open("r") as fh:
                    for line_number, raw_line in enumerate(fh, start=1):
                        line = raw_line.strip()
                        if not line or line.startswith("#"):
                            continue
                        yield EtcFileRecord(
                            filename=etc_path.name,
                            line=line,
                            line_number=line_number,
                            source=etc_path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error reading etc file %s: %s", etc_path, e)
