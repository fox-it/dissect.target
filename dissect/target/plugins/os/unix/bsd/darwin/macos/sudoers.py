from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SudoersRecord = TargetRecordDescriptor(
    "macos/sudoers/entries",
    [
        ("string", "rule"),
        ("path", "source"),
    ],
)


class MacOSSudoersPlugin(Plugin):
    """Plugin to parse sudoers configuration files on macOS.

    Locations:
        /etc/sudoers
        /private/etc/sudoers
        /etc/sudoers.d/*
        /private/etc/sudoers.d/*
    """

    __namespace__ = "sudoers"

    PATHS = [
        "etc/sudoers",
        "private/etc/sudoers",
    ]

    GLOBS = [
        "etc/sudoers.d/*",
        "private/etc/sudoers.d/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._sudoers_paths = []
        seen = set()
        root = self.target.fs.path("/")

        for p in self.PATHS:
            path = root.joinpath(p)
            if path.exists() and str(path) not in seen:
                seen.add(str(path))
                self._sudoers_paths.append(path)

        for pattern in self.GLOBS:
            for path in root.glob(pattern):
                if str(path) not in seen:
                    seen.add(str(path))
                    self._sudoers_paths.append(path)

    def check_compatible(self) -> None:
        if not self._sudoers_paths:
            raise UnsupportedPluginError("No sudoers files found")

    @export(record=SudoersRecord)
    def entries(self) -> Iterator[SudoersRecord]:
        """Parse sudoers configuration entries."""
        for path in self._sudoers_paths:
            try:
                with path.open("r") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        yield SudoersRecord(
                            rule=line,
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing sudoers file %s: %s", path, e)
