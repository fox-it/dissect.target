from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

OSXShadowRecord = TargetRecordDescriptor(
    "osx/shadow",
    [
        ("string", "name"),
        ("string", "hash"),
        ("string", "salt"),
        ("varint", "iterations"),
        ("string", "algorithm"),
        ("path", "source"),
    ],
)


class ShadowPlugin(Plugin):
    """Unix shadow passwords plugin."""

    USER_FILE_GLOB = "/var/db/dslocal/nodes/Default/users/*.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.user_files = set()
        self._resolve_files()

    def check_compatible(self) -> None:
        if not self.user_files:
            raise UnsupportedPluginError("No shadow files found")

    def _resolve_files(self) -> None:
        for file in self.target.fs.glob(self.USER_FILE_GLOB):
            self.user_files.add(file)

    @export(record=OSXShadowRecord)
    def passwords(self) -> Iterator[OSXShadowRecord]:
        """Yield shadow records from OS X user plist files."""
        for path in self.user_files:
            path = self.target.fs.path(path)
            user = plistlib.load(path.open())
            if user.get("ShadowHashData") is None:
                continue

            shadow = plistlib.loads(user["ShadowHashData"][0])
            username = user["name"][0]

            for key in shadow:
                if shadow[key].get("entropy") is None:
                    continue

                hash = shadow[key]["entropy"].hex()
                salt = shadow[key]["salt"].hex()
                iterations = shadow[key]["iterations"]

                yield OSXShadowRecord(
                    name=username,
                    hash=hash,
                    salt=salt,
                    iterations=iterations,
                    algorithm=key,
                    source=path,
                    _target=self.target,
                )
