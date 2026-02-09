from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugin import export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class FreeBsdPlugin(BsdPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._os_release = self._parse_os_release("/bin/freebsd-version*")

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        FREEBSD_PATHS = {
            "/.sujournal",
            "/entropy",
            "/bin/freebsd-version",
        }

        for fs in target.filesystems:
            if fs.exists("/net") and any(fs.exists(path) for path in FREEBSD_PATHS):
                return fs
        return None

    @export(property=True)
    def version(self) -> str | None:
        return self._os_release.get("USERLAND_VERSION")
