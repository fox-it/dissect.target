from __future__ import annotations

from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target


class FreeBsdPlugin(BsdPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._os_release = self._parse_os_release("/bin/freebsd-version*")

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/net") or fs.exists("/.sujournal"):
                return fs

        return None

    @export(property=True)
    def version(self) -> Optional[str]:
        return self._os_release.get("USERLAND_VERSION")
