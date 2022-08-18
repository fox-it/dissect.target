from __future__ import annotations

from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target


class OpenBsdPlugin(BsdPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._hostname_dict = self._parse_hostname_string(["/etc/myname"])

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/bsd") or fs.exists("/bsd.rd") or fs.exists("/bsd.mp") or fs.exists("/bsd.mp"):
                return fs

        return None

    @export(property=True)
    def version(self) -> Optional[str]:
        return None

    @export(property=True)
    def hostname(self) -> Optional[str]:
        return self._hostname_dict.get("hostname", None)
