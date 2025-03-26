from __future__ import annotations

from dissect.target.filesystem import Filesystem
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target


class OpenBsdPlugin(BsdPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._hostname_dict = self._parse_hostname_string([("/etc/myname", None)])

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        BSD_PATHS = {
            "/bsd",
            "/bsd.rd",
            "/bsd.mp",
        }

        for fs in target.filesystems:
            for path in BSD_PATHS:
                if fs.exists(path):
                    return fs

    @export(property=True)
    def version(self) -> str | None:
        return None

    @export(property=True)
    def hostname(self) -> str | None:
        return self._hostname_dict.get("hostname", None)
