from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import Filesystem
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class OpenBsdPlugin(BsdPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._hostname, self._domain = self._parse_hostname_string([("/etc/myname", None)])

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        OPENBSD_PATHS = {
            "/bsd",
            "/bsd.rd",
            "/bsd.mp",
        }

        for fs in target.filesystems:
            if any(fs.exists(path) for path in OPENBSD_PATHS):
                return fs
        return None

    @export(property=True)
    def version(self) -> str | None:
        return None

    @export(property=True)
    def hostname(self) -> str | None:
        return self._hostname

    @export(property=True)
    def domain(self) -> str | None:
        return self._domain
