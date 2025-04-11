from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import Filesystem
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix._os import UnixPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class BsdPlugin(UnixPlugin):
    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            # checking the existence of /var/authpf for free- and openbsd
            # checking the existence of /var/at for net- and freebsd
            if fs.exists("/usr/obj") or fs.exists("/altroot") or fs.exists("/etc/pf.conf"):
                return fs

        return None

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.BSD.value

    @export(property=True)
    def hostname(self) -> str | None:
        fh = self.target.fs.path("/etc/rc.conf")

        for line in fh.open("rt").readlines():
            if line.startswith("hostname"):
                return line.rstrip().split("=", maxsplit=1)[1].replace('"', "")
        return None

    @export(property=True)
    def ips(self) -> list[str] | None:
        self.target.log.error("ips plugin not implemented for %s", self.__class__)
        return None
