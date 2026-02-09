from __future__ import annotations

from operator import itemgetter
from typing import TYPE_CHECKING

from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class VyosPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        self.target = target

        versions = []
        for d in self.target.fs.path("/boot").iterdir():
            if d.joinpath("live-rw").exists():
                versions.append((d.name, "live-rw"))
            elif d.joinpath("rw").exists():
                versions.append((d.name, "rw"))

        latest = sorted(versions, key=itemgetter(0))[0]
        self._version, rootpath = latest

        # VyOS does some additional magic with base system files
        layer = target.fs.append_layer()
        layer.map_file_entry("/", target.fs.root.get(f"/boot/{self._version}/{rootpath}"))
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            boot_dir = fs.path("/boot")

            if not boot_dir.is_dir():
                continue

            for d in boot_dir.iterdir():
                if not d.is_dir():
                    continue

                if d.joinpath("live-rw").exists() or d.joinpath("rw").exists():
                    return fs

        return None

    @export(property=True)
    def ips(self) -> list[str] | None:
        return None

    @export(property=True)
    def version(self) -> str:
        return self._version

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.VYOS.value
