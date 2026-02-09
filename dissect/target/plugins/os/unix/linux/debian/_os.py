from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class DebianPlugin(LinuxPlugin):
    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if fs.exists("/etc/network/interfaces") or fs.exists("/etc/debian_version") or fs.exists("/etc/dpkg/"):
                return fs

        return None
