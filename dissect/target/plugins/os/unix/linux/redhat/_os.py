from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugin import export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class RedHatPlugin(LinuxPlugin):
    """RedHat, CentOS and Fedora Plugin."""

    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        REDHAT_PATHS = {
            "/etc/centos-release",
            "/etc/fedora-release",
            "/etc/redhat-release",
            "/etc/sysconfig/network-scripts",  # legacy detection
        }

        for fs in target.filesystems:
            for path in REDHAT_PATHS:
                if fs.exists(path):
                    return fs
        return None

    @export(property=True)
    def architecture(self) -> str | None:
        """Return architecture this RHEL distribution runs on."""

        for path in ["/usr/bin/coreutils", "/bin/sh", "/bin/bash"]:
            if (bin := self.target.fs.path(path)).exists():
                return self._get_architecture(path=bin)
        return None
