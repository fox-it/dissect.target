from __future__ import annotations

from dissect.target.filesystem import Filesystem
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target


class RedHatPlugin(LinuxPlugin):
    """RedHat, CentOS and Fedora Plugin."""

    REDHAT_PATHS = {
        "/etc/centos-release",
        "/etc/fedora-release",
        "/etc/redhat-release",
        "/etc/sysconfig/network-scripts",  # legacy detection
    }

    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            for path in cls.REDHAT_PATHS:
                if fs.exists(path):
                    return fs
