from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target


class RedHat(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        # also applicable to centos (which is a red hat derivative)
        for fs in target.filesystems:
            if fs.exists("/etc/sysconfig/network-scripts"):
                return fs

        return None
