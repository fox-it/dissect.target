from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target


class SuSEPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            # modern and old package managers of suse distros
            if len(list(fs.glob("/etc/*YaST*"))) > 0 or fs.exists("/etc/zypp"):
                return fs
