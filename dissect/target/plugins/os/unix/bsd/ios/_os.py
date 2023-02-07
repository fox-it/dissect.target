import plistlib

from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin


class IOSPlugin(BsdPlugin):
    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/private/var/preferences"):
                return fs

        return None

    @classmethod
    def create(cls, target, sysvol):
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self):
        path = self.target.fs.path("/private/var/preferences/SystemConfiguration/preferences.plist")

        if not path.exists():
            return None

        preferences = plistlib.load(path.open())
        return preferences["System"]["System"]["ComputerName"]

    @export(property=True)
    def ips(self):
        raise NotImplementedError

    @export(property=True)
    def version(self):
        raise NotImplementedError

    @export(property=True)
    def users(self):
        raise NotImplementedError

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.IOS.value
