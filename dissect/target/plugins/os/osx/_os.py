import plistlib

from dissect.target.plugin import OSPlugin, export


class MacPlugin(OSPlugin):
    VERSION = "/System/Library/CoreServices/SystemVersion.plist"
    GLOBAL = "/Library/Preferences/.GlobalPreferences.plist"
    SYSTEM = "/Library/Preferences/SystemConfiguration/preferences.plist"

    def __init__(self, target):
        super().__init__(target)
        self.target = target

    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/Library") and fs.exists("/Applications"):
                return fs

        return None

    @classmethod
    def create(cls, target, sysvol):
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self):
        for path in ["/Library/Preferences/SystemConfiguration/preferences.plist"]:
            try:
                preferencesPlist = self.target.fs.open(path).read().rstrip()
                preferences = plistlib.loads(preferencesPlist)
                return preferences["System"]["System"]["ComputerName"]

            except FileNotFoundError:
                pass

    @export(property=True)
    def ips(self):
        raise NotImplementedError

    @export(property=True)
    def version(self):
        for path in ["/System/Library/CoreServices/SystemVersion.plist"]:
            try:
                systemVersionPlist = self.target.fs.open(path).read().rstrip()
                systemVersion = plistlib.loads(systemVersionPlist)
                productName = systemVersion["ProductName"]
                productUserVisibleVersion = systemVersion["ProductUserVisibleVersion"]
                productBuildVersion = systemVersion["ProductBuildVersion"]
                return f"{productName} {productUserVisibleVersion} ({productBuildVersion})"
            except FileNotFoundError:
                pass

    @export(property=True)
    def users(self):
        raise NotImplementedError

    @export(property=True)
    def os(self):
        return "osx"
