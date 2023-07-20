from __future__ import annotations

import plistlib
from typing import Iterator, Optional

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target


class MacPlugin(BsdPlugin):
    VERSION = "/System/Library/CoreServices/SystemVersion.plist"
    GLOBAL = "/Library/Preferences/.GlobalPreferences.plist"
    SYSTEM = "/Library/Preferences/SystemConfiguration/preferences.plist"

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/Library") and fs.exists("/Applications"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> MacPlugin:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> Optional[str]:
        for path in ["/Library/Preferences/SystemConfiguration/preferences.plist"]:
            try:
                preferencesPlist = self.target.fs.open(path).read().rstrip()
                preferences = plistlib.loads(preferencesPlist)
                return preferences["System"]["System"]["ComputerName"]

            except FileNotFoundError:
                pass

    @export(property=True)
    def ips(self) -> Optional[list[str]]:
        raise NotImplementedError

    @export(property=True)
    def version(self) -> Optional[str]:
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

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        for path in self.target.fs.path("/var/db/dslocal/nodes/Default/users/").glob("*.plist"):
            user = plistlib.loads(path.read_bytes())

            # An user account can have multiply home directories
            for home_dir in user.get("home", []):
                yield UnixUserRecord(
                    name=user.get("name", [None])[0],
                    passwd=user.get("passwd", [None])[0],
                    uid=user.get("uid", [None])[0],
                    gid=user.get("gid", [None])[0],
                    gecos=user.get("realname", [None])[0],
                    home=home_dir,
                    shell=user.get("shell", [None])[0],
                    source=path,
                )

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.OSX.value
