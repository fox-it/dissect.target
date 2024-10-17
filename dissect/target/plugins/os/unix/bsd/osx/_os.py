from __future__ import annotations

import plistlib
from typing import Iterator, Optional

from flow.record.fieldtypes import posix_path

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
        try:
            preferences = plistlib.load(self.target.fs.path(self.SYSTEM).open())
            return preferences["System"]["System"]["ComputerName"]

        except FileNotFoundError:
            pass

    @export(property=True)
    def ips(self) -> Optional[list[str]]:
        return list(set(map(str, self.target.network.ips())))

    @export(property=True)
    def version(self) -> Optional[str]:
        try:
            systemVersion = plistlib.load(self.target.fs.path(self.VERSION).open())
            productName = systemVersion["ProductName"]
            productUserVisibleVersion = systemVersion["ProductUserVisibleVersion"]
            productBuildVersion = systemVersion["ProductBuildVersion"]
            return f"{productName} {productUserVisibleVersion} ({productBuildVersion})"
        except FileNotFoundError:
            pass

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        try:
            for path in self.target.fs.path("/var/db/dslocal/nodes/Default/users/").glob("*.plist"):
                user = plistlib.load(path.open())

                # The home directory of a user account can be null,
                # but a user account can also have multiply home directories e.g. the root account.
                # https://developer.apple.com/documentation/foundation/filemanager/1642853-homedirectory/
                for home_dir in user.get("home", [None]):
                    yield UnixUserRecord(
                        name=user.get("name", [None])[0],
                        passwd=user.get("passwd", [None])[0],
                        uid=user.get("uid", [None])[0],
                        gid=user.get("gid", [None])[0],
                        gecos=user.get("realname", [None])[0],
                        home=posix_path(home_dir) if home_dir else None,
                        shell=user.get("shell", [None])[0],
                        source=path,
                    )
        except FileNotFoundError:
            pass

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.OSX.value

    @export(property=True)
    def architecture(self) -> Optional[str]:
        # OS-X uses Mach-O binary format. We should implement something similar
        # to the Unix architecture() function but for Mach-O libraries.
        pass
