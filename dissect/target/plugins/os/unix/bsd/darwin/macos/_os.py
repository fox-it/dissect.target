from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from flow.record.fieldtypes import posix_path

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import MacOSUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd.darwin._os import (
    DarwinPlugin,
    detect_macho_arch,
)
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class MacOSPlugin(DarwinPlugin):
    VERSION = "/System/Library/CoreServices/SystemVersion.plist"
    GLOBAL = "/Library/Preferences/.GlobalPreferences.plist"
    SYSTEM = "/Library/Preferences/SystemConfiguration/preferences.plist"

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if fs.exists("/Library") and fs.exists("/Applications") and not fs.exists("/private/var/mobile"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        try:
            preferences = plistlib.load(self.target.fs.path(self.SYSTEM).open())
            return preferences["System"]["System"]["ComputerName"]

        except FileNotFoundError:
            pass

    @export(property=True)
    def ips(self) -> list[str] | None:
        return list(set(map(str, self.target.network.ips())))

    @export(property=True)
    def version(self) -> str | None:
        try:
            systemVersion = plistlib.load(self.target.fs.path(self.VERSION).open())
        except FileNotFoundError:
            pass
        else:
            productName = systemVersion["ProductName"]
            productUserVisibleVersion = systemVersion["ProductUserVisibleVersion"]
            productBuildVersion = systemVersion["ProductBuildVersion"]
            return f"{productName} {productUserVisibleVersion} ({productBuildVersion})"

    @export(record=MacOSUserRecord)
    def users(self) -> Iterator[MacOSUserRecord]:
        try:
            for path in self.target.fs.path("/var/db/dslocal/nodes/Default/users/").glob("*.plist"):
                user = plistlib.load(path.open())

                # The home directory of a user account can be null,
                # but a user account can also have multiply home directories e.g. the root account.
                # https://developer.apple.com/documentation/foundation/filemanager/1642853-homedirectory/
                for home_dir in user.get("home", [None]):
                    yield MacOSUserRecord(
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
        return OperatingSystem.MACOS.value

    @export(property=True)
    def architecture(self) -> str | None:
        if arch := detect_macho_arch(
            paths=[
                "/bin/bash",
                "/bin/sh",
                "/bin/cp",
                "/bin/ls",
                "/bin/ps",
            ],
            fs=self.target.fs,
        ):
            return f"{arch}-macos"
        return None
