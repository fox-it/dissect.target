from __future__ import annotations

from pathlib import Path
import plistlib
from dataclasses import dataclass
from typing import Any, Iterator

from dissect.target.filesystem import Filesystem, VirtualFilesystem
from dissect.target.helpers.record import IOSUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd.darwin._os import (
    DarwinPlugin,
    detect_macho_arch,
)
from dissect.target.target import Target


class IOSPlugin(DarwinPlugin):
    """Apple iOS plugin.

    Resources:
        - https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html
        - https://corp.digitalcorpora.org/corpora/mobile/iOS17/
    """  # noqa: E501

    SYSTEM = "/private/var/preferences/SystemConfiguration/preferences.plist"
    GLOBAL = "/private/var/mobile/Library/Preferences/.GlobalPreferences.plist"
    VERSION = "/System/Library/CoreServices/SystemVersion.plist"

    # /private/etc/master.passwd is a copy of /private/etc/passwd
    PASSWD_FILES = ["/private/etc/passwd"]

    def __init__(self, target: Target):
        super().__init__(target)

        self._config = Config.load(
            target.fs.path(self.SYSTEM),
            target.fs.path(self.GLOBAL),
            target.fs.path(self.VERSION),
        )

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if fs.exists("/private/var/preferences") and fs.exists("/private/var/mobile"):
                return fs

    @classmethod
    def create(cls, target: Target, sysvol: VirtualFilesystem) -> None:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        try:
            # ComputerName can contain invalid utf characters, so we use HostName instead.
            return self._config.SYSTEM["System"]["System"]["HostName"]
        except KeyError:
            pass

    @export(property=True)
    def ips(self) -> list:
        return []

    @export(property=True)
    def version(self) -> str:
        return f'{self._config.VERSION["ProductName"]} {self._config.VERSION["ProductVersion"]} ({self._config.VERSION["ProductBuildVersion"]})'  # noqa: E501

    @export(record=IOSUserRecord)
    def users(self) -> Iterator[IOSUserRecord]:
        for user in super().users():
            yield IOSUserRecord(**user._asdict())

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.IOS.value

    @export(property=True)
    def architecture(self) -> str | None:
        if arch := detect_macho_arch(["/bin/df", "/bin/ps", "/sbin/fsck", "/sbin/mount"], fs=self.target.fs):
            return f"{arch}-ios"


@dataclass
class Config:
    SYSTEM: dict[str, Any]
    GLOBAL: dict[str, Any]
    VERSION: dict[str, Any]

    @classmethod
    def load(cls, *args: list[Path]) -> Config:
        plists = []
        for path in args:
            if path.is_file():
                plists.append(plistlib.load(path.open("rb")))
            else:
                plists.append({})
        return cls(*plists)
