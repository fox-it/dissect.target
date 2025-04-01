import plistlib
from dataclasses import dataclass
from pathlib import Path

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target

# https://en.wikipedia.org/wiki/Mach-O
ARCH_MAP = {
    b"\x0c\x00\x00\x01": "arm64",  # big endian, x64
    b"\x01\x00\x00\x0c": "arm64",  # little endian, x64
    b"\x0c\x00\x00\x00": "arm32",  # big endian, x32
    b"\x00\x00\x00\x0c": "arm32",  # little endian, x32
}


class IOSPlugin(BsdPlugin):
    """Apple iOS plugin.

    Resources:
        - https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html
        - https://corp.digitalcorpora.org/corpora/mobile/iOS17/
    """  # noqa: E501

    SYSTEM = "/private/var/preferences/SystemConfiguration/preferences.plist"
    GLOBAL = "/private/var/mobile/Library/Preferences/.GlobalPreferences.plist"
    VERSION = "/System/Library/CoreServices/SystemVersion.plist"

    def __init__(self, target: Target):
        super().__init__(target)

        self._config = Config(
            target.fs.path(self.SYSTEM),
            target.fs.path(self.GLOBAL),
            target.fs.path(self.VERSION),
        )

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if fs.exists("/private/var/preferences"):
                return fs

    @classmethod
    def create(cls, target: Target, sysvol: VirtualFilesystem) -> None:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        try:
            # ComputerName can contain invalid utf characters
            return self._config.SYSTEM["System"]["System"]["HostName"]
        except KeyError:
            pass

    @export(property=True)
    def ips(self) -> list:
        return []

    @export(property=True)
    def version(self) -> str:
        return f'{self._config.VERSION["ProductName"]} {self._config.VERSION["ProductVersion"]} ({self._config.VERSION["ProductBuildVersion"]})'  # noqa: E501

    # /private/etc/master.passwd is a copy of /private/etc/passwd
    PASSWD_FILES = ["/private/etc/passwd"]

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.IOS.value

    @export(property=True)
    def architecture(self) -> str | None:
        return detect_macho_arch(["/bin/df", "/bin/ps", "/sbin/fsck", "/sbin/mount"], suffix="ios", fs=self.target.fs)


def detect_macho_arch(paths: list[str | Path], suffix: str, fs: Filesystem | None = None) -> str | None:
    """Detect the architecture of the system by reading the Mach-O headers of the provided binaries.

    We could use the mach-o magic headers (feedface, feedfacf, cafebabe), but the mach-o cpu type
    also contains bitness.

    Args:
        paths: List of strings or ``Path`` objects.
        suffix: String to append to returned architecture, e.g. providing ``suffix`` returns ``arm64-suffix``.
        fs: Optional filesystem to search the provided paths in. Required if ``paths`` is a list of strings.

    Returns:
        Detected architecture or ``None``.

    Resources:
        - https://github.com/opensource-apple/cctools/blob/master/include/mach/machine.h
    """
    for path in paths:
        if isinstance(path, str):
            if not fs:
                raise ValueError("Provided string paths but no filesystem!")
            path = fs.path(path)

        if not path.is_file():
            continue

        try:
            with path.open("rb") as fh:
                fh.seek(4)
                arch = ARCH_MAP.get(fh.read(4))  # mach-o cpu type
                return f"{arch}-{suffix}"
        except Exception:
            pass


@dataclass
class Config:
    SYSTEM: dict
    GLOBAL: dict
    VERSION: dict

    def __post_init__(self):
        for field in self.__dataclass_fields__.keys():
            path = getattr(self, field)
            if path.is_file():
                setattr(self, field, plistlib.load(path.open("rb")))
