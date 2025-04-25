from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.bsd._os import BsdPlugin

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

# https://en.wikipedia.org/wiki/Mach-O
ARCH_MAP = {
    b"\x0c\x00\x00\x01": "arm64",  # big endian, x64
    b"\x01\x00\x00\x0c": "arm64",  # little endian, x64
    b"\x0c\x00\x00\x00": "arm32",  # big endian, x32
    b"\x00\x00\x00\x0c": "arm32",  # little endian, x32
}


class DarwinPlugin(BsdPlugin):
    """Darwin plugin."""

    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if (fs.exists("/Library") and fs.exists("/Applications")) or fs.exists("/private/var/mobile"):
                return fs
        return None


def detect_macho_arch(paths: list[str | Path], fs: Filesystem | None = None) -> str | None:
    """Detect the architecture of the system by reading the Mach-O headers of the provided binaries.

    We could use the mach-o magic headers (feedface, feedfacf, cafebabe), but the mach-o cpu type
    also contains bitness.

    Args:
        paths: List of strings or ``Path`` objects.
        fs: Optional filesystem to search the provided paths in. Required if ``paths`` is a list of strings.

    Returns:
        Detected architecture (e.g. ``arm64``) or ``None``.

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
                return ARCH_MAP.get(fh.read(4))  # mach-o cpu type
        except Exception:
            pass

    return None
