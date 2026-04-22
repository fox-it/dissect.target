from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugin import internal
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


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

    @internal
    def misc_user_paths(self) -> Iterator[tuple[str, tuple[str, str] | None]]:
        yield from super().misc_user_paths()

        if (user_path := self.target.fs.path("/Users")).exists():
            yield from ((entry, None) for entry in user_path.iterdir() if entry.is_dir())


def macho_cpu_type(paths: list[str | Path], fs: Filesystem | None = None) -> int | None:
    """Extract the Mach-O CPU type of a target by reading the Mach-O header of the supplied binar(y|ies).

    We could use Macho-O magic headers (``feedface``, ``feedfacf``, ``cafebabe``), but the Mach-O CPU type
    also contains bitness.

    Args:
        paths: List of strings or ``Path`` objects.
        fs: Optional filesystem to search the provided paths in. Required if ``paths`` is a list of strings.

    Returns:
        Mach-O CPU type integer.

    References:
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
                return int.from_bytes(fh.read(4), "big")  # Mach-O CPU type. Header is big endian
        except Exception:
            pass

    return None
