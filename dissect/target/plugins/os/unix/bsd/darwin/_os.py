from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugin import internal
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE

FAT_ARCH_SIZE = 20
FAT_ARCH_64_SIZE = 32

CPU_TYPE_ARM64 = 0x0100000C

# A fat header entry is 32 bytes, so this covers a reasonable number of slices
MACHO_HEADER_SIZE = 1024


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


def cpu_types_from_macho(data: bytes) -> list[int]:
    """Extract all Mach-O CPU types from a Mach-O or fat binary header.

    A fat binary holds one architecture entry per contained slice, a thin binary only has its own CPU type.

    Args:
        data: The start of the binary, at least the size of a fat header entry.

    Returns:
        The CPU types found in the header, in the order they appear.
    """
    if len(data) < 8:
        return []

    # Fat headers are always big endian, thin headers are in the endianness of their target
    magic = int.from_bytes(data[:4], "big")

    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        arch_size = FAT_ARCH_64_SIZE if magic == FAT_MAGIC_64 else FAT_ARCH_SIZE
        cpu_types = []

        for offset in range(8, 8 + int.from_bytes(data[4:8], "big") * arch_size, arch_size):
            if len(data) < offset + 4:
                break
            cpu_types.append(int.from_bytes(data[offset : offset + 4], "big"))

        return cpu_types

    if magic in (MH_MAGIC, MH_MAGIC_64):
        return [int.from_bytes(data[4:8], "big")]

    if magic in (MH_CIGAM, MH_CIGAM_64):
        return [int.from_bytes(data[4:8], "little")]

    return []


def select_cpu_type(cpu_types: list[int]) -> int | None:
    """Select the CPU type that best describes the target from the slices of a fat binary.

    Prefer ``arm64`` so that Apple silicon targets are not reported as Intel based on the first slice.
    """
    if CPU_TYPE_ARM64 in cpu_types:
        return CPU_TYPE_ARM64

    return cpu_types[0] if cpu_types else None


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
                if cpu_type := select_cpu_type(cpu_types_from_macho(fh.read(MACHO_HEADER_SIZE))):
                    return cpu_type
        except Exception:
            pass

    return None
