from __future__ import annotations

import struct
from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.bsd.darwin._os import (
    CPU_TYPE_ARM64,
    FAT_MAGIC,
    cpu_types_from_macho,
    macho_cpu_type,
    select_cpu_type,
)

CPU_TYPE_X86_64 = 0x01000007


def fat_binary(*cpu_types: int) -> bytes:
    """Build a fat binary header with one architecture entry per CPU type."""
    data = struct.pack(">II", FAT_MAGIC, len(cpu_types))
    for cpu_type in cpu_types:
        data += struct.pack(">IIIII", cpu_type, 0, 4096, 512, 12)
    return data


def test_cpu_types_from_fat_binary() -> None:
    assert cpu_types_from_macho(fat_binary(CPU_TYPE_X86_64, CPU_TYPE_ARM64)) == [CPU_TYPE_X86_64, CPU_TYPE_ARM64]


def test_cpu_types_from_thin_binary() -> None:
    assert cpu_types_from_macho(b"\xcf\xfa\xed\xfe" + struct.pack("<I", CPU_TYPE_X86_64)) == [CPU_TYPE_X86_64]


def test_select_cpu_type_prefers_arm64() -> None:
    assert select_cpu_type([CPU_TYPE_X86_64, CPU_TYPE_ARM64]) == CPU_TYPE_ARM64
    assert select_cpu_type([CPU_TYPE_X86_64]) == CPU_TYPE_X86_64
    assert select_cpu_type([]) is None


def test_macho_cpu_type_fat_binary() -> None:
    fs = VirtualFilesystem()
    fs.map_file_fh("/bin/universal", BytesIO(fat_binary(CPU_TYPE_X86_64, CPU_TYPE_ARM64)))

    assert macho_cpu_type(["/bin/universal"], fs=fs) == CPU_TYPE_ARM64
