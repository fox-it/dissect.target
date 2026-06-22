from __future__ import annotations

from typing import BinaryIO
from xml.etree.ElementTree import ElementTree

from defusedxml import ElementTree as ET

from dissect.target.plugins.os.unix.linux.android.util.abx import AbxFile


def read_android_xml(fh: BinaryIO) -> ElementTree:
    """Convert a readable stream of bytes which might be plaintext XML or ABX to an ElementTree."""
    offset = fh.tell()
    magic = fh.read(4)
    fh.seek(offset)

    if magic == b"ABX\x00":
        return AbxFile(None, fh).tree

    if magic == b"<?xm":
        return ElementTree(ET.fromstring(fh.read().decode()))

    raise ValueError(f"Unexpected magic {magic!r}")
