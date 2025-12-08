from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, TypeAlias

from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers.magic import mimetypes

MagicSignature: TypeAlias = tuple[str, str, bytes]
MagicResult: TypeAlias = str | None


class Magic:
    """Magic is a helper class for identifying files to a file type by magic bytes.

    This class mimics ``python-magic`` behaviour, however this implementation does
    not depend on the ``libmagic`` C-library system package. Instead a precompiled
    XML document of FreeDesktop's shared-mime-info project is used to identify files.

    Falls back to file extensions (where applicable) if no magic header is detected
    in the provided buffer.

    The underlying implementation currently does not support nested magic definitions
    and logical AND/OR matches, which somewhat limits the supported FreeDesktop XML
    magic signature set.

    .. code-block:: python

        from dissect.target.helpers import magic

        >>> magic.from_buffer(b"SQLite format 3\x00FILE DATA\x4d\x3c\xb2\xa1")
        "SQLite3 database"

        >>> magic.from_file(target.fs.path("file.jpg"), mime=True)
        "image/jpg"

    Currently does not implement ``python-magic`` :class:`Magic` invocation behaviour.

    Resources:
        - https://github.com/ahupp/python-magic/blob/master/magic/__init__.py
        - https://github.com/file/file/tree/master/magic
        - https://freedesktop.org/wiki/Specifications/shared-mime-info-spec/
        - https://gitlab.freedesktop.org/xdg/shared-mime-info/-/blob/master/data/freedesktop.org.xml.in
    """

    @staticmethod
    def detect(buf: bytes | BinaryIO, suffix: str | None = None, *, mime: bool = False) -> MagicResult:
        """Searches ``mimetypes.MAP`` for the given bytes."""

        is_buffer = hasattr(buf, "read") and hasattr(buf, "seek")
        res_attr = "type" if mime else "name"

        if suffix is not None and not isinstance(suffix, str):
            raise TypeError("Provided suffix is not a string")

        for index, offset, magic in mimetypes.MAP:
            try:
                if is_buffer:
                    buf.seek(offset)
                    if buf.read(len(magic)) == magic:
                        return mimetypes.TYPES[index][res_attr]
                else:
                    if buf[offset : offset + len(magic)] == magic:
                        return mimetypes.TYPES[index][res_attr]

            except EOFError:  # noqa: PERF203
                continue

        if suffix:
            for index, patterns in mimetypes.PATTERNS:
                if suffix.endswith(patterns):
                    return mimetypes.TYPES[index][res_attr]

        return None


def from_file(path: Path, *, mime: bool = False) -> MagicResult:
    """Detect file type from a :class:`Path` instance."""

    if not isinstance(path, Path):
        raise TypeError("Provided path is not a Path instance")

    return from_descriptor(path.open("rb"), path.suffix, mime=mime)


def from_entry(entry: FilesystemEntry, *, mime: bool = False) -> MagicResult:
    """Detect file type from a :class:`FilesystemEntry` instance."""

    if not isinstance(entry, FilesystemEntry):
        raise TypeError("Provided entry is not a FilesystemEntry instance")

    return from_descriptor(entry.open(), Path(entry.name).suffix, mime=mime)


def from_descriptor(fh: BinaryIO, suffix: str | None = None, *, mime: bool = False) -> MagicResult:
    """Detect file type from a file descriptor or handle."""

    if not hasattr(fh, "read") or not hasattr(fh, "seek"):
        raise TypeError("Provided fh does not have a read or seek method")

    return from_buffer(fh, suffix, mime=mime)


# Convenience alias, not present in python-magic.
from_fh = from_descriptor


def from_buffer(buf: bytes | BinaryIO, suffix: str | None = None, *, mime: bool = False) -> MagicResult:
    """Detect file type from provided bytes or buffer of bytes."""

    if not isinstance(buf, bytes) and not hasattr(buf, "read"):
        raise TypeError("Provided buf is not bytes or a buffer")

    return Magic().detect(buf, suffix, mime=mime)
