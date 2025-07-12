from __future__ import annotations

import bz2
import dataclasses
import io
import logging
import struct
from enum import IntEnum
from functools import lru_cache
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct import BaseType, cstruct
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

BZIP_HEADER = b"BZh9"
FILE_MAGIC = b"ESDb"
COMPAT_1 = (1, 7, 9)

log = logging.getLogger(__name__)


class EverythingVarInt(int, BaseType):
    @classmethod
    def _read(cls, stream: BinaryIO, context: dict[str, Any] | None = None) -> int:
        return read_varint(stream)

    @classmethod
    def _write(cls, stream: BinaryIO, data: int) -> int:
        return stream.write(write_varint(data))


c_header_def = """
flag EntryAttributes : uint32_t {
    has_file_size = 1,
    has_date_created = 2,
    has_date_modified = 4,
    has_date_accessed = 8,
    has_attributes = 16,
    has_folder_size = 32
};

struct everything_db_header {
    // Note - File header may be equal to `BZIP_HEADER`. In this case, file must be handled as a bzip compressed file
    char magic[4];

    // Version
    uint16_t version_patch;
    uint8_t version_minor;
    uint8_t version_major;

    // Flags
    EntryAttributes   entry_attributes;

    uint32_t number_of_folders;
    uint32_t number_of_files;
    EverythingVarInt number_of_filesystems;

};
"""
c_header = cstruct()
c_header.add_custom_type("EverythingVarInt", EverythingVarInt)
c_header.load(c_header_def)


def version_match(stmt: str, cond: bool) -> str:
    """Used for easy filtering of version constraints in cstruct definitions"""
    return stmt if cond else ""


@lru_cache
def filesystems_cstruct(version: tuple[int, int, int]) -> cstruct:
    c_filesystems_def = f"""
    struct EverythingVarBytes {{
        EverythingVarInt len;
        char data[len];
    }};

    struct filesystem_header {{
        EverythingVarInt type;
        {version_match("uint8_t out_of_date;", version >= COMPAT_1)}
    }};
    struct ntfs_header {{
        // Guid in format \\\\?\\Volume{{GUID}}
        EverythingVarBytes guid;
        // Disk drive (C:, D:)
        EverythingVarBytes path;
        EverythingVarBytes root;
        {version_match("EverythingVarBytes include_only;", version >= COMPAT_1)}
        {version_match("uint64_t journal_id;", version >= COMPAT_1)}
        {version_match("uint64_t next_usn;", version >= COMPAT_1)}
    }};

    struct efu_header {{
        // Path to file on disk containing EFU
        EverythingVarBytes source_path;
        {version_match("uint64_t unk1;", version >= COMPAT_1)}
    }};

    struct folder_header {{
        // Subfolder being indexed
        EverythingVarBytes path;
        // Next time to update folder
        {version_match("uint64_t next_update_time;", version >= COMPAT_1)}
    }};

    struct refs_header {{
        // Guid in format \\\\?\\Volume{{GUID}}
        EverythingVarBytes guid;
        // Disk drive (C:, D:)
        EverythingVarBytes path;
        EverythingVarBytes root;
        {version_match("EverythingVarBytes include_only;", version >= COMPAT_1)}
        {version_match("uint64_t journal_id;", version >= COMPAT_1)}
        {version_match("uint64_t next_usn;", version >= COMPAT_1)}
    }};
    """
    c_filesystems = cstruct()
    c_filesystems.add_custom_type("EverythingVarInt", EverythingVarInt)
    c_filesystems.load(c_filesystems_def)

    return c_filesystems


class EverythingFSType(IntEnum):
    NTFS = 0
    EFU = 1
    FOLDER = 2
    REFS = 3
    # TODO - Add FAT support (Only in Everything 1.5 which is still in alpha)


@dataclasses.dataclass
class Record:
    file_path: str
    size: int
    date_created: datetime | None
    date_modified: datetime | None
    date_accessed: datetime | None
    attributes: int | None
    file_type: str


class EverythingIndexObj:
    def __init__(self):
        # This is the index of filesystem_list
        self.fs_index: int | None = None
        # Path to file (Only basename)
        self.file_path = None
        # Anything not explicitly set with parent index has an fs_index
        self.parent_index = None
        self.size = None
        self.date_created = None
        self.date_modified = None
        self.date_accessed = None
        self.attributes = None

    def resolve_path(self, folder_list: list) -> str:
        if self.parent_index is not None:
            return folder_list[self.parent_index].resolve_path(folder_list) + "\\" + self.file_path
        return self.file_path

    def resolve_fs(self, folder_list: list) -> int | None:
        if self.fs_index is not None:
            return self.fs_index
        return folder_list[self.parent_index].resolve_fs(folder_list)


class EverythingDB:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)

        # Check if file is bzipped
        header = self.fh.read(4)
        self.fh.seek(-4, io.SEEK_CUR)
        # The database may be stored in a bzip compressed file, so we check for the header.
        # Beneath the compression, the file is still a valid database file.
        if header == BZIP_HEADER:
            self.fh = bz2.open(self.fh)  # noqa: SIM115

        header = c_header.everything_db_header(self.fh)
        if header.magic != FILE_MAGIC:
            raise ValueError(f"Invalid Everything magic header {header.magic}")

        self.header = header
        self.version = (header.version_major, header.version_minor, header.version_patch)
        self.c_filesystems = filesystems_cstruct(self.version)
        self.filesystems = []
        self.__parse_filesystems()

        # This might be hidden/system files/folders, or maybe a list of folders to exclude?
        # TODO - Check what happens when changing exclude hidden/system files/folders
        if self.version > COMPAT_1:
            exclude_flags = c_header.uint8_t(self.fh)
            log.debug("Exclude flags: %s", exclude_flags)

        # There is some logic here, but in my test file it doesn't affect the data
        # (Tested by dumping the raw array while debugging in IDA)
        # In practice, none of the data in the function is saved, it just advances the offset
        # This *MIGHT* be affected by an old version of the db (before 1.7.8)
        # If any of these fail, then I'd have to reverse this function and add support

        # I expect 0 here because the inner implementation of the function is:
        # for i in range(read_varint(self.fh)):
        #   do something
        # and the function is called 3 times one after another. As long as zero is returned each time, we don't need
        # to implement the logic
        if [read_varint(self.fh), read_varint(self.fh), read_varint(self.fh)] != [0, 0, 0]:
            raise NotImplementedError("Failed to parse database, unimplemented feature. Please open an issue")

        # Keep current position in the file, so we can seek back to it during __iter__
        self._start_seek = self.fh.tell()

    def __repr__(self) -> str:
        return f"{self.header} - Filesystems{self.filesystems}"

    def __parse_filesystems(self) -> None:
        for i in range(self.header.number_of_filesystems):
            filesystem_header = self.c_filesystems.filesystem_header(self.fh)
            log.debug("Filesystem %d: type %s", i, filesystem_header)

            try:
                fs_type = EverythingFSType(filesystem_header.type)
            except ValueError:
                raise ValueError(f"Unknown FS type {filesystem_header.type}")

            if fs_type in [EverythingFSType.NTFS, EverythingFSType.REFS]:
                if fs_type == EverythingFSType.NTFS:
                    header = self.c_filesystems.ntfs_header(self.fh)
                else:
                    header = self.c_filesystems.refs_header(self.fh)

            elif fs_type == EverythingFSType.EFU:
                header = self.c_filesystems.efu_header(self.fh)

            elif fs_type == EverythingFSType.FOLDER:
                header = self.c_filesystems.folder_header(self.fh)
            else:
                raise NotImplementedError(f"Have not implemented parsing {fs_type}")
            self.filesystems.append((fs_type, filesystem_header, header))

    def __iter__(self) -> Iterator[Record]:
        self.fh.seek(self._start_seek)
        # This builds a list of folders in the filesystem.  This creates an index, where each object contains:
        #   index of parent object (meaning the folder above)
        #   index of filesystem
        # This is later used to build a hierarchy for folders
        folder_list = [EverythingIndexObj() for _ in range(self.header.number_of_folders)]
        parent_lookup = c_header.uint32_t[self.header.number_of_folders](self.fh)
        for lookup_index, folder in enumerate(folder_list):
            parent_index = parent_lookup[lookup_index]
            # `parent_index` is an index into `folder_list`, which points to the parent folder of the current item
            # At the end of the loop, we have a list where each folder has an index to its parent.
            # Root folders (Such as C:\) don't have parents, instead they have an index into self.filesystem_list,
            # representing the filesystem they belong to.
            # This is represented by `filesystem_index = parent_index - self.header.number_of_folders`.
            # So we identify root folders by their parent_index being bigger than self.header.number_of_folders.

            # If `parent_index` is too big, we have an issue (It can't be an index into a filesystem or parent)
            if parent_index >= (self.header.number_of_filesystems + self.header.number_of_folders):
                raise ValueError("Invalid folder offset")
            if parent_index >= self.header.number_of_folders:
                folder.fs_index = parent_index - self.header.number_of_folders
            else:
                folder.parent_index = parent_index

        # This recursively resolves fs_index, so every folder will have it.
        for folder in folder_list:
            folder.fs_index = folder.resolve_fs(folder_list)

        yield from parse_folders(self, folder_list)

        yield from parse_files(self, folder_list)


def read_varint(stream: BinaryIO) -> int:
    """Read an ``uint8``, if it's equal to ``0xFF``, read the next 4 bytes as an ``int32``.
    In decompiled-ish code:
    .. code-block:: c

        int v1;
        LOBYTE(v1) = read(fd, 1);
        if ( (_BYTE)v1 == 0xFF ) v1 = read(fd, 4);
        else v1 = (unsigned __int8)v1;
    """
    first = stream.read(1)[0]
    if first == 0xFF:
        return int.from_bytes(stream.read(4), byteorder="little", signed=True)
    return first


def write_varint(data: int) -> bytes:
    # Strings under 0xFF are stored as a single unsigned byte, and everything else is stored as 0xFF + 4 bytes signed
    if data < 0xFF:
        return struct.pack("<B", data)
    return struct.pack("<Bi", 0xFF, data)


def parse_folder(db: EverythingDB, folder: EverythingIndexObj, name: str) -> None:
    folder.file_path = name
    # This is hardcoded for all folders
    folder.attributes = 16

    if c_header.EntryAttributes.has_folder_size in db.header.entry_attributes:
        folder.size = c_header.uint64_t(db.fh)
    if c_header.EntryAttributes.has_date_created in db.header.entry_attributes:
        folder.date_created = c_header.uint64_t(db.fh)
    if c_header.EntryAttributes.has_date_modified in db.header.entry_attributes:
        folder.date_modified = c_header.uint64_t(db.fh)
    if c_header.EntryAttributes.has_date_accessed in db.header.entry_attributes:
        folder.date_accessed = c_header.uint64_t(db.fh)
    if c_header.EntryAttributes.has_attributes in db.header.entry_attributes:
        folder.attributes = c_header.uint32_t(db.fh)

    if db.filesystems[folder.fs_index][0] == EverythingFSType.REFS:
        # Unknown
        c_header.uint64_t(db.fh)
        c_header.uint64_t(db.fh)
    elif db.filesystems[folder.fs_index][0] == EverythingFSType.NTFS:
        # Unknown
        c_header.uint64_t(db.fh)
    elif db.filesystems[folder.fs_index][0] == EverythingFSType.EFU:
        if folder.parent_index is None:
            # The EFU format does not contain the root drive, so it just puts random data into
            # the metadata.  This will cause errors if passed to flow.record, so we remove it here
            folder.date_accessed = None
            folder.date_modified = None
            folder.date_created = None
            folder.size = None

    # Must be done here because EFU files can contain garbage values
    if folder.date_accessed is not None:
        folder.date_accessed = wintimestamp(folder.date_accessed)
    if folder.date_modified is not None:
        folder.date_modified = wintimestamp(folder.date_modified)
    if folder.date_created is not None:
        folder.date_created = wintimestamp(folder.date_created)


def read_truncated_name(fh: BinaryIO, current_buf: bytes = b"") -> bytes:
    """Read a string stored in the format used by the database.
    If you have called this function before, you *must* pass the previous result to `current_buf`.

    Explanation:
    Everything has an "Optimization", where it saves all the basenames of the folders (and files)
    to the disk alphabetically.  This allows them to reuse similar filename buffers.
    For example, if two folders in the filesystem are named "AAA" and "ABCD",
    (and are alphabetically consecutive)
    then the first file will have data "AAA", with a `new_byte_count` of 3,
    and the second file will have a `new_byte_count` of 3 (length of "BCD"),
    and a `trunc_from_prev` of 3,
    thereby telling us to remove the last 3 bytes of the previous buffer, and saving space.
    The same thing happens later on when parsing filenames
    """
    if new_byte_count := read_varint(fh):
        trunc_from_prev = read_varint(fh)
        if trunc_from_prev > len(current_buf):
            raise ValueError(f"Error while parsing folder names {trunc_from_prev} > {len(current_buf)}")
        current_buf = current_buf[: len(current_buf) - trunc_from_prev]
    current_buf += fh.read(new_byte_count)
    return current_buf


def parse_folders(db: EverythingDB, folder_list: list[EverythingIndexObj]) -> Iterator[Record]:
    temp_buf = b""
    for folder in folder_list:
        # There is a bug loading EFU files, (which causes Everything v1.4.0.704b to crash)
        # where it tries to read an extra byte, which is not present in the file.
        # If at any point parsing EFU files fails, it is likely because of this bug,
        # and can be fixed by reading and discarding a single byte here.

        temp_buf = read_truncated_name(db.fh, temp_buf)
        # The yield can't happen here, because we can only call resolve_path once we finish this loop
        parse_folder(db, folder, temp_buf.decode())

    for folder in folder_list:
        yield Record(
            file_path=folder.resolve_path(folder_list),
            size=folder.size,
            attributes=folder.attributes,
            date_created=folder.date_created,
            date_modified=folder.date_modified,
            date_accessed=folder.date_accessed,
            file_type="directory",
        )


def parse_files(db: EverythingDB, folder_list: list[EverythingIndexObj]) -> Iterator[Record]:
    temp_buf = b""
    for _ in range(db.header.number_of_files):
        parent_index = c_header.uint32_t(db.fh)
        if parent_index > db.header.number_of_filesystems + db.header.number_of_folders:
            raise ValueError(
                "Error while parsing file names. Parent index out of bounds "
                f"{parent_index} > {db.header.number_of_filesystems + db.header.number_of_folders}"
            )

        # There MAY be some edge case where this is okay, and the check should be
        # parent_index < db.number_of_folders + db.total_filesystem_num, but I haven't seen this yet
        # Is there any way a file has a root filesystem without a folder?
        if parent_index >= db.header.number_of_folders:
            raise ValueError("Something weird, this points to filesystem_index")

        # There is a bug loading EFU files, (which causes Everything v1.4.0.704b to crash)
        # where it tries to read an extra byte, which is not present in the file.
        # If at any point parsing EFU files fails, it is likely because of this bug,
        # and can be fixed by reading and discarding a single byte here.

        file_name = folder_list[parent_index].resolve_path(folder_list)
        temp_buf = read_truncated_name(db.fh, temp_buf)
        file_size = (
            c_header.uint64_t(db.fh) if db.header.entry_attributes.has_file_size in db.header.entry_attributes else None
        )
        date_created = (
            wintimestamp(c_header.uint64_t(db.fh))
            if db.header.entry_attributes.has_date_created in db.header.entry_attributes
            else None
        )
        date_modified = (
            wintimestamp(c_header.uint64_t(db.fh))
            if db.header.entry_attributes.has_date_modified in db.header.entry_attributes
            else None
        )
        date_accessed = (
            wintimestamp(c_header.uint64_t(db.fh))
            if db.header.entry_attributes.has_date_accessed in db.header.entry_attributes
            else None
        )
        attributes = (
            c_header.uint32_t(db.fh)
            if db.header.entry_attributes.has_attributes in db.header.entry_attributes
            else None
        )

        try:
            yield Record(
                file_path=f"{file_name}\\{temp_buf.decode()}",
                size=file_size,
                attributes=attributes,
                date_created=date_created,
                date_modified=date_modified,
                date_accessed=date_accessed,
                file_type="file",
            )
        # This shouldn't be possible, but it happened in my tests to folders in the recycle bin
        except UnicodeDecodeError as e:
            log.warning("Failed parsing filepath: %s\\%s", file_name, temp_buf, exc_info=e)
