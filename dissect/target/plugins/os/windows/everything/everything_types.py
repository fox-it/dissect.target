from __future__ import annotations

import bz2
import contextlib
import dataclasses
import logging
from abc import ABC
from datetime import datetime
from enum import IntEnum
from packaging.version import Version
from typing import Any, BinaryIO, Iterator

from dissect.cstruct import BaseType, cstruct
from dissect.util.ts import wintimestamp

BZIP_HEADER = b"BZh9"
FILE_MAGIC = b"ESDb"
REFS_MIN_VERSION = Version("1.7.17")
COMPAT_1 = Version("1.7.9")

log = logging.getLogger(__name__)
__filesystem_cstruct_cache = {}


class EverythingVarInt(BaseType):
    """TODO - Maybe this can be built using cstruct in a roundabout way?"""

    @classmethod
    def _read(cls, stream: BinaryIO, context: dict[str, Any] = None) -> int:
        return read_byte_or_4(stream)

    @classmethod
    def _write(cls, stream: BinaryIO, data: Any) -> int:
        raise NotImplementedError


class EverythingVarBytes(BaseType):
    @classmethod
    def _read(cls, stream: BinaryIO, context: dict[str, Any] = None) -> bytes:
        return read_len_then_data(stream)

    @classmethod
    def _write(cls, stream: BinaryIO, data: Any) -> int:
        raise NotImplementedError


c_header_def = """
struct everything_db_header {
    // Note - File header may be equal to `BZIP_HEADER`. In this case, file must be handled as a bzip compressed file
    char magic[4];

    // Version
    uint16_t version_patch;
    uint8_t version_minor;
    uint8_t version_major;

    // Flags
    uint32_t flag_has_file_size:1;
    uint32_t flag_has_date_created:1;
    uint32_t flag_has_date_modified:1;
    uint32_t flag_has_date_accessed:1;
    uint32_t flag_has_attributes:1;
    uint32_t flag_has_folder_size:1;

    uint32_t number_of_folders;
    uint32_t number_of_files;
    EverythingVarInt number_of_filesystems;

};
"""
everything_header_cs = cstruct()
everything_header_cs.add_custom_type("EverythingVarInt", EverythingVarInt)
everything_header_cs.load(c_header_def)


def version_match(stmt: str, cond: bool) -> str:
    """Used for easy filtering of version constraints in cstruct definitions"""
    return stmt if cond else ""


def filesystems_cstruct(version: Version) -> cstruct:
    if cached_fs_cstruct := __filesystem_cstruct_cache.get(version):
        return cached_fs_cstruct

    c_filesystems_def = f"""
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
    everything_filesystem_cs = cstruct()
    everything_filesystem_cs.add_custom_type("EverythingVarInt", EverythingVarInt)
    everything_filesystem_cs.add_custom_type("EverythingVarBytes", EverythingVarBytes)
    everything_filesystem_cs.load(c_filesystems_def)

    __filesystem_cstruct_cache[version] = everything_filesystem_cs
    return everything_filesystem_cs


@dataclasses.dataclass(init=False)
class EverythingFS(ABC):
    MIN_VERSION = None
    MAX_VERSION = None
    out_of_date: int

    @classmethod
    def supported_version(cls, version: Version) -> bool:
        if cls.MIN_VERSION and version < cls.MIN_VERSION:
            return False
        if cls.MAX_VERSION and version > cls.MAX_VERSION:
            return False
        return True


@dataclasses.dataclass(init=False)
class EverythingNTFS(EverythingFS):
    # Guid in format \\?\Volume{GUID}
    guid: str
    # Disk drive (C:, D:)
    path: str
    root: str
    include_only: str
    journal_id: int
    next_usn: int


@dataclasses.dataclass(init=False)
class EverythingEFU(EverythingFS):
    # Path of EFU on disk
    source_path: str

    # Only after 1.7.9 TODO Verify
    unk1: int


@dataclasses.dataclass(init=False)
class EverythingFolder(EverythingFS):
    # Path to folder being indexed
    path: str

    # Timestamp of next folder update? Only after 1.7.9
    next_update_time: int


@dataclasses.dataclass(init=False)
class EverythingREFS(EverythingNTFS):
    MIN_VERSION = REFS_MIN_VERSION


class EverythingFSType(IntEnum):
    NTFS = 0
    EFU = 1
    FOLDER = 2
    REFS = 3
    # TODO - Add FAT support (Only in Everything 1.5 which is still in alpha)


EverythingFSTypeToFS = {
    EverythingFSType.NTFS: EverythingNTFS,
    EverythingFSType.EFU: EverythingEFU,
    EverythingFSType.FOLDER: EverythingFolder,
    EverythingFSType.REFS: EverythingREFS,
}


@dataclasses.dataclass
class EverythingF:
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
        else:
            return self.file_path

    def resolve_fs(self, folder_list: list) -> int | None:
        if self.fs_index is not None:
            return self.fs_index
        else:
            return folder_list[self.parent_index].resolve_fs(folder_list)


@dataclasses.dataclass
class EverythingDBMetadata:
    magic: bytes

    version: Version

    flag_has_file_size: bool
    flag_has_date_created: bool
    flag_has_date_modified: bool
    flag_has_date_accessed: bool
    flag_has_attributes: bool
    flag_has_folder_size: bool

    number_of_folders: int
    number_of_files: int
    number_of_filesystems: int


class EverythingDBParser:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        # Check if file is bzipped
        header = self.read(4)
        self.fh.seek(-4, 1)
        # Everything supports BZipped databases. Everything is the same under the compression
        if header == BZIP_HEADER:
            self.fh: BinaryIO = bz2.open(self.fh)  # type:ignore

        header = everything_header_cs.everything_db_header(self.fh)
        if header.magic != FILE_MAGIC:
            raise ValueError(f"Invalid Everything magic header {header.magic}")

        self.header = EverythingDBMetadata(
            magic=header.magic,
            version=Version(f"{header.version_major}.{header.version_minor}.{header.version_patch}"),
            flag_has_file_size=header.flag_has_file_size,
            flag_has_date_created=header.flag_has_date_created,
            flag_has_date_modified=header.flag_has_date_modified,
            flag_has_date_accessed=header.flag_has_date_accessed,
            flag_has_attributes=header.flag_has_attributes,
            flag_has_folder_size=header.flag_has_folder_size,
            number_of_folders=header.number_of_folders,
            number_of_files=header.number_of_files,
            number_of_filesystems=header.number_of_filesystems,
        )

        self.filesystems_cstruct = filesystems_cstruct(self.header.version)
        self.__parse_filesystems()

        # This might be hidden/system files/folders, or maybe a list of folders to exclude?
        # TODO - Check what happens when changing exclude hidden/system files/folders
        if self.database_version > COMPAT_1:
            exclude_flags = self.read_u8()
            log.debug("Exclude flags: %s", exclude_flags)

        # There is some logic here, but in my test file it doesn't affect the data
        # (Tested by dumping the raw array while debugging in IDA)
        # In practice, none of the data in the function is saved, it just advances the offset
        # This *MIGHT* be affected by an old version of the db (before 1.7.8)
        # If any of these fail, then I'd have to reverse this function and add support

        # I expect 0 here because the inner implementation of the function is:
        # for i in range(self.read_byte_or_4()):
        #   do something
        # and the function is called 3 times one after another. As long as zero is returned each time, we don't need
        # to implement the logic
        if [self.read_byte_or_4(), self.read_byte_or_4(), self.read_byte_or_4()] != [0, 0, 0]:
            raise NotImplementedError("Failed to parse database, unimplemented feature. Please open an issue")

    def __repr__(self) -> str:
        return f"{self.header} - Filesystems{self.filesystem_list}"

    def __parse_filesystems(self) -> None:
        # TODO - Is there a way for this to be cstructable
        self.filesystem_list: list[EverythingFS] = []

        for i in range(self.header.number_of_filesystems):
            filesystem_header = self.filesystems_cstruct.filesystem_header(self.fh)
            log.debug("Filesystem %d: type %s", i, filesystem_header)

            try:
                fs_type = EverythingFSType(filesystem_header.type)
            except ValueError:
                raise ValueError(f"Unknown FS type {filesystem_header.type}")
            fs = EverythingFSTypeToFS[fs_type]()
            if not fs.supported_version(self.database_version):
                raise ValueError(f"Unsupported FS type {fs_type} for version {self.database_version}")

            # Version dependent attribute
            with contextlib.suppress(AttributeError):
                fs.out_of_date = filesystem_header.out_of_date

            if fs_type in [EverythingFSType.NTFS, EverythingFSType.REFS]:
                if fs_type == EverythingFSType.NTFS:
                    c_fs = self.filesystems_cstruct.ntfs_header(self.fh)
                else:
                    c_fs = self.filesystems_cstruct.refs_header(self.fh)
                fs.guid = c_fs.guid
                fs.path = c_fs.path
                fs.root = c_fs.root
                with contextlib.suppress(AttributeError):
                    fs.include_only = c_fs.include_only
                    fs.journal_id = c_fs.journal_id
                    fs.next_usn = c_fs.next_usn

            elif fs_type == EverythingFSType.EFU:
                c_fs = self.filesystems_cstruct.efu_header(self.fh)
                fs.source_path = c_fs.source_path
                with contextlib.suppress(AttributeError):
                    fs.unk1 = c_fs.unk1

            elif fs_type == EverythingFSType.FOLDER:
                c_fs = self.filesystems_cstruct.folder_header(self.fh)
                fs.path = c_fs.path
                with contextlib.suppress(AttributeError):
                    fs.next_update_time = c_fs.next_update_time
            else:
                raise NotImplementedError(f"Have not implemented parsing {fs_type}")
            self.filesystem_list.append(fs)

    @property
    def database_version(self) -> Version:
        return self.header.version

    def __iter__(self) -> Iterator[EverythingF]:
        # TODO - Can this be cstructed?
        # This builds a list of folders in the filesystem.  This creates an index, where each object contains:
        #   index of parent object (meaning the folder above)
        #   index of filesystem
        # This is later used to build a hierarchy for folders
        folder_list = [EverythingIndexObj() for _ in range(self.header.number_of_folders)]
        for folder in folder_list:
            parent_index = self.read_u32()
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
        for f in folder_list:
            f.fs_index = f.resolve_fs(folder_list)

        temp_buf = b""

        for folder in folder_list:
            # Explanation:
            # Everything has an "Optimization", where it saves all the basenames of the folders (and files)
            # to the disk alphabetically.  This allows them to reuse similar filename buffers.
            # For example, if two folders in the filesystem are named "Potato" and "PotatoSalad" respectively,
            # (and are alphabetically consecutive)
            # then the first file will have data "Potato", with a `new_byte_count` of 6,
            # and the second file will have a `new_byte_count` of 5 (length of "Salad"),
            # and a `trunc_from_prev` (see below) of 5,
            # thereby telling us to remove the last 5 bytes
            # of the previous buffer, and saving space.
            # The same thing happens later on when parsing filenames

            # I believe this is an actual bug, loading EFU files also causes Everything v1.4.0.704b to crash
            # Leaving the code here in case this is fixed in a newer version
            # if self.filesystem_list[folder.fs_index] == EverythingFSType.EFU:
            #     unk2 = self.read_u8()
            #     logger.debug(f"EFU: unk2: {unk2}")

            if new_byte_count := self.read_byte_or_4():
                trunc_from_prev = self.read_byte_or_4()
                if trunc_from_prev > len(temp_buf):
                    raise ValueError(f"Error while parsing folder names {trunc_from_prev} > {len(temp_buf)}")
                temp_buf = temp_buf[: len(temp_buf) - trunc_from_prev]
            temp_buf += self.read(new_byte_count)

            folder.file_path = temp_buf.decode()

            # This is hardcoded for all folders
            folder.attributes = 16

            # The yield can't happen here, because we can only call resolve_path once we finish this loop
            if self.header.flag_has_folder_size:
                folder.size = self.read_u64()
            if self.header.flag_has_date_created:
                folder.date_created = self.read_u64()
            if self.header.flag_has_date_modified:
                folder.date_modified = self.read_u64()
            if self.header.flag_has_date_accessed:
                folder.date_accessed = self.read_u64()
            if self.header.flag_has_attributes:
                folder.attributes = self.read_u32()

            if isinstance(self.filesystem_list[folder.fs_index], EverythingREFS):
                # Unknown
                self.read_u64()
                self.read_u64()
            elif isinstance(self.filesystem_list[folder.fs_index], EverythingNTFS):
                # Unknown
                self.read_u64()
            elif isinstance(self.filesystem_list[folder.fs_index], EverythingEFU):
                if folder.parent_index is not None:
                    continue
                # The EFU format does not contain the root drive, so it just puts random data into
                # the metadata.  This will cause errors if passed to flow.record, so we remove it here
                folder.date_accessed = None
                folder.date_modified = None
                folder.date_created = None
                folder.size = None

        for folder in folder_list:
            yield EverythingF(
                file_path=folder.resolve_path(folder_list),
                size=folder.size,
                attributes=folder.attributes,
                date_created=wintimestamp(folder.date_created) if folder.date_created else None,
                date_modified=wintimestamp(folder.date_modified) if folder.date_modified else None,
                date_accessed=wintimestamp(folder.date_accessed) if folder.date_accessed else None,
                file_type="directory",
            )

        temp_buf = b""
        for _ in range(self.header.number_of_files):
            # See comment above for explanation of this loop
            parent_index = self.read_u32()
            if parent_index > self.header.number_of_filesystems + self.header.number_of_folders:
                raise ValueError(
                    "Error while parsing file names. Parent index out of bounds "
                    f"{parent_index} > {self.header.number_of_filesystems + self.header.number_of_folders}"
                )

            # There MAY be some edge case where this is okay, and the check should be
            # parent_index < self.number_of_folders + self.total_filesystem_num, but I haven't seen this yet
            # Is there any way a file has a root filesystem without a folder?
            if parent_index >= self.header.number_of_folders:
                raise ValueError("Something weird, this points to filesystem_index")

            # This is what the code wants me to do, but this causes everything (including the original code) to fail.
            # I believe this is an actual bug, EFU files also cause Everything v1.4.0.704b to crash when parsing DB
            # Keeping this commented out for now
            # if self.filesystem_list[folder_list[parent_index].fs_index] == EverythingFSType.EFU:
            #     unk3 = self.read_u8()
            #     logger.debug(f"EFU: unk3: {unk3}")

            file_name = folder_list[parent_index].resolve_path(folder_list)
            if new_byte_count := self.read_byte_or_4():
                trunc_from_prev = self.read_byte_or_4()
                if trunc_from_prev > len(temp_buf):
                    raise ValueError(f"Error while parsing file name {trunc_from_prev} > {len(temp_buf)}")
                temp_buf = temp_buf[: len(temp_buf) - trunc_from_prev]
            temp_buf += self.read(new_byte_count)
            file_size = self.read_u64() if self.header.flag_has_file_size else None
            date_created = wintimestamp(self.read_u64()) if self.header.flag_has_date_created else None
            date_modified = wintimestamp(self.read_u64()) if self.header.flag_has_date_modified else None
            date_accessed = wintimestamp(self.read_u64()) if self.header.flag_has_date_accessed else None
            attributes = self.read_u32() if self.header.flag_has_attributes else None

            try:
                yield EverythingF(
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
                log.warning(f"Failed parsing filepath: {file_name}\\{temp_buf}", exc_info=e)

    def read(self, i: int) -> bytes:
        return self.fh.read(i)

    def read_u8(self) -> int:
        return self.fh.read(1)[0]

    def read_u32(self) -> int:
        return int.from_bytes(self.fh.read(4), byteorder="little")

    def read_u64(self) -> int:
        return int.from_bytes(self.fh.read(8), byteorder="little")

    def read_byte_or_4(self) -> int:
        return read_byte_or_4(self.fh)

    def read_len_then_data(self):
        return read_len_then_data(self.fh)


def read_byte_or_4(stream: BinaryIO) -> int:
    """This functions reads a single byte, and in case the first byte is 0xFF, reads another 4 (Saving space)

    In decompiled-ish code:
    int v1;
    LOBYTE(v1) = read(fd, 1);
    if ( (_BYTE)v1 == 0xFF ) v1 = read(fd, 4);
    else v1 = (unsigned __int8)v1;
    """
    first = stream.read(1)[0]
    if first == 0xFF:
        # This has never actually happened to me, so debating leaving this here for now.
        # Is this signed? recv is signed so I assume so
        raise NotImplementedError("Untested feature, can remove comment and see if this still works :)")
        return int.from_bytes(stream.read(4), byteorder="little", signed=True)
    else:
        return first


def read_len_then_data(stream: BinaryIO) -> bytes:
    data_len = read_byte_or_4(stream)
    return stream.read(data_len)
