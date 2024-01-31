import bz2
import logging
import dataclasses
from datetime import datetime

from typing import IO, Iterator, Optional, Union, List
from enum import auto, IntFlag, IntEnum
from dissect.util.ts import wintimestamp

logger = logging.getLogger(__name__)
FILE_MAGIC = b"ESDb"
# EZDB is an old format, used for EverythingDB 1.6.6 and 1.6.7 (Everything 1.2.1, back in 2009)
UNSUPPORTED_FILE_MAGIC = b"EZDB"
BZIP_HEADER = b"BZh9"


class EverythingFSType(IntEnum):
    NTFS = 0
    EFU = 1
    FOLDER = 2
    REFS = 3
    # FAT - Only supported from 1.5 (still in alpha)


class EverythingFlags(IntFlag):
    HasFileSize = auto()
    HasDateCreated = auto()
    HasDateModified = auto()
    HasDateAccessed = auto()
    HasAttributes = auto()
    HasFolderSize = auto()


class EverythingIndexObj:
    def __init__(self) -> None:
        # This is the index of filesystem_list
        self.fs_index: Optional[int] = None
        # Path to file (Only basename)
        self.file_path = None
        # Anything not explicitly set with parent index has an fs_index
        self.parent_index = None
        self.size = None
        self.date_created = None
        self.date_modified = None
        self.date_accessed = None
        self.attributes = None

    def resolve_path(self, folder_list: List) -> str:
        if self.parent_index is not None:
            return (
                    folder_list[self.parent_index].resolve_path(folder_list)
                    + "\\"
                    + self.file_path
            )
        else:
            return self.file_path

    def resolve_fs(self, folder_list: List) -> Optional[int]:
        if self.fs_index is not None:
            return self.fs_index
        else:
            return folder_list[self.parent_index].resolve_fs(folder_list)


@dataclasses.dataclass
class EverythingF:
    file_path: str
    size: Optional[int]
    date_created: Optional[datetime]
    date_modified: Optional[datetime]
    date_accessed: Optional[datetime]
    attributes: Optional[int]


class EverythingDirectory(EverythingF):
    pass


class EverythingFile(EverythingF):
    pass


class EverythingDBParser:
    def __init__(self, file_handle: IO[bytes]):
        self.fh = file_handle
        magic = self.__parse_magic(self.fh)

        # Everything supports BZipped databases
        if magic == BZIP_HEADER:
            self.fh.seek(-4, 1)
            self.fh = bz2.open(self.fh)
            magic = self.__parse_magic(self.fh)

        if magic == UNSUPPORTED_FILE_MAGIC:
            raise NotImplementedError(f"{UNSUPPORTED_FILE_MAGIC} files are not yet supported")

        if magic != FILE_MAGIC:
            raise ValueError(f"is not a known EverythingDB file. Magic: {magic.decode()}")

        self.__db_version = self.__parse_db_version()

        # This is the latest as of v1.4.1 which was released in 2017 (Maybe also a bit earlier?)
        # This is the version of the database format, not of Everything itself
        # Has not been tested on earlier versions, might actually work
        # I can add support for more versions if needed
        assert self.__db_version == "1.7.20"

        self.flags = EverythingFlags(self.read_u32())

        self.number_of_folders = self.read_u32()
        self.number_of_files = self.read_u32()

        self.__parse_filesystems()

        # Unused in this format
        exclude_flags = self.read_u8()
        logger.debug(f"Exclude flags: {exclude_flags}")

        # There is some logic here, but in my test file it doesn't affect the data
        # (Tested by dumping the raw array while debugging in IDA)
        # In practice, none of the data in the function is saved, it just advances the offset
        # This *MIGHT* be affected by an old version of the db (before 1.7.20)
        # If any of these fail, then I'd have to reverse this function and add support

        # I expect 0 here because the inner implementation of the function is:
        # for i in range(self.read_byte_or_4()):
        #   do something
        # and the function is called 3 times one after another. As long as zero is returned each time, we don't need
        # to implement the logic
        if [self.read_byte_or_4(), self.read_byte_or_4(), self.read_byte_or_4()] != [0, 0, 0]:
            raise NotImplementedError("Failed to parse database, need to implement support for weird database")

    def __parse_filesystems(self):
        self.total_filesystem_num = self.read_byte_or_4()
        self.filesystem_list: List[EverythingFSType] = []
        logger.debug("filesystem count %s", self.total_filesystem_num)
        # Most of the filesystem data is going to waste, not sure if we want it or not
        for i in range(self.total_filesystem_num):
            fs_type = self.read_byte_or_4()
            logger.debug(f"Filesystem {i}: type {fs_type}")
            fs_out_of_date = self.read_u8()
            logger.debug(f"Filesystem {i}: out of date {fs_out_of_date}")
            try:
                # TODO: Test Everything 1.5
                fs_type = EverythingFSType(fs_type)
            except ValueError:
                raise ValueError(f"Unsupported FS type {fs_type}")

            self.filesystem_list.append(fs_type)
            if fs_type == EverythingFSType.NTFS:
                fs_guid = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} NTFS: guid: {fs_guid}")
                fs_path = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} NTFS: path: {fs_path}")
                fs_root = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} NTFS: root: {fs_root}")
                include_only = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} NTFS: include_only: {include_only}")
                journal_id = self.read_u64()
                logger.debug(f"Filesystem {i} NTFS: USN Journal ID: {hex(journal_id)}")
                next_usn = self.read_u64()
                logger.debug(f"Filesystem {i} NTFS: Next USN: {hex(next_usn)}")
            elif fs_type == EverythingFSType.FOLDER:
                fs_path = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} FOLDER: path: {fs_path}")
                fs_next_update = self.read_u64()
                logger.debug(f"Filesystem {i} FOLDER: next_update: {hex(fs_next_update)}")
            elif fs_type == EverythingFSType.EFU:
                src_efu_file = self.read_len_then_data()
                logger.debug(f"Filesystem {i} EFU: path: {src_efu_file}")
                unk1 = self.read_u64()
                logger.debug(f"Filesystem {i} EFU: unk1: {unk1}")
            elif fs_type == EverythingFSType.REFS:
                # All parameters here are guesses based off of NTFS and looking at data.
                # Either way, the data here is not important for parsing so if I'm wrong nothing bad will happen
                fs_guid = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} REFS: guid: {fs_guid}")
                fs_path = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} REFS: path: {fs_path}")
                fs_root = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} REFS: root: {fs_root}")
                fs_include_only = self.read_len_then_data().decode()
                logger.debug(f"Filesystem {i} REFS: include_only: {fs_include_only}")
                journal_id = self.read_u64()
                logger.debug(f"Filesystem {i} REFS: USN Journal ID: {journal_id}")
                next_usn = self.read_u64()
                logger.debug(f"Filesystem {i} REFS: Next USN: {hex(next_usn)}")
            else:
                raise NotImplementedError(f"Have not implemented parsing {fs_type}")

    def __iter__(self) -> Iterator[Union[EverythingFile, EverythingDirectory]]:
        # This builds a list of folders in the filesystem.  This creates an index, where each object contains:
        #   index of parent object (meaning the folder above)
        #   index of filesystem
        # This is later used to build a hierarchy for folders
        folder_list = [EverythingIndexObj() for _ in range(self.number_of_folders)]
        for i in range(self.number_of_folders):
            parent_index = self.read_u32()
            # parent_index is a pointer into folder_list, which points to the parent folder.
            # If the parent_index is more than the number of folders on the filesystem, it represents the index
            # of the filesystem in self.filesystem_list.
            # If it is event bigger than that, something is wrong with the database
            assert parent_index < (
                    self.total_filesystem_num + self.number_of_folders
            ), "Invalid folder offset"
            if parent_index >= self.number_of_folders:
                folder_list[i].fs_index = parent_index - self.number_of_folders
            else:
                folder_list[i].parent_index = parent_index

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
            # then the first file will have data "Potato", with a str_len of 6,
            # and the second file will have a str_len of 5 (length of "Salad"), and a "num_from_prev" (see below) of 5,
            # thereby telling us to remove the last 5 bytes of the previous buffer, and saving allocations.
            # The same thing happens later on when parsing filenames

            prev_size = len(temp_buf)

            # This is what the code wants me to do, but this causes everything (including the original code) to fail.
            # Keeping this commented out for now
            # if self.filesystem_list[folder.fs_index] == EverythingFSType.EFU:
            #     unk2 = self.read_u8()
            #     logger.debug(f"EFU: unk2: {unk2}")

            str_len = self.read_byte_or_4()
            if str_len:
                remove_from_prev = self.read_byte_or_4()
                assert remove_from_prev <= prev_size, "Invalid folder code offset"
                temp_buf = temp_buf[: prev_size - remove_from_prev]
            temp_buf += self.read(str_len)

            folder.file_path = temp_buf.decode()

            # This is hardcoded for all folders
            folder.attributes = 16

            # The yield can't happen here, because we can only call resolve_path once we finish this loop
            if EverythingFlags.HasFolderSize in self.flags:
                folder.size = self.read_u64()
            if EverythingFlags.HasDateCreated in self.flags:
                folder.date_created = self.read_u64()
            if EverythingFlags.HasDateModified in self.flags:
                folder.date_modified = self.read_u64()
            if EverythingFlags.HasDateAccessed in self.flags:
                folder.date_accessed = self.read_u64()
            if EverythingFlags.HasAttributes in self.flags:
                folder.attributes = self.read_u32()
            if self.filesystem_list[folder.fs_index] == EverythingFSType.NTFS:
                self.read_u64()
            elif self.filesystem_list[folder.fs_index] == EverythingFSType.REFS:
                self.read_u64()
                self.read_u64()
            elif self.filesystem_list[folder.fs_index] == EverythingFSType.EFU and folder.parent_index is None:
                # This is something the original code ignores, but I have to handle because we actually care about the
                # date being correct.  The EFU format does not contain the root drive, so it just puts random data into
                # the metadata.  This will cause errors if passed to flow.record, so we remove it here
                folder.date_accessed = None
                folder.date_modified = None
                folder.date_created = None
                folder.size = None
            else:
                pass

        for folder in folder_list:
            yield EverythingDirectory(
                file_path=folder.resolve_path(folder_list),
                size=folder.size,
                attributes=folder.attributes,
                date_created=wintimestamp(folder.date_created) if folder.date_created else None,
                date_modified=wintimestamp(folder.date_modified) if folder.date_modified else None,
                date_accessed=wintimestamp(folder.date_accessed) if folder.date_accessed else None,
            )

        temp_buf = b""
        for _ in range(self.number_of_files):
            # See comment above for explanation of this loop
            prev_size = len(temp_buf)
            parent_index = self.read_u32()
            assert not (
                    parent_index > self.total_filesystem_num + self.number_of_folders
            ), "Invalid parent folder offset"
            # There MAY be some edge case where this is okay, and the check should be
            # parent_index < self.number_of_folders + self.total_filesystem_num, but I haven't seen this yet
            assert parent_index < self.number_of_folders, "Something weird, this points to filesystem_index"

            # This is what the code wants me to do, but this causes everything (including the original code) to fail.
            # Keeping this commented out for now
            # if self.filesystem_list[folder_list[parent_index].resolve_fs(folder_list)] == EverythingFSType.EFU:
            #     unk3 = self.read_u8()
            #     logger.debug(f"EFU: unk3: {unk3}")
            #     raise NotImplementedError("This has not been tested, but should work. Remove this raise and test")

            file_name = folder_list[parent_index].resolve_path(folder_list)
            str_len = self.read_byte_or_4()
            if str_len:
                remove_from_prev = self.read_byte_or_4()
                assert remove_from_prev <= prev_size, "Invalid file code offset"
                temp_buf = temp_buf[: prev_size - remove_from_prev]
            temp_buf += self.read(str_len)
            file_size = self.read_u64() if EverythingFlags.HasFileSize in self.flags else None
            date_created = self.read_u64() if EverythingFlags.HasDateCreated in self.flags else None
            date_modified = self.read_u64() if EverythingFlags.HasDateModified in self.flags else None
            date_accessed = self.read_u64() if EverythingFlags.HasDateAccessed in self.flags else None
            attributes = self.read_u32() if EverythingFlags.HasAttributes in self.flags else None

            try:
                yield EverythingFile(
                    file_path=f"{file_name}\\{temp_buf.decode()}",
                    size=file_size,
                    attributes=attributes,
                    date_created=wintimestamp(date_created) if date_created else None,
                    date_modified=wintimestamp(date_modified) if date_modified else None,
                    date_accessed=wintimestamp(date_accessed) if date_accessed else None,
                )
            # This shouldn't be possible, but it happened in my tests to folders in the recycle bin
            except UnicodeDecodeError as e:
                logger.warning(f"Failed parsing filepath: {file_name}\\{temp_buf}", exc_info=e)

    @staticmethod
    def __parse_magic(reader: IO[bytes]) -> bytes:
        mgk = reader.read(4)
        return mgk

    def read(self, i: int) -> bytes:
        return self.fh.read(i)

    def read_u8(self) -> int:
        return self.fh.read(1)[0]

    def read_u32(self) -> int:
        return int.from_bytes(self.fh.read(4), byteorder="little")

    def read_u64(self) -> int:
        return int.from_bytes(self.fh.read(8), byteorder="little")

    @property
    def version(self):
        return self.__db_version

    def __parse_db_version(self):
        """This function must only be called from init when fh is in the right position

        This logic is mostly guesswork and just whatever worked, I didn't actually look at the real implementation
        For now this isn't critical as it works on the latest version of the DB (2016 as of 2022)
        """
        [v1, v2, v3, v4] = self.read(4)
        version = f"{v4}.{v3}.{int.from_bytes([v1, v2], byteorder='little')}"
        return version

    def read_byte_or_4(self) -> int:
        """This functions reads a single byte, and in case the first byte is 0xFF, reads another 4 (Saving space)

        In decompiled-ish code:
        int v1;
        LOBYTE(v1) = read(fd, 1);
        if ( (_BYTE)v1 == 0xFF ) v1 = read(fd, 4);
        else v1 = (unsigned __int8)v1;
        """
        first = self.read(1)[0]
        if first == 0xFF:
            # This has never actually happened to me, so debating leaving this here for now
            raise NotImplementedError("Untested feature, can remove comment and see if this still works :)")
            return int.from_bytes(data.read(4), byteorder="little", signed=True)
        else:
            return first

    def read_len_then_data(self):
        data_len = self.read_byte_or_4()
        return self.read(data_len)
