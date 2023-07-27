from __future__ import annotations

import logging
from typing import BinaryIO, Iterator

from dissect.util.stream import AlignedStream
from impacket.smb import ATTR_DIRECTORY, SharedFile
from impacket.smb3structs import (
    FILE_ATTRIBUTE_NORMAL,
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_READ_DATA,
    FILE_SHARE_READ,
)
from impacket.smbconnection import SessionError, SMBConnection

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class SmbFilesystem(Filesystem):
    """Filesystem implementation for SMB."""

    __fstype__ = "smb"

    def __init__(self, conn: SMBConnection, share_name: str, *args, **kwargs):
        super().__init__(None, *args, **kwargs, alt_separator="\\", case_sensitive=False)
        self._conn = conn
        self._share_name = share_name

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        """No, your file is not an SMB connection."""
        raise TypeError("Detect is not allowed on SmbFilesystem class")

    def get(self, path: str) -> FilesystemEntry:
        """Returns a SmbFilesystemEntry object corresponding to the given path."""
        path = fsutil.normalize(path, self.alt_separator)
        return SmbFilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path: str) -> SharedFile:
        if not path.strip("/"):
            # Getting proper information about the root of the share is cumbersome to just fake it
            return SharedFile(0, 0, 0, 0, 0, ATTR_DIRECTORY, "", "")

        try:
            result = self._conn.listPath(self._share_name, path)
        except SessionError as e:
            if e.error == 0xC0000103:
                # STATUS_NOT_A_DIRECTORY
                raise NotADirectoryError(path, cause=e)
            else:
                # 0xC000000F is STATUS_NO_SUCH_FILE, but everything else should raise a FileNotFoundError anyway
                raise FileNotFoundError(path, cause=e)

        if len(result) != 1:
            raise FileNotFoundError(path)

        return result[0]


class SmbFilesystemEntry(FilesystemEntry):
    fs: SmbFilesystem
    entry: SharedFile

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(fsutil.join(self.path, path, alt_separator=self.fs.alt_separator))

    def _iterdir(self) -> Iterator[SharedFile]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        path = fsutil.join(self.path, "*", alt_separator=self.fs.alt_separator)
        try:
            entry: SharedFile

            for entry in self.fs._conn.listPath(self.fs._share_name, path):
                if entry.get_longname() in (".", ".."):
                    continue

                yield entry
        except SessionError as e:
            log.error("Failed to list directory '%s' share '%s', error: %s", path, self.fs._share_name, e)

    def iterdir(self) -> Iterator[str]:
        for entry in self._iterdir():
            yield entry.get_longname()

    def scandir(self) -> Iterator[FilesystemEntry]:
        for entry in self._iterdir():
            entry_path = fsutil.join(self.path, entry.get_longname(), alt_separator=self.fs.alt_separator)
            yield SmbFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> SmbStream:
        log.debug("Attempting to open file: %s", self.path)
        try:
            return SmbStream(self.fs, self)
        except SessionError as e:
            raise FilesystemError(f"Failed to open file: {self.path}", cause=e)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return bool(self._resolve(follow_symlinks=follow_symlinks).entry.is_directory())
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return not self._resolve(follow_symlinks=follow_symlinks).is_dir()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        st_info = [
            0o755,
            fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
            id(self.fs),
            0,
            0,
            0,
            self.entry.get_filesize(),
            self.entry.get_atime_epoch(),
            self.entry.get_mtime_epoch(),
            self.entry.get_ctime_epoch(),
        ]

        return fsutil.stat_result(st_info)


class SmbStream(AlignedStream):
    """Stream implementation for reading SMB files."""

    def __init__(self, fs: SmbFilesystem, entry: SmbFilesystemEntry):
        self.fs = fs
        self.entry = entry

        self.tree_id = self.fs._conn.connectTree(self.fs._share_name)
        self.file_id = self.fs._conn.openFile(
            treeId=self.tree_id,
            pathName=entry.path,
            desiredAccess=FILE_READ_DATA,
            shareMode=FILE_SHARE_READ,
            creationOption=FILE_NON_DIRECTORY_FILE,
            creationDisposition=FILE_OPEN,
            fileAttributes=FILE_ATTRIBUTE_NORMAL,
        )
        super().__init__(entry.entry.get_filesize())

    def _read(self, offset: int, length: int) -> bytes:
        return self.fs._conn.readFile(self.tree_id, self.file_id, offset, length)

    def close(self) -> None:
        try:
            self.fs._conn.closeFile(self.tree_id, self.file_id)
        except Exception as e:
            log.warning("Failed to close file descriptor %d: %s", self.file_id, e)

        try:
            log.debug("Attempting to disconnect tree: %s (id=%d)", self.fs._share_name, self.tree_id)
            self.fs._conn.disconnectTree(self.tree_id)
        except Exception as e:
            log.warning(
                "Failed to disconnect from tree (share=%s, tree_id=%d): %s", self.fs._share_name, self.tree_id, e
            )
