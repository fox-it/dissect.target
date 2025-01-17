from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

# See https://datatracker.ietf.org/doc/html/rfc1057


class NfsStat(Enum):
    NFS3_OK = 0
    NFS3ERR_PERM = 1
    NFS3ERR_NOENT = 2
    NFS3ERR_IO = 5
    NFS3ERR_NXIO = 6
    NFS3ERR_ACCES = 13
    NFS3ERR_EXIST = 17
    NFS3ERR_XDEV = 18
    NFS3ERR_NODEV = 19
    NFS3ERR_NOTDIR = 20
    NFS3ERR_ISDIR = 21
    NFS3ERR_INVAL = 22
    NFS3ERR_FBIG = 27
    NFS3ERR_NOSPC = 28
    NFS3ERR_ROFS = 30
    NFS3ERR_MLINK = 31
    NFS3ERR_NAMETOOLONG = 63
    NFS3ERR_NOTEMPTY = 66
    NFS3ERR_DQUOT = 69
    NFS3ERR_STALE = 70
    NFS3ERR_REMOTE = 71
    NFS3ERR_BADHANDLE = 10001


@dataclass
class FileHandle3:
    MAXSIZE: ClassVar[int] = 64
    opaque: bytes

    def __post_init__(self):
        if len(self.opaque) > self.MAXSIZE:
            raise ValueError(f"FileHandle3 cannot exceed {self.MAXSIZE} bytes")


@dataclass
class CookieVerf3:
    MAXSIZE: ClassVar[int] = 8
    opaque: bytes

    def __post_init__(self):
        if len(self.opaque) > self.MAXSIZE:
            raise ValueError(f"CookieVerf cannot exceed {self.MAXSIZE} bytes")


class FileType3(Enum):
    NF3REG = 1  # regular file
    NF3DIR = 2  # directory
    NF3BLK = 3  # block special
    NF3CHR = 4  # character special
    NF3LNK = 5  # symbolic link
    NF3SOCK = 6  # socket
    NF3FIFO = 7  # fifo


@dataclass
class SpecData3:
    specdata1: int
    specdata2: int


@dataclass
class NfsTime3:
    seconds: int
    nseconds: int


@dataclass
class FileAttributes3:
    type: FileType3
    mode: int
    nlink: int
    uid: int
    gid: int
    size: int
    used: int
    rdev: SpecData3
    fsid: int
    fileid: int
    atime: NfsTime3
    mtime: NfsTime3
    ctime: NfsTime3


class MountStat(Enum):
    MNT3_OK = 0  # no error
    MNT3ERR_PERM = 1  # Not owner
    MNT3ERR_NOENT = 2  # No such file or directory
    MNT3ERR_IO = 5  # I/O error
    MNT3ERR_ACCES = 13  # Permission denied
    MNT3ERR_NOTDIR = 20  # Not a directory
    MNT3ERR_INVAL = 22  # Invalid argument
    MNT3ERR_NAMETOOLONG = 63  # Filename too long
    MNT3ERR_NOTSUPP = 10004  # Operation not supported
    MNT3ERR_SERVERFAULT = 10006  # A failure on the server


@dataclass
class MountParams:
    dirpath: str


@dataclass
class MountOK:
    filehandle: FileHandle3
    authFlavors: list[int]


@dataclass
class ReadDirPlusParams:
    dir: FileHandle3
    cookie: int
    cookieverf: CookieVerf3
    dir_count: int
    max_count: int


@dataclass
class EntryPlus3:
    fileid: int
    name: str
    cookie: int
    attributes: FileAttributes3 | None
    handle: FileHandle3 | None


@dataclass
class ReadDirPlusResult3:
    dir_attributes: FileAttributes3 | None
    cookieverf: CookieVerf3
    entries: list[EntryPlus3]
    eof: bool


@dataclass
class Read3args:
    file: FileHandle3
    offset: int
    count: int


@dataclass
class Read3resok:
    file_attributes: FileAttributes3 | None
    count: int
    eof: bool
    data: bytes
