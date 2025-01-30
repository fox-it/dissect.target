from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from dissect.target.helpers.sunrpc.sunrpc import ProcedureDescriptor

# See https://datatracker.ietf.org/doc/html/rfc1057


NfsProgram = 100003
MountProgram = 100005
NfsVersion = 3

# List of procedure descriptors
MountProc = ProcedureDescriptor(MountProgram, NfsVersion, 1)
ReadDirPlusProc = ProcedureDescriptor(NfsProgram, NfsVersion, 17)
ReadFileProc = ProcedureDescriptor(NfsProgram, NfsVersion, 6)
LookupProc = ProcedureDescriptor(NfsProgram, NfsVersion, 3)
GetAttrProc = ProcedureDescriptor(NfsProgram, NfsVersion, 1)
ReadLinkProc = ProcedureDescriptor(NfsProgram, NfsVersion, 5)


class Nfs3Stat(IntEnum):
    OK = 0
    ERR_PERM = 1
    ERR_NOENT = 2
    ERR_IO = 5
    ERR_NXIO = 6
    ERR_ACCES = 13
    ERR_EXIST = 17
    ERR_XDEV = 18
    ERR_NODEV = 19
    ERR_NOTDIR = 20
    ERR_ISDIR = 21
    ERR_INVAL = 22
    ERR_FBIG = 27
    ERR_NOSPC = 28
    ERR_ROFS = 30
    ERR_MLINK = 31
    ERR_NAMETOOLONG = 63
    ERR_NOTEMPTY = 66
    ERR_DQUOT = 69
    ERR_STALE = 70
    ERR_REMOTE = 71
    ERR_BADHANDLE = 10001


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


class FileType3(IntEnum):
    REG = 1  # regular file
    DIR = 2  # directory
    BLK = 3  # block special
    CHR = 4  # character special
    LNK = 5  # symbolic link
    SOCK = 6  # socket
    FIFO = 7  # fifo


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


class MountStat3(IntEnum):
    OK = 0  # no error
    ERR_PERM = 1  # Not owner
    ERR_NOENT = 2  # No such file or directory
    ERR_IO = 5  # I/O error
    ERR_ACCES = 13  # Permission denied
    ERR_NOTDIR = 20  # Not a directory
    ERR_INVAL = 22  # Invalid argument
    ERR_NAMETOOLONG = 63  # Filename too long
    ERR_NOTSUPP = 10004  # Operation not supported
    ERR_SERVERFAULT = 10006  # A failure on the server


@dataclass
class MountOK3:
    filehandle: FileHandle3
    auth_flavors: list[int]


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


@dataclass
class DirOpArgs3:
    handle: FileHandle3
    filename: str


@dataclass
class Lookup3resok:
    object: FileHandle3
    obj_attributes: FileAttributes3 | None
    dir_attributes: FileAttributes3 | None


@dataclass
class Readlink3resok:
    obj_attributes: FileAttributes3 | None
    target: str  # named "data" in the NFC
