from __future__ import annotations

import ipaddress
import struct
from enum import IntEnum
from typing import TYPE_CHECKING, NamedTuple

from dissect.cstruct import cstruct
from dissect.database.sqlite3 import SQLite3
from dissect.util.ts import from_unix, from_unix_us

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, alias, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from pathlib import Path

    from dissect.target.target import Target

UTMP_FIELDS = [
    ("datetime", "ts"),
    ("datetime", "ts_logout"),
    ("string", "ut_type"),
    ("string", "ut_user"),
    ("varint", "ut_pid"),
    ("string", "ut_line"),
    ("string", "ut_id"),
    ("string", "ut_host"),
    ("net.ipaddress", "ut_addr"),
    ("string", "ut_service"),
    ("path", "source"),
]

BtmpRecord = TargetRecordDescriptor(
    "linux/log/btmp",
    UTMP_FIELDS,
)

WtmpRecord = TargetRecordDescriptor(
    "linux/log/wtmp",
    UTMP_FIELDS,
)

utmp_def = """
#define UT_LINESIZE     32
#define UT_NAMESIZE     32
#define UT_HOSTSIZE     256

typedef uint32 pid_t;

enum Type : uint8_t {
    EMPTY           = 0x0,
    RUN_LVL         = 0x1,
    BOOT_TIME       = 0x2,
    NEW_TIME        = 0x3,
    OLD_TIME        = 0x4,
    INIT_PROCESS    = 0x5,
    LOGIN_PROCESS   = 0x6,
    USER_PROCESS    = 0x7,
    DEAD_PROCESS    = 0x8,
    ACCOUNTING      = 0x9,
};

struct exit_status {
    uint16 e_termination;
    uint16 e_exit;
};

struct {
    uint32 tv_sec;
    uint32 tv_usec;
} timeval;

struct entry {
    uint32  ut_type;
    pid_t   ut_pid;
    char    ut_line[UT_LINESIZE];
    char    ut_id[4];
    char    ut_user[UT_NAMESIZE];
    char    ut_host[UT_HOSTSIZE];
    struct  exit_status ut_exit;
    long    ut_session;
    struct  timeval ut_tv;
    int32_t ut_addr_v6[4];         // Internet address of remote host; IPv4 address uses just ut_addr_v6[0]
    char    __unused[20];
};
"""

c_utmp = cstruct().load(utmp_def)


class UtmpRecord(NamedTuple):
    ts: datetime
    ts_logout: datetime | None  # utmpdb specific
    ut_type: str
    ut_user: str
    ut_pid: int | None
    ut_line: str
    ut_id: str | None
    ut_host: str
    ut_addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    ut_service: str | None  # utmpdb specific


class UtmpFile:
    """Parser for utmp files."""

    def __init__(self, path: Path):
        self.fh = open_decompress(path, "rb")

    def __iter__(self) -> Iterator[UtmpRecord]:
        while True:
            try:
                entry = c_utmp.entry(self.fh)

                r_type = ""
                if entry.ut_type in c_utmp.Type:
                    r_type = c_utmp.Type(entry.ut_type).name

                ut_host = entry.ut_host.decode(errors="surrogateescape").strip("\x00")
                ut_addr = None

                # UTMP misuses the field ut_addr_v6 for IPv4 and IPv6 addresses, because of this the ut_host field
                # is used to determine if the ut_addr_v6 is an IPv6 address where the last 12 bytes of trailing zeroes.
                if entry.ut_addr_v6:
                    if entry.ut_addr_v6[1:] != [0, 0, 0]:
                        # IPv6 address that uses > 4 bytes
                        ut_addr = ipaddress.ip_address(struct.pack("<4i", *entry.ut_addr_v6))
                    else:
                        try:
                            if isinstance(ipaddress.ip_address(ut_host), ipaddress.IPv6Address):
                                # IPv6 address that uses 4 bytes with 12 bytes of trailing zeroes.
                                ut_addr = ipaddress.ip_address(struct.pack("<4i", *entry.ut_addr_v6))
                            elif isinstance(ipaddress.ip_address(ut_host), ipaddress.IPv4Address):
                                # IPv4 address (ut_host, ut_addr_v6)
                                ut_addr = ipaddress.ip_address(struct.pack("<i", entry.ut_addr_v6[0]))
                            else:
                                pass
                        except ValueError:
                            # NOTE: in case the ut_host does not contain a valid IPv6 address,
                            # ut_addr_v6 is parsed as IPv4 address. This could not lead to incorrect results.
                            ut_addr = ipaddress.ip_address(struct.pack("<i", entry.ut_addr_v6[0]))

                yield UtmpRecord(
                    ts=from_unix(entry.ut_tv.tv_sec),
                    ts_logout=None,
                    ut_type=r_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user.decode(errors="surrogateescape").strip("\x00"),
                    ut_line=entry.ut_line.decode(errors="surrogateescape").strip("\x00"),
                    ut_id=entry.ut_id.decode(errors="surrogateescape").strip("\x00"),
                    ut_host=ut_host,
                    ut_addr=ut_addr,
                    ut_service=None,
                )

            except EOFError:  # noqa: PERF203
                break


class WtmpDbEntryType(IntEnum):
    """IntEnum of WtmpDb entry Types.

    This differs from utmp's Type enum as BOOT_TIME and RUNLEVEL are swapped
    and USER_PROCESS is 0x3 instead of 0x7.

    References:
        - https://github.com/thkukuk/wtmpdb/blob/main/include/wtmpdb.h
    """

    EMPTY = 0
    BOOT_TIME = 1
    RUN_LVL = 2  # called RUNLEVEL in wtmpdb.h, renamed for consistency with utmp
    USER_PROCESS = 3


class WtmpDbFile:
    """Parser for WtmpDb files.

    References:
        - https://github.com/thkukuk/wtmpdb
        - https://packages.debian.org/trixie/libpam-wtmpdb
    """

    def __init__(self, path: Path):
        self.path = path
        self.db = SQLite3(path)

    def __iter__(self) -> Iterator[UtmpRecord]:
        """Iterate over the ``wtmp`` SQLite3 table.

        References:
            - https://github.com/thkukuk/wtmpdb/blob/main/README.md#database
        """
        if not (table := self.db.table("wtmp")):
            return None

        for row in table.rows():
            yield UtmpRecord(
                ts=from_unix_us(row.Login),
                ts_logout=from_unix_us(row.Logout) if row.Logout else None,
                ut_type=WtmpDbEntryType(row.Type).name,
                ut_pid=None,
                ut_user=row.User,
                ut_line=row.TTY,
                ut_id=None,
                ut_host=row.RemoteHost or None,
                ut_addr=row.RemoteHost or None,
                ut_service=row.Service,
            )


class UtmpPlugin(Plugin):
    """Unix utmp log plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.btmp_paths = list(self.target.fs.path("/").glob("var/log/btmp*"))
        self.wtmp_paths = list(self.target.fs.path("/").glob("var/log/wtmp*")) + list(
            self.target.fs.path("/").glob("var/lib/wtmpdb/wtmp*")
        )
        self.utmp_paths = list(self.target.fs.path("/").glob("var/run/utmp*"))

    def check_compatible(self) -> None:
        if not any(self.btmp_paths + self.wtmp_paths + self.utmp_paths):
            raise UnsupportedPluginError("No wtmp and/or btmp log files found")

    def _build_record(
        self, record: TargetRecordDescriptor, entry: UtmpRecord, source: Path
    ) -> Iterator[BtmpRecord | WtmpRecord]:
        return record(
            ts=entry.ts,
            ts_logout=entry.ts_logout,
            ut_type=entry.ut_type,
            ut_pid=entry.ut_pid,
            ut_user=entry.ut_user,
            ut_line=entry.ut_line,
            ut_id=entry.ut_id,
            ut_host=entry.ut_host,
            ut_addr=entry.ut_addr,
            ut_service=entry.ut_service,
            source=source,
            _target=self.target,
        )

    @export(record=BtmpRecord)
    def btmp(self) -> Iterator[BtmpRecord]:
        """Return failed login attempts stored in the btmp file.

        On a Linux system, failed login attempts are stored in the btmp file located in the var/log/ folder.

        References:
            - https://en.wikipedia.org/wiki/Utmp
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        for path in self.btmp_paths:
            if not path.is_file():
                self.target.log.warning("Unable to parse btmp file: %s is not a file", path)
                continue

            for entry in UtmpFile(path):
                yield self._build_record(BtmpRecord, entry, path)

    @alias("utmp")
    @export(record=WtmpRecord)
    def wtmp(self) -> Iterator[WtmpRecord]:
        """Yield contents of wtmp and wtmpdb log files.

        The wtmp file contains the historical data of the utmp file. The utmp file contains information about users
        logins at which terminals, logouts, system events and current status of the system, system boot time
        (used by uptime) etc.

        References:
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        seen = set()

        for path in self.wtmp_paths + self.utmp_paths:
            if not path.is_file():
                self.target.log.warning("Unable to parse wtmp file: %s is not a file", path)
                continue

            if any(seen_path.samefile(path) for seen_path in seen):
                continue
            seen.add(path)

            iterator = WtmpDbFile if path.suffix == ".db" else UtmpFile
            for entry in iterator(path):
                yield self._build_record(WtmpRecord, entry, path)
