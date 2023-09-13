import gzip
import ipaddress
import struct
from collections import namedtuple
from typing import Iterator

from dissect.cstruct import cstruct
from dissect.util.stream import BufferedStream
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, export
from dissect.target.target import Target

UTMP_FIELDS = [
    ("datetime", "ts"),
    ("string", "ut_type"),
    ("string", "ut_user"),
    ("varint", "ut_pid"),
    ("string", "ut_line"),
    ("string", "ut_id"),
    ("string", "ut_host"),
    ("net.ipaddress", "ut_addr"),
]

BtmpRecord = TargetRecordDescriptor(
    "linux/log/btmp",
    [
        *UTMP_FIELDS,
    ],
)

WtmpRecord = TargetRecordDescriptor(
    "linux/log/wtmp",
    [
        *UTMP_FIELDS,
    ],
)

c_utmp = """
#define UT_LINESIZE     32
#define UT_NAMESIZE     32
#define UT_HOSTSIZE     256

typedef uint32 pid_t;

enum Type : char {
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
"""  # noqa: E501

utmp = cstruct()
utmp.load(c_utmp)

UTMP_ENTRY = namedtuple(
    "UTMPRecord",
    [
        "ts",
        "ut_type",
        "ut_user",
        "ut_pid",
        "ut_line",
        "ut_id",
        "ut_host",
        "ut_addr",
    ],
)


class UtmpFile:
    """utmp maintains a full accounting of the current status of the system"""

    def __init__(self, target: Target, path: TargetPath):
        self.fh = target.fs.path(path).open()

        if "gz" in path:
            self.compressed = True
        else:
            self.compressed = False

    def __iter__(self):
        if self.compressed:
            gzip_entry = BufferedStream(gzip.open(self.fh, mode="rb"))
            byte_stream = gzip_entry
        else:
            byte_stream = self.fh

        while True:
            try:
                entry = utmp.entry(byte_stream)

                r_type = ""
                if entry.ut_type in utmp.Type.reverse:
                    r_type = utmp.Type.reverse[entry.ut_type]

                ut_host = entry.ut_host.decode(errors="surrogateescape").strip("\x00")
                ut_addr = None

                # UTMP misuses the field ut_addr_v6 for IPv4 and IPv6 addresses, because of this the ut_host field
                # is used to determine if the ut_addr_v6 is an IPv6 address where the last 12 bytes of trailing zeroes.
                if entry.ut_addr_v6:
                    if not entry.ut_addr_v6[1:] == [0, 0, 0]:
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

                utmp_entry = UTMP_ENTRY(
                    ts=from_unix(entry.ut_tv.tv_sec),
                    ut_type=r_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user.decode(errors="surrogateescape").strip("\x00"),
                    ut_line=entry.ut_line.decode(errors="surrogateescape").strip("\x00"),
                    ut_id=entry.ut_id.decode(errors="surrogateescape").strip("\x00"),
                    ut_host=ut_host,
                    ut_addr=ut_addr,
                )

                yield utmp_entry
            except EOFError:
                break


class UtmpPlugin(Plugin):
    WTMP_GLOB = "/var/log/wtmp*"
    BTMP_GLOB = "/var/log/btmp*"

    def check_compatible(self) -> None:
        if not self.target.os == OperatingSystem.LINUX and not any(
            [
                list(self.target.fs.glob(self.BTMP_GLOB)),
                list(self.target.fs.glob(self.WTMP_GLOB)),
            ]
        ):
            raise UnsupportedPluginError("No WTMP or BTMP log files found")

    @export(record=[BtmpRecord])
    def btmp(self) -> Iterator[BtmpRecord]:
        """Return failed login attempts stored in the btmp file.

        On a Linux system, failed login attempts are stored in the btmp file located in the var/log/ folder.

        References:
            - https://en.wikipedia.org/wiki/Utmp
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        btmp_paths = self.target.fs.glob(self.BTMP_GLOB)
        for btmp_path in btmp_paths:
            btmp = UtmpFile(self.target, btmp_path)

            for entry in btmp:
                yield BtmpRecord(
                    ts=entry.ts,
                    ut_type=entry.ut_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user,
                    ut_line=entry.ut_line,
                    ut_id=entry.ut_id,
                    ut_host=entry.ut_host,
                    ut_addr=entry.ut_addr,
                    _target=self.target,
                )

    @export(record=[WtmpRecord])
    def wtmp(self) -> Iterator[WtmpRecord]:
        """Return the content of the wtmp log files.

        The wtmp file contains the historical data of the utmp file. The utmp file contains information about users
        logins at which terminals, logouts, system events and current status of the system, system boot time
        (used by uptime) etc.

        References:
            - https://www.thegeekdiary.com/what-is-the-purpose-of-utmp-wtmp-and-btmp-files-in-linux/
        """
        wtmp_paths = self.target.fs.glob(self.WTMP_GLOB)
        for wtmp_path in wtmp_paths:
            wtmp = UtmpFile(self.target, wtmp_path)

            for entry in wtmp:
                yield WtmpRecord(
                    ts=entry.ts,
                    ut_type=entry.ut_type,
                    ut_pid=entry.ut_pid,
                    ut_user=entry.ut_user,
                    ut_line=entry.ut_line,
                    ut_id=entry.ut_id,
                    ut_host=entry.ut_host,
                    ut_addr=entry.ut_addr,
                    _target=self.target,
                )
