import gzip
import ipaddress
import struct
from collections import namedtuple

from dissect.cstruct import cstruct
from dissect.util.stream import BufferedStream
from dissect.util.ts import from_unix

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

    def __init__(self, fh, compressed=False):
        self.fh = fh
        self.compressed = compressed

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

                # UTMP misuses the field ut_addr_v6 for IPv4 and IPv6 addresses, because of this
                # the ut_host field is used to determine if the ut_addr_v6 is an IPv6 address
                # where the last 12 bytes are zeroes.
                if entry.ut_addr_v6:
                    if not entry.ut_addr_v6[1:] == [0, 0, 0]:
                        # IPv6 address
                        ut_addr = ipaddress.ip_address(struct.pack("<4i", *entry.ut_addr_v6))
                    else:
                        try:
                            if isinstance(ipaddress.ip_address(ut_host), ipaddress.IPv6Address):
                                # IPv6 address with 12 bytes of trailing zeroes
                                # If the host contains a valid IPv6 address, the full entry_addr_v6 field is parsed
                                # instead of the first 4 bytes.
                                ut_addr = ipaddress.ip_address(struct.pack("<4i", *entry.ut_addr_v6))
                            else:
                                # IPv4 address
                                ut_addr = ipaddress.ip_address(struct.pack("<i", entry.ut_addr_v6[0]))
                        except ValueError:
                            # IPv4 address
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
