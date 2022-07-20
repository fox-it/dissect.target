import gzip

from dissect import cstruct
from dissect.util.stream import BufferedStream

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
    int32_t ut_addr_v6[4];
    char    __unused[20];
};
"""

utmp = cstruct.cstruct()
utmp.load(c_utmp)


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
                yield utmp.entry(byte_stream)
            except EOFError:
                break
