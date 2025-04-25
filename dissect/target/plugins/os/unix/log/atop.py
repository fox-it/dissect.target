from __future__ import annotations

import zlib
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

# The structs rawheader and rawrecord have added padding compared to the structs in the source code
# https://github.com/Atoptool/atop/blob/master/rawlog.h, https://github.com/Atoptool/atop/blob/master/photoproc.h
atop_def = """
typedef unsigned long long time_t;
typedef long long count_t;

#define  _UTSNAME_LENGTH  65

struct utsname {
    char  sysname[_UTSNAME_LENGTH];     /* Name of the implementation of the operating system. */
    char  nodename[_UTSNAME_LENGTH];    /* Name of this node on the network. */
    char  release[_UTSNAME_LENGTH];     /* Current release level of this implementation. */
    char  version[_UTSNAME_LENGTH];     /* Current version level of this release. */
    char  machine[_UTSNAME_LENGTH];     /* Name of the hardware type the system is running on. */
    char  domainname[_UTSNAME_LENGTH];  /* Name of the domain of this node on the network. */
};

struct rawheader {
    unsigned  int      magic;
    unsigned  short    aversion;        /* creator atop version with MSB */
    unsigned  short    future1;         /* can be reused */
    unsigned  short    future2;         /* can be reused */
    unsigned  short    rawheadlen;      /* length of struct rawheader */
    unsigned  short    rawreclen;       /* length of struct rawrecord */
    unsigned  short    hertz;           /* clock interrupts per second */
    unsigned  short    sfuture[6];      /* future use */
    unsigned  int      sstatlen;        /* length of struct sstat */
    unsigned  int      tstatlen;        /* length of struct tstat */
    struct    utsname  utsname;         /* info about this system  */
    char               cfuture[8];      /* future use */
    unsigned  int      pagesize;        /* size of memory page (bytes) */
    int                supportflags;    /* used features */
    int                osrel;           /* OS release number */
    int                osvers;          /* OS version number */
    int                ossub;           /* OS version subnumber */
    int                ifuture[6];      /* future use */
    uint16             padding;
};

struct rawrecord {
    time_t           curtime;           /* current time (epoch) */
    unsigned  short  flags;             /* various flags */
    unsigned  short  sfuture[3];        /* future use */
    unsigned  int    scomplen;          /* length of compressed sstat */
    unsigned  int    pcomplen;          /* length of compressed tstat's */
    unsigned  int    interval;          /* interval (number of seconds) */
    unsigned  int    ndeviat;           /* number of tasks in list */
    unsigned  int    nactproc;          /* number of processes in list */
    unsigned  int    ntask;             /* total number of tasks */
    unsigned  int    totproc;           /* total number of processes */
    unsigned  int    totrun;            /* number of running  threads */
    unsigned  int    totslpi;           /* number of sleeping threads(S) */
    unsigned  int    totslpu;           /* number of sleeping threads(D) */
    unsigned  int    totzomb;           /* number of zombie processes */
    unsigned  int    nexit;             /* number of exited processes */
    unsigned  int    noverflow;         /* number of overflow processes */
    unsigned  int    ifuture[6];        /* future use */
    int              padding;
};
"""
atop_tstat_def = """
#define  PNAMLEN  15
#define  CMDLEN   255

/* structure containing only relevant process-info extracted from kernel's process-administration */
struct tstat {
    /* GENERAL TASK INFO */
    struct gen {
        int     tgid;                   /* threadgroup identification */
        int     pid;                    /* process identification */
        int     ppid;                   /* parent process identification */
        int     ruid;                   /* real  user  identification */
        int     euid;                   /* eff.  user  identification */
        int     suid;                   /* saved user  identification */
        int     fsuid;                  /* fs    user  identification */
        int     rgid;                   /* real  group identification */
        int     egid;                   /* eff.  group identification */
        int     sgid;                   /* saved group identification */
        int     fsgid;                  /* fs    group identification */
        int     nthr;                   /* number of threads in tgroup */
        char    name[PNAMLEN+1];        /* process name string */
        char    isproc;                 /* boolean: process level? */
        char    state;                  /* process state ('E' = exited) */
        int     excode;                 /* process exit status */
        time_t  btime;                  /* process start time (epoch) */
        time_t  elaps;                  /* process elaps time (hertz) */
        char    cmdline[CMDLEN+1];      /* command-line string */
        int     nthrslpi;               /* # threads in state 'S' */
        int     nthrslpu;               /* # threads in state 'D' */
        int     nthrrun;                /* # threads in state 'R' */
        int     ctid;                   /* OpenVZ container ID */
        int     vpid;                   /* OpenVZ virtual PID */
        int     wasinactive;            /* boolean: task inactive */
        char    container[16];          /* Docker container id (12 pos) */
    } gen;

    /* CPU STATISTICS */
    struct cpu {
        count_t  utime;                 /* time user   text (ticks) */
        count_t  stime;                 /* time system text (ticks) */
        int      nice;                  /* nice value */
        int      prio;                  /* priority */
        int      rtprio;                /* realtime priority */
        int      policy;                /* scheduling policy */
        int      curcpu;                /* current processor */
        int      sleepavg;              /* sleep average percentage */
        int      ifuture[4];            /* reserved for future use */
        char     wchan[16];             /* wait channel string */
        count_t  rundelay;              /* schedstat rundelay (nanosec) */
        count_t  cfuture[1];            /* reserved for future use */
    } cpu;

    /* DISK STATISTICS */
    struct dsk {
        count_t  rio;                   /* number of read requests */
        count_t  rsz;                   /* cumulative # sectors read */
        count_t  wio;                   /* number of write requests */
        count_t  wsz;                   /* cumulative # sectors written */
        count_t  cwsz;                  /* cumulative # written sectors */
        count_t  cfuture[4];            /* reserved for future use */
    } dsk;

    /* MEMORY STATISTICS */
    struct mem {
        count_t  minflt;                /* number of page-reclaims */
        count_t  majflt;                /* number of page-faults */
        count_t  vexec;                 /* virtmem execfile (Kb) */
        count_t  vmem;                  /* virtual  memory  (Kb) */
        count_t  rmem;                  /* resident memory  (Kb) */
        count_t  pmem;                  /* resident memory  (Kb) */
        count_t  vgrow;                 /* virtual  growth  (Kb) */
        count_t  rgrow;                 /* resident growth  (Kb) */
        count_t  vdata;                 /* virtmem data     (Kb) */
        count_t  vstack;                /* virtmem stack    (Kb) */
        count_t  vlibs;                 /* virtmem libexec  (Kb) */
        count_t  vswap;                 /* swap space used  (Kb) */
        count_t  vlock;                 /* virtual locked   (Kb) */
        count_t  cfuture[3];            /* reserved for future use */
    } mem;

    /* NETWORK STATISTICS */
    struct net {
        count_t  tcpsnd;                /* number of TCP-packets sent */
        count_t  tcpssz;                /* cumulative size packets sent */
        count_t  tcprcv;                /* number of TCP-packets recved */
        count_t  tcprsz;                /* cumulative size packets rcvd */
        count_t  udpsnd;                /* number of UDP-packets sent */
        count_t  udpssz;                /* cumulative size packets sent */
        count_t  udprcv;                /* number of UDP-packets recved */
        count_t  udprsz;                /* cumulative size packets sent */
        count_t  avail1;
        count_t  avail2;
        count_t  cfuture[4];            /* reserved for future use */
    } net;

    struct gpu {
        char     state;                 /* A - active, E - Exit, '\0' - no use */
        char     cfuture[3];
        short    nrgpus;                /* number of GPUs for this process */
        int32_t  gpulist;               /* bitlist with GPU numbers */
        int      gpubusy;               /* gpu busy perc process lifetime      -1 = n/a */
        int      membusy;               /* memory busy perc process lifetime   -1 = n/a */
        count_t  timems;                /* milliseconds accounting -1 = n/a, value 0 for active process, value > 0 after termination */
        count_t  memnow;                /* current    memory consumption in KiB */
        count_t  memcum;                /* cumulative memory consumption in KiB */
        count_t  sample;                /* number of samples */
    } gpu;
};
"""  # noqa: E501

c_atop = cstruct().load(atop_def)
c_atop.load(atop_tstat_def, align=True)

AtopRecord = TargetRecordDescriptor(
    "linux/log/atop",
    [
        ("datetime", "ts"),
        ("string", "process"),
        ("string", "cmdline"),
        ("varint", "tgid"),
        ("varint", "pid"),
        ("varint", "ppid"),
        ("varint", "ruid"),
        ("varint", "euid"),
        ("varint", "suid"),
        ("varint", "fsuid"),
        ("varint", "rgid"),
        ("varint", "egid"),
        ("varint", "sgid"),
        ("varint", "fsgid"),
        ("varint", "nthr"),
        ("boolean", "isproc"),
        ("string", "state"),
        ("varint", "excode"),
        ("varint", "elaps"),
        ("varint", "nthrslpi"),
        ("varint", "nthrslpu"),
        ("varint", "nthrrun"),
        ("varint", "ctid"),
        ("varint", "vpid"),
        ("boolean", "wasinactive"),
        ("string", "container"),
        ("path", "filepath"),
    ],
)


class AtopFile:
    """Parse general task information of processes of an Atop log file."""

    def __init__(self, fh: BinaryIO):
        fh.seek(0)

        self.fh = fh
        self.header = c_atop.rawheader(self.fh)
        self.version = self.version()

    def __iter__(self) -> Iterator[c_atop.tstat]:
        while True:
            try:
                record = c_atop.rawrecord(self.fh)
                # system level statistics is not parsed
                self.fh.read(record.scomplen)
                process = self.decompress(self.fh.read(record.pcomplen))
                for _ in range(record.ndeviat):
                    yield c_atop.tstat(process)
            except EOFError:  # noqa: PERF203
                break

    def decompress(self, data: bytes) -> bytes:
        return BytesIO(zlib.decompress(data))

    def version(self) -> str:
        major_version = (self.header.aversion >> 8) & 0x7F
        minor_version = self.header.aversion & 0xFF
        return f"{major_version}.{minor_version}"


class AtopPlugin(Plugin):
    """Unix atop plugin."""

    ATOP_GLOB = "atop_*"
    ATOP_MAGIC = 0xFEEDBEEF
    ATOP_PATH = "/var/log/atop"
    ATOP_VERSIONS = ("2.6", "2.7")

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.ATOP_PATH).exists():
            raise UnsupportedPluginError("No ATOP files found")

    @export(record=AtopRecord)
    def atop(self) -> Iterator[AtopRecord]:
        """Return the content of Atop log files.

        An Atop log file contains the activity of all processes that were running during the interval.
        This includes system-level activity related to the CPU, memory, swap, disks and network layers,
        and for every process (and thread) it shows e.g. the CPU utilization, memory growth, disk utilization,
        priority, username, state, and exit code.

        References:
            - https://diablohorn.com/2022/11/17/parsing-atop-files-with-python-dissect-cstruct/

        Yields AtopRecord with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            process (string): The process name.
            cmdline (string): The command-line of the process.
            tgid (varint): The threadgroup of the process
            pid (varint): The proccess identifier of the process.
            ppid (varint): The proccess identifier of the parent-process.
            ruid (varint): The ruid of the process.
            euid (varint): The euid of the process.
            suid (varint): The suid of the process.
            fsuid (varint): The fsuid of the process.
            rgid (varint): The rgid of the process.
            egid (varint): The egid of the process.
            sgid (varint): The sgid of the process.
            fsgid (varint): The fsgid of the process.
            nthr (varint): The nthr of the process.
            isproc (boolean). The process-level of the process.
            state (string). The state of the process.
            excode (varint): The exit-code of the process.
            elaps (varint): The elapsed time of the process.
            nthrslpi (varint): The threads in state 'S' of the process.
            nthrslpu (varint): The threads in state 'D' of the process.
            nthrrun (varint): The threads in state 'R' of the process.
            ctid (varint): The OpenVZ container ID of the process.
            vpid (varint): The OpenVZ virtual pid of the process.
            wasinactive (boolean): The activity of the process.
            container (string): The Docker Container ID of the process.
            filepath (path): The file name.
        """
        for file in self.target.fs.path(self.ATOP_PATH).glob(self.ATOP_GLOB):
            fh = file.open()

            atop_magic = int.from_bytes(fh.read(4), "little")

            if atop_magic != self.ATOP_MAGIC:
                self.target.log.warning("The Atop log file %s has an invalid magic header", file.name)
                continue

            atop = AtopFile(fh)

            if atop.version not in self.ATOP_VERSIONS:
                self.target.log.warning(
                    "The version %s of the Atop log file %s is incompatible",
                    atop.version,
                    file.name,
                )
                continue

            for entry in atop:
                yield AtopRecord(
                    ts=entry.gen.btime,
                    process=entry.gen.name.decode().strip("\x00"),
                    cmdline=entry.gen.cmdline.decode().strip("\x00"),
                    tgid=entry.gen.tgid,
                    pid=entry.gen.pid,
                    ppid=entry.gen.ppid,
                    ruid=entry.gen.ruid,
                    euid=entry.gen.euid,
                    suid=entry.gen.suid,
                    fsuid=entry.gen.fsuid,
                    rgid=entry.gen.rgid,
                    egid=entry.gen.egid,
                    sgid=entry.gen.sgid,
                    fsgid=entry.gen.fsgid,
                    nthr=entry.gen.nthr,
                    isproc=int.from_bytes(entry.gen.isproc, "little"),
                    state=entry.gen.state.decode().strip("\x00"),
                    excode=entry.gen.excode,
                    elaps=entry.gen.elaps,
                    nthrslpi=entry.gen.nthrslpi,
                    nthrslpu=entry.gen.nthrslpu,
                    nthrrun=entry.gen.nthrrun,
                    ctid=entry.gen.ctid,
                    vpid=entry.gen.vpid,
                    wasinactive=entry.gen.wasinactive,
                    container=entry.gen.container.decode().strip("\x00"),
                    filepath=file,
                    _target=self.target,
                )
