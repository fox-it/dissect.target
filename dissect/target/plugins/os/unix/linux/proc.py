from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum
from functools import cached_property
from ipaddress import IPv4Address, IPv6Address
from socket import htonl
from struct import pack, unpack
from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import fsutil
from dissect.target.helpers.utils import StrEnum
from dissect.target.plugin import Plugin, internal

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.target import Target


def parse_ip(addr: str | int, version: int = 4) -> IPv6Address | IPv4Address:
    """Convert ``/proc/net`` IPv4 or IPv6 hex address into their standard IP notation."""

    if version == 6:
        addr = unpack("!LLLL", bytes.fromhex(addr))
        return IPv6Address(pack("@IIII", *addr))

    if isinstance(addr, int):
        return IPv4Address(htonl(addr))

    addr = int(addr, 16)
    return IPv4Address(htonl(addr))


# Labels are borrowed from https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
@dataclass(order=True)
class NetSocket:
    sl: str  # number of entry
    local_address: str  # local IPv4 or IPv6 address
    rem_address: str  # remote IPv4 or IPv6 address
    state: str  # connection state
    tx_rx_queue: str  # transmit and receive-queue
    tr_tm_when: str  # timer_active and number of jiffies until timer expires
    restansmit: str  # number of unrecovered RTO timeouts
    uid: int  # uid
    timeout: str  # unanswered 0-window probes
    inode: int  # inode
    ref: str | None = None  # socket reference count
    pointer: str | None = None  # location of socket in memory
    drops: str | None = None  # retransmit timeout
    predicted_tick: str | None = None  # predicted tick of soft slock (delayed ACK control data)
    ack_pingpong: str | None = None  # ack.quick<<1|ack.pingpong
    congestion_window: str | None = None  # sending congestion window
    size_threshold: str | None = None  # slow start size threshhold or -f if the threshold is >= 0xFFFF

    # Values parsed from raw values listed above.
    protocol_string: str | None = None
    local_ip: str | None = None  # parsed value from local_address
    local_port: int | None = None  # parsed value from local_address
    remote_ip: str | None = None  # parsed value from rem_address
    remote_port: int | None = None  # parsed value from rem_address
    state_string: str | None = None  # parsed value from state
    owner: str | None = None  # resolved owner name of the socket, else "0".
    rx_queue: int | None = None  # parsed value from tx_rx_queue
    tx_queue: int | None = None  # parsed value from tx_rx_queue
    pid: int | None = None  # pid of the socket
    name: str | None = None  # process name associated to the socket
    cmdline: str | None = None  # process cmdline associated to the socket

    @classmethod
    def from_line(cls, line: str, ip_vers: int = 4) -> Self:
        socket = cls(*line.split())

        socket.uid = int(socket.uid)
        socket.inode = int(socket.inode)
        socket.tx_queue, socket.rx_queue = [int(queue, 16) for queue in socket.tx_rx_queue.split(":")]
        socket.local_ip, socket.local_port = socket.local_address.split(":")
        socket.remote_ip, socket.remote_port = socket.rem_address.split(":")

        socket.local_ip = parse_ip(socket.local_ip, ip_vers)
        socket.local_port = int(socket.local_port, 16)
        socket.remote_ip = parse_ip(socket.remote_ip, ip_vers)
        socket.remote_port = int(socket.remote_port, 16)

        return socket


@dataclass(order=True)
class UnixSocket:
    num: str  # the kernel table slot number
    ref: int  # the number of users of the socket
    protocol: int  # currently always 0. "Unix"
    flags: str  # the internal kernel flags holding the status of the socket
    type: int  # the socket type: 1 for SOCK_STREAM, 2 for SOCK_DGRAM and 5 for SOCK_SEQPACKET sockets
    state: int  # the internal state of the socket
    inode: int  # the inode number of the socket. the inode is commonly refered to as port in tools as ss and netstat
    path: str | None = None  # sockets in the abstract namespace are included in the list,
    # and are shown with a Path that commences with the character '@'

    # Values parsed from raw values listed above.
    state_string: str | None = None
    stream_type_string: str | None = None
    protocol_string: str = "unix"

    @classmethod
    def from_line(cls, line: str) -> Self:
        socket = cls(*line.split())

        socket.type = int(socket.type)
        socket.protocol = int(socket.protocol)
        socket.state = int(socket.state, 16)
        socket.ref = int(socket.ref, 16)
        socket.inode = int(socket.inode)

        return socket


@dataclass(order=True)
class PacketSocket:
    sk: int  # socket number
    ref: int  # the number of processes using this socket
    type: int  # type of the socket
    protocol: int  # protocol used by the socket to capture ie. 0003 is ETH_P_ALL
    iface: int  # network interface index
    r: int  # number of bytes that have been received by the socket and are waiting to be processed
    rmem: int  # receive window memory
    user: int  # uid from the owner of the socket
    inode: int  # inode

    # Values parsed from raw values listed above
    pid: int | None = None  # pid of the socket
    name: str | None = None  # process name associated to the socket
    cmdline: str | None = None  # process cmdline associated to the socket
    protocol_type: int | None = None  # value parsed from protocol field
    owner: str | None = None  # resolved owner from user (uid) field
    protocol_string: str = "packet"

    @classmethod
    def from_line(cls, line: str) -> Self:
        parts = line.split()
        return cls(*[int(parts[0], 16), *list(map(int, parts[1:]))])


@dataclass
class Environ:
    variable: str
    contents: str


class ProcessStateEnum(StrEnum):
    R = "Running"  # Running
    I = "Idle"  # Idle # noqa: E741
    S = "Sleeping"  # Sleeping in an interruptible wait
    D = "Waiting"  # Waiting in uninterruptible disk sleep
    Z = "Zombie"  # Zombie
    T = "Stopped"  # Stopped (on a signal) or (before Linux 2.6.33) trace stopped
    t = "Tracing"  # Tracing stop (Linux 2.6.33 onward)
    X = "Dead"  # Dead (from Linux 2.6.0 onward)
    x = "Dead"  # Dead (Linux 2.6.33 to 3.13 only)
    K = "Wakekill"  # Wakekill (Linux 2.6.33 to 3.13 only)
    W = "Waking"  # Waking (Linux 2.6.33 to 3.13 only)
    P = "Parked"  # Parked (Linux 3.9 to 3.13 only)
    N = "None"  # Sentinel value in-case a process' state file is not present


PROC_STAT_NAMES = [
    "pid",
    "comm",  # Process name
    "state",
    "ppid",
    "pgrp",
    "session",
    "tty_nr",
    "tpgid",
    "flags",
    "minflt",
    "cminflt",
    "majflt",
    "cmajflt",
    "utime",
    "stime",
    "cutime",
    "cstime",
    "priority",
    "nice",
    "num_threads",
    "itrealvalue",
    "starttime",
    "vsize",
    "rss",
    "rsslim",
    "startcode",
    "endcode",
    "startstack",
    "kstkesp",
    "kstkeip",
    "signal",
    "blocked",
    "sigignore",
    "sigcatch",
    "wchan",
    "nswap",
    "cnswap",
    "exit_signal",
    "processor",
    "rt_priority",
    "policy",
    "delayacct_blkio_ticks",
    "guest_time",
    "cguest_time",
    "start_data",
    "end_data",
    "start_brk",
    "arg_start",
    "arg_end",
    "env_start",
    "env_end",
    "exit_code",
]


class Sockets:
    class PacketProtocolTypes(IntEnum):
        ETH_P_802_3 = 0x0001  # Dummy type for 802.3 frames
        ETH_P_AX25 = 0x0002  # Dummy protocol id for AX.25
        ETH_P_ALL = 0x0003  # Every packet (be careful!!!)
        ETH_P_802_2 = 0x0004  # 802.2 frames
        ETH_P_SNAP = 0x0005  # Internal only
        ETH_P_DDCMP = 0x0006  # DEC DDCMP: Internal only
        ETH_P_WAN_PPP = 0x0007  # Dummy type for WAN PPP frames
        ETH_P_PPP_MP = 0x0008  # Dummy type for PPP MP frames
        ETH_P_LOCALTALK = 0x0009  # Localtalk pseudo type
        ETH_P_CAN = 0x000C  # Controller Area Network
        ETH_P_PPPTALK = 0x0010  # Dummy type for Atalk over PPP
        ETH_P_TR_802_2 = 0x0011  # 802.2 frames
        ETH_P_MOBITEX = 0x0015  # Mobitex (kaz@cafe.net)
        ETH_P_CONTROL = 0x0016  # Card specific control frames
        ETH_P_IRDA = 0x0017  # Linux-IrDA
        ETH_P_ECONET = 0x0018  # Acorn Econet
        ETH_P_HDLC = 0x0019  # HDLC frames
        ETH_P_ARCNET = 0x001A  # 1A for ArcNet :-)
        ETH_P_DSA = 0x001B  # Distributed Switch Arch.
        ETH_P_TRAILER = 0x001C  # Trailer switch tagging
        ETH_P_PHONET = 0x00F5  # Nokia Phonet frames
        ETH_P_IEEE802154 = 0x00F6  # IEEE802.15.4 frame

    class SocketStreamType(IntEnum):
        STREAM = 1
        DGRAM = 2
        SEQPACKET = 5

    class SocketStateType(IntEnum):
        LISTENING = 1
        CONNECTED = 3

    class TCPStates(IntEnum):
        DUMMY = 0
        ESTABLISHED = 1
        SYN_SENT = 2
        SYN_RECV = 3
        FIN_WAIT1 = 4
        FIN_WAIT2 = 5
        TIME_WAIT = 6
        CLOSE = 7
        CLOSE_WAIT = 8
        LAST_ACK = 9
        LISTEN = 10
        CLOSING = 11
        NEW_SYN_RECV = 12
        MAX_STATES = 13

    class UDPStates(IntEnum):
        DUMMY = 0
        ESTABLISHED = 1
        LISTEN = 7

    def __init__(self, target: Target):
        self.target = target

    def packet(self) -> Iterator[PacketSocket]:
        """Yield parsed ``/proc/net/packet`` entries."""
        yield from self._parse_packet_sockets()

    def raw(self) -> Iterator[NetSocket]:
        """Yield parsed ``/proc/net/raw`` entries."""
        yield from self._parse_net_sockets("raw")

    def raw6(self) -> Iterator[NetSocket]:
        """Yield parsed ``/proc/net/raw6`` entries."""
        yield from self._parse_net_sockets("raw", 6)

    def tcp6(self) -> Iterator[NetSocket]:
        """Yield parsed ``/proc/net/tcp6`` entries."""
        yield from self._parse_net_sockets("tcp", 6)

    def tcp(self) -> Iterator[NetSocket]:
        """Yield parsed ``/proc/net/tcp`` entries."""
        yield from self._parse_net_sockets("tcp")

    def udp(self) -> Iterator[NetSocket]:
        """Yield parsed ``/proc/net/upd`` entries."""
        yield from self._parse_net_sockets("udp")

    def udp6(self) -> Iterator[NetSocket]:
        """Yield parsed ``/proc/net/udp6`` entries."""
        yield from self._parse_net_sockets("udp", 6)

    def unix(self) -> Iterator[UnixSocket]:
        """Yield parsed ``/proc/net/unix`` entries."""
        yield from self._parse_unix_sockets()

    def _parse_net_sockets(self, protocol: str = "tcp", version: int = 4) -> Iterator[NetSocket]:
        """Internal function to parse ``/proc/net/{tcp(6),udp(6), raw(6)}`` entries.

        Args:
            protocol: The protocol in ``/proc/net/`` to parse entries from.
            version: The version of the protocol to parse entries from.
        """

        entry = self.target.fs.path(f"/proc/net/{protocol}{version if version == 6 else ''}")

        contents = entry.open("rt")

        # Skip over the header row
        contents.readline()
        for line in contents:
            if not (line := line.strip()):
                continue

            socket = NetSocket.from_line(line, version)
            socket.protocol_string = entry.name

            if socket.protocol_string in ("udp", "raw", "udp6", "raw6"):
                socket.state_string = self.UDPStates(int(socket.state, 16)).name
            else:
                socket.state_string = self.TCPStates(int(socket.state, 16)).name

            user = self.target.user_details.find(uid=socket.uid)
            user_name = user.user.name if user else str(socket.uid)
            socket.owner = user_name

            # inode 0 could indicate a kernel process, which has no assiciated PID or FDs in /proc
            # or a inode of 0 could mean the socket is in a TIME_WAIT state.
            if socket.inode == 0:
                socket.pid = socket.inode
                yield socket
            else:
                processes = self.target.proc.inode_to_pids(socket.inode)

                for process in processes:
                    socket.pid = process.pid
                    socket.name = process.name
                    socket.cmdline = process.cmdline
                    yield socket

    def _parse_unix_sockets(self) -> Iterator[UnixSocket]:
        """Internal function to parse ``/proc/net/unix`` entries."""

        entry = self.target.fs.path("/proc/net/unix")
        contents = entry.open("rt")

        # Skip over the header row
        contents.readline()
        for line in contents:
            if not line.strip():
                continue

            socket = UnixSocket.from_line(line)

            socket.stream_type_string = self.SocketStreamType(socket.type).name
            socket.state_string = self.SocketStateType(socket.state).name

            yield socket

    def _parse_packet_sockets(self) -> Iterator[PacketSocket]:
        """Internal function to parse ``/proc/net/packet`` entries."""
        entry = self.target.fs.path("/proc/net/packet")
        contents = entry.open("rt")

        # Skip over the header row
        contents.readline()
        for line in contents:
            if not (line := line.strip()):
                continue

            socket = PacketSocket.from_line(line)

            processes = self.target.proc.inode_to_pids(socket.inode)

            socket.protocol_type = self.PacketProtocolTypes(socket.protocol).name

            user = self.target.user_details.find(uid=socket.user)
            user_name = user.user.name if user else str(socket.user)
            socket.owner = user_name

            for proc in processes:
                socket.pid = proc.pid
                socket.name = proc.name
                socket.cmdline = proc.cmdline
                yield socket


class ProcProcess:
    def __init__(self, target: Target, pid: int | str, proc_root: str = "/proc"):
        self.target = target
        self.root = proc_root
        self._pid = int(pid)

        # Note: ttys and pttys are not yet mapped to the process
        if self._pid == 0:
            # The process with PID 0 is responsible for paging and is referred to as the "swapper" or "sched" process.
            # It is a part of the kernel and is not a regular user-mode process.
            self.name = "swapper"
        else:
            self.entry = target.fs.path(fsutil.join(self.root, str(pid)))
            if not self.entry.exists():
                raise ProcessLookupError(f"Process with PID {pid} could not be found on target: {target}")

            self._stat_file = self._parse_proc_stat_entry()
            self.name = self._process_name

    def _parse_proc_status_entry(self) -> dict[str, str]:
        """Internal function to parse the contents of ``/proc/[pid]/status``."""
        status = self.get("status").open("rt")
        status_dict = {}

        for line in status.readlines():
            key, value = line.split(":", maxsplit=1)
            key = key.lower().strip()
            value = value.strip()
            status_dict[key] = value

        return status_dict

    def _parse_proc_stat_entry(self) -> dict[str, str | int]:
        """Internal function to parse the contents of ``/proc/[pid]/stat``."""
        status_dict = {}
        entry = self.get("stat")

        if entry.exists():
            status = entry.open("rt").readline()

            # The process name exists between parentheses in the second field.
            # Since the name can be arbitrary we have to find the first and last parentheses.
            start_name, end_name = status.find("("), status.rfind(")")

            head = status[:start_name]
            tail = status[end_name:]
            name = status[start_name + 1 : end_name]
            status = head + tail

            for idx, part in enumerate(status.split()[: len(PROC_STAT_NAMES)]):
                try:
                    part = int(part)
                except ValueError:
                    part = part

                status_dict[PROC_STAT_NAMES[idx]] = part

            status_dict["comm"] = name

        return status_dict

    def _parse_environ(self) -> Iterator[Environ]:
        """Internal function to parse entries in ``/proc/[pid]/environ``."""
        # entries in /proc/<pid>/environ are null-terminated
        lines = self.get("environ").read_text().split("\x00")

        for line in lines:
            if line == "":
                # Skip empty line
                continue

            try:
                variable, contents = line.split("=", maxsplit=1)
            except ValueError:
                # Convention tells us that variable names and values are split on '='
                # in practice this is not always the case.
                variable = None
                contents = line

            yield Environ(variable, contents)

    @property
    def _boottime(self) -> int:
        """Returns the boot time of the system.

        Used internally to determine process start- and runtimes.
        """
        for line in self.target.fs.path(self.root).joinpath("stat").open("rt").readlines():
            if not line.startswith("btime"):
                continue

            return int(line.split()[1])
        return None

    def get(self, path: str) -> Path:
        """Returns a TargetPath relative to this process."""
        return self.entry.joinpath(path)

    @property
    def owner(self) -> str:
        """Return the username or the user ID (uid) (if owner is not found) of the owner of this process."""
        if self.uid:
            owner = self.target.user_details.find(uid=self.uid)
            return owner.user.name

        return str(self.uid)

    @property
    def uid(self) -> int:
        """Return the user ID (uid) of the owner of this process."""
        uid = int(self.get("loginuid").read_bytes())
        # loginuid can hold the value "4294967295" (0xFFFFFFFF).
        # Which is defined as "not set" and -1 should be returned.
        return -1 if uid == 0xFFFFFFFF else uid

    @property
    def pid(self) -> int:
        """Returns the process ID (pid) associated to this process."""
        return self._pid

    @property
    def parent(self) -> ProcProcess | None:
        """Returns the parent :class:`ProcProcess` of this process."""
        if self.pid == 0:
            return None
        return ProcProcess(self.target, self._stat_file.get("ppid"))

    @property
    def ppid(self) -> int | None:
        """Returns the parent process ID (ppid) associated to this process."""
        if parent := self.parent:
            return parent.pid
        return None

    @property
    def parent_name(self) -> str | None:
        """Returns the name associated to the parent process ID (ppid) of this process."""
        if parent := self.parent:
            return parent.name
        return None

    @property
    def state(self) -> str:
        """Returns the state of the process (S'leeping, R'unning, I'dle, etc)."""
        return ProcessStateEnum[self._stat_file.get("state", "N")].value

    @property
    def starttime(self) -> datetime:
        """Returns the start time of the process."""
        # Starttime is saved in clockticks per second from the boot time.
        # we asume a standard of 100 clockticks per second. the actual value can be obtained from `getconf CLK_TCK`
        starttime = self._stat_file.get("starttime", 0) / 100

        return from_unix(self._boottime + starttime)

    @property
    def runtime(self) -> timedelta:
        """Returns the runtime of a process until the moment of acquisition."""
        return self.now - self.starttime

    @property
    def now(self) -> datetime:
        """Returns the ``now()`` timestamp of the system at the moment of acquisition."""
        return self.uptime + from_unix(self._boottime)

    def environ(self) -> Iterator[Environ]:
        """Yields the content of the environ file associated with the process."""
        yield from self._parse_environ()

    @property
    def uptime(self) -> timedelta:
        """Returns the uptime of the system from the moment it was acquired."""
        # uptime is saved in seconds from boottime
        uptime = self.target.fs.path(self.root).joinpath("uptime").read_text().split()[0]
        return timedelta(seconds=float(uptime))

    @property
    def _process_name(self) -> str:
        """Internal function that returns the name of the process."""
        return self._stat_file.get("comm", "")

    @property
    def cmdline(self) -> str:
        """Return the command line of a process."""

        line = ""
        entry = self.get("cmdline")

        if entry.exists():
            line = entry.read_text()
            # Cmdlines are null-terminated and use null-bytes to separate the different parts. Translate this back.
            line = line.rstrip("\x00").replace("\x00", " ")

        return line

    def stat(self) -> fsutil.stat_result:
        """Return a stat entry of the process."""
        return self.entry.stat()


class ProcPlugin(Plugin):
    __namespace__ = "proc"

    def __init__(self, target: Target):
        super().__init__(target)
        self.sockets = Sockets(self.target)

    def check_compatible(self) -> None:
        # The /proc folder can exist on live targets, but is empty.
        # So we make the check a little more specific using next()
        if not self.target.fs.exists("/proc") or not next(self.target.fs.iterdir("/proc"), False):
            raise UnsupportedPluginError("No /proc directory found")

    @cached_property
    def inode_map(self) -> dict[int, list[ProcProcess]]:
        """Creates a inode to pid mapping for all process IDs in ``/proc/[pid]``."""
        map = defaultdict(list)

        for path in self.iter_proc():
            if (fdpath := path.joinpath("fd")).exists():
                for fd in fdpath.iterdir():
                    link = fd.readlink().as_posix()

                    if link.startswith("socket:["):
                        _, inode = link.split(":")  # socket type, inode

                        # strip brackets from fd string (socket:[1337])
                        inode = int(inode[1:-1])
                        map[inode].append(ProcProcess(self.target, path.name))

        return map

    @internal
    def iter_proc(self) -> Iterator[Path]:
        """Yields ``/proc/[pid]`` filesystems entries for every process id (pid) found in procfs."""
        yield from self.target.fs.path("/proc").glob("[0-9]*")

    @internal
    def inode_to_pids(self, inode: int) -> list[ProcProcess]:
        return self.inode_map.get(inode, [])

    @internal
    def process(self, pid: int | str) -> ProcProcess:
        return ProcProcess(self.target, pid)

    @internal
    def processes(self) -> Iterator[ProcProcess]:
        for path in self.iter_proc():
            yield ProcProcess(self.target, path.name)
