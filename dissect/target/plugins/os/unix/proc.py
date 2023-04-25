from __future__ import annotations

from codecs import decode
from collections import defaultdict
from ctypes import c_int32
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from enum import IntEnum
from ipaddress import IPv4Address, IPv6Address
from socket import htonl
from struct import pack, unpack
from typing import Iterator, Tuple, Union

from dissect.util.ts import from_unix

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.filesystem import FilesystemEntry, fsutil
from dissect.target.helpers.utils import StrEnum
from dissect.target.plugin import Plugin, internal
from dissect.target.target import Target


# Labels are borrowed from https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
@dataclass(order=True, init=False)
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
    ref: str | None  # socket reference count
    pointer: str | None  # location of socket in memory
    drops: str | None  # retransmit timeout
    predicted_tick: str | None  # predicted tick of soft slock (delayed ACK control data)
    ack_pingpong: str | None  # ack.quick<<1|ack.pingpong
    congestion_window: str | None  # sending congestion window
    size_threshold: str | None  # slow start size threshhold or -f if the threshold is >= 0xFFFF

    # Values parsed from raw values listed above.
    protocol_string: str
    local_ip: IPv4Address | IPv6Address  # parsed value from local_address
    local_port: int  # parsed value from local_address
    remote_ip: IPv4Address | IPv6Address  # parsed value from rem_address
    remote_port: int  # parsed value from rem_address
    state_string: str  # parsed value from state
    owner: str  # resolved owner name of the socket, else "0".
    rx_queue: int  # parsed value from tx_rx_queue
    tx_queue: int  # parsed value from tx_rx_queue
    pid: int  # pid of the socket
    name: str  # process name associated to the socket
    cmdline: str  # process cmdline associated to the socket

    def __init__(self):
        for fld in fields(self):
            setattr(self, fld.name, None)

    def from_line(self, line: str) -> NetSocket:
        splits = line.split()

        # The lines in /proc/net/[protocol] can be of arbitrary column (split) length, but are ordered.
        # So we use the fields(NetSocket) to dynamically fill the NetSockt dataclass.
        for idx, value in enumerate(splits):
            field_names = fields(self)
            setattr(self, field_names[idx].name, value)

        self.uid = int(self.uid)
        self.inode = int(self.inode)
        self.tx_queue, self.rx_queue = [int(queue, 16) for queue in self.tx_rx_queue.split(":")]
        self.local_port, self.remote_port = [
            int(port, 16) for port in (self.local_address.split(":")[1], self.rem_address.split(":")[1])
        ]

        return self


@dataclass(order=True, init=False)
class UnixSocket:
    num: str  # the kernel table slot number.
    ref: int  # the number of users of the socket.
    protocol: int  # currently always 0. "Unix"
    flags: str  # the internal kernel flags holding the status of the socket.
    type: int  # the socket type. For SOCK_STREAM sockets, this is 0001; for SOCK_DGRAM sockets, it is 0002; and for SOCK_SEQPACKET sockets, it is 0005. # noqa
    state: int  # the internal state of the socket.
    inode: int  # the inode number of the socket. the inode is commonly refered to as port in tools as ss and netstat
    path: str = field(
        default=None
    )  # sockets in the abstract namespace are included in the list, and are shown with a Path that commences with the character '@'. # noqa

    # Values parsed from raw values listed above.
    state_string: str = field(default=None)
    stream_type_string: str = field(default=None)
    protocol_string: str = field(default=None)

    # Same as defining field_name: type = field(init=False, default=None)
    def __init__(self):
        for fld in fields(self):
            setattr(self, fld.name, None)

        self.protocol_string = "unix"

    def from_line(self, line: str) -> UnixSocket:
        for idx, value in enumerate(line.split()):
            field_names = fields(self)
            setattr(self, field_names[idx].name, value)

        self.type = int(self.type)
        self.protocol = int(self.protocol)
        self.state = int(self.state, 16)
        self.ref = int(self.ref, 16)
        self.inode = int(self.inode)

        return self


@dataclass(order=True, init=False)
class PacketSocket:
    sk: str  # socket number
    ref: int  # the number of processes using this socket.
    type: int  # type of the socket.
    protocol: int  # protocol used by the socket to capture ie. 0003 is ETH_P_ALL
    iface: int  # network interface index.
    r: int  # number of bytes that have been received by the socket and are waiting to be processed.
    rmem: int  # receive window memory.
    user: int  # uid from the owner of the socket.
    inode: int  # inode

    # Values parsed from raw values listed above.
    pid: int  # pid of the socket
    name: str  # process name associated to the socket
    cmdline: str  # process cmdline associated to the socket
    protocol_type: int = field(default=None)  # value parsed from protocol field
    owner: str = field(default=None)  # resolved owner from user (uid) field
    protocol_string: str = field(default="packet")

    def from_line(self, line: str) -> PacketSocket:
        for idx, value in enumerate(line.split()):
            field_names = fields(self)

            if field_names[idx].name == "sk":
                setattr(self, field_names[idx].name, value)
            else:
                setattr(self, field_names[idx].name, int(value))

        return self


@dataclass
class Environ:
    variable: str
    contents: str


class ProcessStateEnum(StrEnum):
    R = "Running"  # Running
    I = "Idle"  # Idle # noqa
    S = "Sleeping"  # Sleeping in an interruptible wait
    D = "Waiting"  # Waiting in uninterruptible disk sleep
    Z = "Zombie"  # Zombie
    T = "Stopped"  # Stopped (on a signal) or (before Linux 2.6.33) trace stopped
    t = "Tracing"  # Tracing stop (Linux 2.6.33 onward)
    W = "Paging"  # Paging (only before Linux 2.6.0)
    X = "Dead"  # Dead (from Linux 2.6.0 onward)
    x = "Dead"  # Dead (Linux 2.6.33 to 3.13 only)
    K = "Wakekill"  # Wakekill (Linux 2.6.33 to 3.13 only)
    # W = "Waking" # Waking (Linux 2.6.33 to 3.13 only
    P = "Parked"  # Parked (Linux 3.9 to 3.13 only)


proc_stat_name = [
    "pid",
    "comm",  # Proccess name
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

    def __init__(self, target: Target) -> None:
        self.target = target

    def packet(self) -> Iterator[PacketSocket]:
        """Yield parsed /proc/net/packet entries."""
        yield from self._parse_packet_sockets()

    def raw(self) -> Iterator[NetSocket]:
        """Yield parsed /proc/net/raw entries."""
        yield from self._parse_net_sockets("raw")

    def raw6(self) -> Iterator[NetSocket]:
        """Yield parsed /proc/net/raw6 entries."""
        yield from self._parse_net_sockets("raw", 6)

    def tcp6(self) -> Iterator[NetSocket]:
        """Yield parsed /proc/net/tcp6 entries."""
        yield from self._parse_net_sockets("tcp", 6)

    def tcp(self) -> Iterator[NetSocket]:
        """Yield parsed /proc/net/tcp entries."""
        yield from self._parse_net_sockets("tcp")

    def udp(self) -> Iterator[NetSocket]:
        """Yield parsed /proc/net/upd entries."""
        yield from self._parse_net_sockets("udp")

    def udp6(self) -> Iterator[NetSocket]:
        """Yield parsed /proc/net/udp6 entries."""
        yield from self._parse_net_sockets("udp", 6)

    def unix(self) -> Iterator[UnixSocket]:
        """Yield parsed /proc/net/unix entries."""
        yield from self._parse_unix_sockets()

    def _parse_net_sockets(self, protocol: str = "tcp", version: int = None) -> Iterator[NetSocket]:
        """Internal function to parse /proc/net/{tcp(6),udp(6), raw(6)} entries

        Args:
            protocol: the protocol in `/proc/net/` to parse entries from.
            version: the version of the protocol to parse entries from.

        Yields:
            An iterator containg a `NetSocket` dataclass
        """
        entry = (
            self.target.fs.path(f"/proc/net/{protocol}{version}")
            if version
            else self.target.fs.path(f"/proc/net/{protocol}")
        )
        contents = entry.open("rt")
        # Skip over the header row
        contents.readline()
        for line in contents:
            if not line.strip():
                continue

            socket = NetSocket().from_line(line)
            socket.protocol_string = entry.name

            if socket.protocol_string in ("udp", "raw", "udp6", "raw6"):
                socket.state_string = self.UDPStates(int(socket.state, 16)).name
            else:
                socket.state_string = self.TCPStates(int(socket.state, 16)).name

            local_ip = socket.local_address.split(":")[0]
            remote_ip = socket.rem_address.split(":")[0]

            socket.local_ip = self._ipv6(local_ip) if version else self._ipv4(local_ip)
            socket.remote_ip = self._ipv6(remote_ip) if version else self._ipv4(remote_ip)

            # uid 0 incidates root, which does not get resolved by target.user_details.find(uid=0)
            socket.owner = self._resolve_uid(socket.uid)
            processes = self.target.proc.inode_to_pid(socket.inode)

            # inode 0 could indicate a kernel process. which has no assiciated PID or FDs in /proc
            # or a inode of 0 could mean the socket is in a TIME_WAIT state.
            if socket.inode == 0:
                socket.pid = socket.inode
                yield socket
            else:
                for process in processes:
                    socket.pid = process.pid
                    socket.name = process.name
                    socket.cmdline = process.cmdline
                    yield socket

    def _parse_unix_sockets(self) -> Iterator[UnixSocket]:
        """Internal function to parse `/proc/net/unix` entries.

        Yields:
            An iterator containg a `NetSocket` dataclass.
        """
        entry = self.target.fs.path("/proc/net/unix")
        contents = entry.open("rt")

        # Skip over the header row
        contents.readline()
        for line in contents:
            if not line.strip():
                continue

            socket = UnixSocket().from_line(line)

            socket.stream_type_string = self.SocketStreamType(socket.type).name
            socket.state_string = self.SocketStateType(socket.state).name

            yield socket

    def _parse_packet_sockets(self) -> Iterator[PacketSocket]:
        """Internal function to parse `/proc/net/packet` entries.

        Yields:
            An iterator containing a `PacketSocket` dataclass.
        """
        entry = self.target.fs.path("/proc/net/packet")
        contents = entry.open("rt")

        # Skip over the header row
        contents.readline()
        for line in contents:
            if not line.strip():
                continue

            socket = PacketSocket().from_line(line)

            processes = self.target.proc.inode_to_pid(socket.inode)

            socket.protocol_type = self.PacketProtocolTypes(socket.protocol).name
            # uid 0 (usually) incidates root, which does not get resolved by target.user_details.find(uid=0) yet.
            socket.owner = self._resolve_uid(socket.user)

            for proc in processes:
                socket.pid = proc.pid
                socket.name = proc.name
                socket.cmdline = proc.cmdline
                yield socket

    def _resolve_uid(self, uid: int) -> str:
        """Internal function to resolve a uid to a username. Returns the uid as a string if no username can be found."""
        if uid == 0:
            # NOTE: currently target.user_details.find(uid=0) does not get resolved. so we return "0"
            return "0"

        user = self.target.user_details.find(uid=uid)
        if user:
            return user.user.name

        return str(uid)

    def _ipv6(self, addr: str | int) -> str:
        """Convert /proc/net IPv6 hex address into standard IPv6 notation."""

        addr = unpack("!LLLL", decode(addr, "hex"))
        return IPv6Address(pack("@IIII", *addr))

    def _ipv4(self, addr: str | int) -> IPv4Address:
        """Convert /proc/net IPv4 hex address into standard IPv4 notation."""
        if isinstance(addr, int):
            return IPv4Address(htonl(addr))

        addr = int(addr, 16)
        return IPv4Address(htonl(addr))


class ProcProcess:
    def __init__(self, target: Target, pid: int, proc_root: str = "/proc") -> None:
        self._pid = int(pid)
        self.target = target

        # TODO map ttys and pttys to process
        if self._pid == 0:
            # The process with PID 0 is responsible for paging and is referred to as the "swapper" or "sched" process.
            # It is a part of the kernel and is not a regular user-mode process.
            self.name = "swapper"
        else:
            try:
                if pid == "self":
                    self.entry = target.fs.get(fsutil.join(proc_root, "self"))
                else:
                    self.entry = target.fs.get(fsutil.join(proc_root, str(pid)))
            except FileNotFoundError:
                raise ProcessLookupError(f"Process with PID {pid} could not be found on target: {target}")

            # self._status_file = self._parse_proc_status_entry()
            self._stat_file = self._parse_proc_stat_entry()
            self.name = self._process_name

    @internal
    def get(self, path) -> FilesystemEntry:
        """Returns a FilesystemEntry relative to this process."""
        return self.entry.get(path)

    @property
    def owner(self) -> str:
        """Return the username or the uid (if owner is not found) of the owner of this process."""
        if self.uid:
            owner = self.target.user_details.find(uid=self.uid)
            return owner.user.name

        # uid is 0 we still want to return that
        return str(self.uid)

    @property
    def uid(self) -> int:
        """Return the uid of the owner of this process."""

        uid = int((self.get("loginuid").open().read()))
        # loginuid can hold the value "4294967295". Which is defined as "not set" and -1 should be returned.
        return -1 if c_int32(uid) == -1 else uid

    @property
    def pid(self) -> int:
        """Returns the process id (pid) associated to this process."""
        return self._pid

    @property
    def parent(self) -> Union[ProcProcess, None]:
        """Returns the parent `ProcProcess of this process."""
        if self.pid == 0:
            return None
        return ProcProcess(self.target, self._stat_file.get("ppid"))

    @property
    def ppid(self) -> int:
        """Returns the parent process id (ppid) assiciated to this process."""
        if self.pid == 0:
            return None
        return self.parent.pid

    @property
    def ppid_name(self) -> str:
        """Returns the name accociated to the parent process id (ppid) of this process."""
        return self.parent.name

    @property
    def state(self) -> str:
        """Returns the state of the process (S'leeping, R'unning, I'dle, etc."""
        return ProcessStateEnum[self._stat_file.get("state")].value

    @property
    def starttime(self) -> datetime:
        """Returns the start time of the process."""
        # Starttime is saved in clockticks per second from the boot time.
        # we asume a standard of 100 clockticks per second. the actual value can be obtained from `getconf CLK_TCK`
        starttime = self._stat_file.get("starttime") / 100

        return from_unix(self._boottime + starttime)

    @property
    def _boottime(self) -> int:
        """Returns the boot time of the system.

        Used internally to determine process start- and run times.
        """
        for line in self.target.fs.get("/proc/stat").open().readlines():
            if not line.startswith(b"btime"):
                continue

            return int(line.split()[1])

    @property
    def runtime(self) -> timedelta:
        """Returns the runtime of a process until the moment of acquisition."""
        runtime = self.now - self.starttime
        return runtime

    @property
    def now(self) -> datetime:
        """Returns the `now()` timestamp of the system of the moment of acquisition."""
        now = self.uptime + from_unix(self._boottime)
        return now

    @internal
    def environ(self) -> Iterator[Environ]:
        """Yields the content of the environ file associated with the process as variable name and content pair.

        Yields:
            An iterator containing a tuple with the variable name and contents thereof.
        """
        yield from self._parse_environ()

    @property
    def uptime(self) -> datetime:
        """Returns the uptime of the system from the moment it was acquired."""
        # uptime is saved in seconds from boottime
        uptime = timedelta(seconds=float(self.target.fs.get("/proc/uptime").open().readline().split()[0]))

        return uptime

    @property
    def _process_name(self) -> str:
        """Internal function that returns the name of the process."""
        return self._stat_file.get("comm", None).decode()

    @property
    def cmdline(self) -> str:
        """Return the command line of a process."""
        cmdline = self.get("cmdline").open().readline().decode()
        # Cmdlines are null-terminated and use null-bytes for spaces. Translate this back.
        cmdline = cmdline.rstrip("\x00").replace("\x00", " ")
        return cmdline

    @internal
    def stat(self) -> fsutil.stat_result:
        """Return a stat entry of the process."""
        return self.entry.stat()

    @internal
    def _parse_proc_status_entry(self) -> dict:
        """Internal function to parse the contents of /proc/[pid]/status."""
        status = self.get("status").open()
        status_dict = {}

        for line in status.readlines():
            key, value = line.split(b":", maxsplit=1)
            key = key.decode().lower().strip()
            value = value.decode().strip()
            status_dict[key] = value

        return status_dict

    @internal
    def _parse_proc_stat_entry(self) -> dict:
        """Internal function to parse the contents of /proc/[pid]/stat."""
        status = self.get("stat").open().readline()
        status_dict = {}

        # The process name exists between parentheses in the second field.
        # Since the name can be arbitrary we have to find the first and last parentheses.
        start_name, end_name = status.find(b"("), status.rfind(b")")

        head = status[:start_name]
        tail = status[end_name:]
        name = status[start_name + 1 : end_name]  # noqa
        status = head + tail

        for idx, part in enumerate(status.split()):
            try:
                part = int(part.decode())
            except ValueError:
                part = part.decode()

            status_dict[proc_stat_name[idx]] = part

        status_dict["comm"] = name

        return status_dict

    @internal
    def _parse_environ(self) -> Iterator[Environ]:
        """Internal function to parse entries in /proc/[pid]/environ"""
        # entries in /proc/<pid>/environ are null-terminated
        environ = self.get("environ").open()
        lines = environ.read().split(b"\x00")

        for line in lines:
            if line == b"":
                # Skip empty line
                continue
            try:
                variable, contents = line.split(b"=", maxsplit=1)
            except ValueError:
                # Covention tells us that variable names and values are split on '='
                # in practice this is not always the case.
                variable = None
                contents = line

            yield Environ(variable=variable, contents=contents)


class ProcPlugin(Plugin):
    __namespace__ = "proc"

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        # make this a lookup instead of a pre-processed map
        self.inode_map = None
        self.sockets = Sockets(self.target)

    @internal
    def _set_inode_pid_map(self) -> None:
        """Creates a inode to pid mapping for all process ids in /proc/[pid]"""
        if not self.inode_map:
            map = defaultdict(list)

            for pid, entry in self._iter_proc_pids():
                try:
                    fds = entry.get("fd").scandir()
                except FileNotFoundError:
                    continue

                for fd in fds:
                    link = fd.readlink()

                    if link.startswith("socket:["):
                        sock_type, inode = link.split(":")

                        # strip brackets from fd string (socket:[1337])
                        inode = int(inode[1:-1])
                        map[inode].append(ProcProcess(self.target, pid))

            self.inode_map = map

    def check_compatible(self) -> bool:
        if not self.target.fs.exists("/proc"):
            raise UnsupportedPluginError("No /proc directory found")
        return None

    @internal
    def inode_to_pid(self, inode: int) -> list:
        if self.inode_map:
            return self.inode_map.get(inode, [])

        # only create the mapping when actually needed
        self._set_inode_pid_map()
        return self.inode_to_pid(inode)

    @internal
    def process(self, pid) -> ProcProcess:
        return ProcProcess(self.target, pid)

    @internal
    def processes(self) -> Iterator[ProcProcess]:
        for pid, _ in self._iter_proc_pids():
            yield ProcProcess(self.target, pid)

    @internal
    def _iter_proc_pids(self) -> Iterator[Tuple[str, FilesystemEntry]]:
        """Yields /proc/<pid> filesystems entries for every process id (pid) found in procfs

        Yields:
            An iterator containing the process id (pid) and corrensponding filesystem entry.
        """
        for entry in self.target.fs.glob_ext("/proc/[0-9]*"):
            yield entry.name, entry

    @internal
    def iter_proc(self) -> Iterator[str]:
        for _, entry in self._iter_proc_pids():
            yield str(entry.path)

    @internal
    def iter_proc_ext(self) -> Iterator[ProcProcess]:
        for _, entry in self._iter_proc_pids():
            yield entry
