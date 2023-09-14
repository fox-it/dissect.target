from itertools import chain
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.linux.proc import (
    NetSocket,
    PacketSocket,
    UnixSocket,
)
from dissect.target.target import Target

NetSocketRecord = TargetRecordDescriptor(
    "linux/proc/sockets",
    [
        ("string", "protocol"),
        ("uint32", "rx_queue"),
        ("uint32", "tx_queue"),
        ("string", "local_ip"),
        ("string", "local_port"),
        ("string", "remote_ip"),
        ("string", "remote_port"),
        ("string", "state"),
        ("string", "owner"),
        ("uint32", "inode"),
        ("uint32", "pid"),
        ("string", "name"),
        ("string", "cmdline"),
    ],
)

UnixSocketRecord = TargetRecordDescriptor(
    "linux/proc/sockets",
    [
        ("string", "protocol"),
        ("uint32", "ref"),
        ("string", "flags"),
        ("string", "type"),
        ("string", "state"),
        ("uint32", "inode"),
        ("string", "path"),
    ],
)

PacketSocketRecord = TargetRecordDescriptor(
    "linux/proc/sockets",
    [
        ("string", "protocol"),
        ("string", "protocol_type"),
        ("string", "sk"),
        ("uint32", "ref"),
        ("uint32", "type"),
        ("uint32", "iface"),
        ("uint32", "r"),
        ("uint32", "rmem"),
        ("uint32", "user"),
        ("string", "owner"),
        ("uint32", "inode"),
        ("uint32", "pid"),
        ("string", "name"),
        ("string", "cmdline"),
    ],
)


class NetSocketPlugin(Plugin):
    __namespace__ = "sockets"

    def __init__(self, target: Target):
        super().__init__(target)
        self.sockets = self.target.proc.sockets

    def check_compatible(self) -> None:
        self.target.proc

    @export(record=PacketSocketRecord)
    def packet(self) -> Iterator[PacketSocketRecord]:
        """This plugin yields the packet sockets and available stats associated with them.

        Yields PacketSocketRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            protocol (int): The captured protocol i.e. 0003 is ETH_P_ALL
            protocol_type (str): The canonical name of the captured protocol.
            sk (string): The socket number.
            type (int): The integer type of the socket (packet).
            iface (int): The interface index of the socket.
            r (int): The number of bytes that have been received by the socket and are waiting to be processed.
            rmem (int): The size of the receive buffer for the socket.
            user (int): The user ID of the process that created the socket.
            inode (int): The inode associated to the socket.
            pid (int): The pid associated with this socket.
            name (string): The process name associated to this socket.
            cmdline (string): The command line used to start the socket with.
            owner (string): The resolved user ID of the socket.
        """
        yield from map(self._generate_packet_socket_record, self.sockets.packet())

    @export(record=UnixSocketRecord)
    def unix(self) -> Iterator[UnixSocketRecord]:
        """This plugin yields the unix sockets and available stats associated with them.

        Yields UnixSocketRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            protocol (string): The protocol used by the socket.
            flags (bytes): The flags associated with the socket.
            type (string): The stream type of the socket.
            state (string): The state of the socket.
            inode (int): The inode associated to the socket.
            path (string): The path associated to the socket.
        """
        yield from map(self._generate_unix_socket_record, self.sockets.unix())

    @export(record=NetSocketRecord)
    def raw(self) -> Iterator[NetSocketRecord]:
        """This plugin yields the raw and raw6 sockets and available stats associated with them.

        Yields NetSocketRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            protocol (string): The protocol used by the socket.
            receive_queue (int): The size, in bytes of the receive queue of the socket.
            transmit_queue (int): The size, in bytes of the transmit queue of the socket.
            local_ip (string): The local ip the socket connects from.
            local_port (int): The local port the socket connects from.
            remote_ip (string): The remote ip the socket connects to.
            remote_port (int): The remote port the socket connects to.
            state (string): The state of the socket.
            owner (string): The loginuid of the pid associated with this socket.
            inode (int): The inode (fd) associated with this socket.
            pid (int): The pid associated with this socket.
            name (string): The process name associated with this socket.
            cmdline (string): The command line used to start the socket with.
        """
        yield from map(self._generate_net_socket_record, chain(self.sockets.raw(), self.sockets.raw6()))

    @export(record=NetSocketRecord)
    def udp(self) -> Iterator[NetSocketRecord]:
        """This plugin yields the udp and udp6 sockets and available stats associated with them.

        Yields NetSocketRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            protocol (string): The protocol used by the socket.
            receive_queue (int): The size, in bytes of the receive queue of the socket.
            transmit_queue (int): The size, in bytes of the transmit queue of the socket.
            local_ip (string): The local ip the socket connects from.
            local_port (int): The local port the socket connects from.
            remote_ip (string): The remote ip the socket connects to.
            remote_port (int): The remote port the socket connects to.
            state (string): The state of the socket.
            owner (string): The loginuid of the pid associated with this socket.
            inode (int): The inode (fd) associated with this socket.
            pid (int): The pid associated with this socket.
            name (string): The process name associated with this socket.
            cmdline (string): The command line used to start the socket with.
        """
        yield from map(self._generate_net_socket_record, chain(self.sockets.udp(), self.sockets.udp6()))

    @export(record=NetSocketRecord)
    def tcp(self) -> Iterator[NetSocketRecord]:
        """This plugin yields the tcp and tcp6 sockets and available stats associated with them.

        Yields NetSocketRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            protocol (string): The protocol used by the socket.
            receive_queue (int): The size, in bytes of the receive queue of the socket.
            transmit_queue (int): The size, in bytes of the transmit queue of the socket.
            local_ip (string): The local ip the socket connects from.
            local_port (int): The local port the socket connects from.
            remote_ip (string): The remote ip the socket connects to.
            remote_port (int): The remote port the socket connects to.
            state (string): The state of the socket.
            owner (string): The loginuid of the pid associated with this socket.
            inode (int): The inode (fd) associated with this socket.
            pid (int): The pid associated with this socket.
            name (string): The process name associated with this socket.
            cmdline (string): The command line used to start the socket with.
        """
        yield from map(self._generate_net_socket_record, chain(self.sockets.tcp(), self.sockets.tcp6()))

    def _generate_unix_socket_record(self, data: UnixSocket) -> UnixSocketRecord:
        return UnixSocketRecord(
            protocol=data.protocol_string,
            ref=data.ref,
            flags=data.flags,
            type=data.stream_type_string,
            state=data.state_string,
            inode=data.inode,
            path=data.path,
            _target=self.target,
        )

    def _generate_packet_socket_record(self, data: PacketSocket) -> PacketSocketRecord:
        return PacketSocketRecord(
            protocol=data.protocol_string,
            protocol_type=data.protocol_type,
            sk=data.sk,
            ref=data.ref,
            type=data.type,
            iface=data.iface,
            r=data.r,
            rmem=data.rmem,
            user=data.user,
            inode=data.inode,
            pid=data.pid,
            name=data.name,
            cmdline=data.cmdline,
            owner=data.owner,
            _target=self.target,
        )

    def _generate_net_socket_record(self, data: NetSocket) -> NetSocketRecord:
        return NetSocketRecord(
            protocol=data.protocol_string,
            rx_queue=data.rx_queue,
            tx_queue=data.tx_queue,
            local_ip=data.local_ip,
            local_port=data.local_port,
            remote_ip=data.remote_ip,
            remote_port=data.remote_port,
            state=data.state_string,
            owner=data.owner,
            inode=data.inode,
            pid=data.pid,
            name=data.name,
            cmdline=data.cmdline,
            _target=self.target,
        )
