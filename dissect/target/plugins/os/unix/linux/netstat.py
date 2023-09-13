from itertools import chain
from typing import Iterator

from dissect.target.plugin import Plugin, export

NETSTAT_HEADER = f"Active Internet connections (only servers)\n{'Proto':<10}{'Recv-Q':^10}{'Send-Q':^10}{'Local Address':^20}{'Foreign Address':^20}{'State':^10}{'User':^15}{'Inode':^10}{'PID/Program name':^10}{'Command':>10}"  # noqa
NETSTAT_TEMPLATE = "{protocol:<12}{receive_queue:<10}{transmit_queue:<11}{local_addr:<19}{remote_addr:<20}{state:<13}{owner:<12}{inode:<8}{pid_program:<19}{cmdline}"  # noqa


class NetstatPlugin(Plugin):
    def check_compatible(self) -> None:
        self.target.proc

    @export(output="yield")
    def netstat(self) -> Iterator[str]:
        """This plugin mimics the output `netstat -tunelwap` would generate on a Linux machine."""
        sockets = chain(
            self.target.sockets.tcp(),
            self.target.sockets.udp(),
            self.target.sockets.raw(),
        )

        yield NETSTAT_HEADER

        for record in sockets:
            local_addr = f"{record.local_ip}:{record.local_port}"
            remote_addr = f"{record.remote_ip}:{record.remote_port}"
            pid_program = f"{record.pid}/{record.name}"

            yield NETSTAT_TEMPLATE.format(
                protocol=record.protocol,
                receive_queue=record.rx_queue,
                transmit_queue=record.tx_queue,
                local_addr=local_addr,
                remote_addr=remote_addr,
                state=record.state,
                owner=record.owner,
                inode=record.inode,
                pid_program=pid_program,
                cmdline=record.cmdline,
            )
