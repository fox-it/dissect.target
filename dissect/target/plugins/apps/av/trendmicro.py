from typing import Iterator

from dissect import cstruct
from dissect.util.ts import from_unix

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

TrendMicroWFLogRecord = TargetRecordDescriptor(
    "application/av/trendmicro/wflog",
    [
        ("datetime", "ts"),
        ("string", "threat"),
        ("string", "message"),
        ("string", "keywords"),
        ("string", "fkey"),
    ],
)


TrendMicroWFFirewallRecord = TargetRecordDescriptor(
    "application/av/trendmicro/wffirewall",
    [
        ("datetime", "ts"),
        ("net.ipaddress", "local_ip"),
        ("net.ipaddress", "remote_ip"),
        ("string", "direction"),
        ("uint16", "port"),
        ("path", "path"),
        ("string", "description"),
    ],
)


pfwlog_def = """
struct firewall_entry {
    char      _[1];
    char      direction;
    uint16    port;
    uint32    timestamp;
    char      _pad[8];
    char      local_ip[65];
    char      remote_ip[65];
    char      path[520];
    wchar     description[128];
    char      _[10];
};
"""
c_pfwlog = cstruct.cstruct()
c_pfwlog.load(pfwlog_def)


class TrendMicroPlugin(Plugin):
    __namespace__ = "trendmicro"

    LOG_FOLDER = "sysvol/Program Files (x86)/Trend Micro/Security Agent"
    LOG_FILE_FIREWALL = f"{LOG_FOLDER}/PFW/PfwLog_*.dat"  # Windows intrusions
    LOG_FILE_INFECTIONS = f"{LOG_FOLDER}/Misc/pccnt35.log"  # Windows infections

    def __init__(self, target: Target) -> None:
        super().__init__(target)

    def check_compatible(self) -> bool:
        if not self.target.fs.path(self.LOG_FOLDER).exists():
            raise UnsupportedPluginError

    @export(record=TrendMicroWFLogRecord)
    def wflogs(self) -> Iterator[TrendMicroWFLogRecord]:
        """Return Trend Micro Worry-free log history records.

        Yields TrendMicroWFLogRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): timestamp.
            threat (string): Description of the detected threat (if available).
            message (string): Message as reported in the user interface
            keywords (string): Unparsed fields that might be visible in user interface.
            fkey (string): Foreign key for reference for further investigation.
        """
        with self.target.fs.path(self.LOG_FILE_INFECTIONS).open("rt") as f:
            for lineno, line in enumerate(f.readlines()):
                cells = line.split("<;>")
                yield TrendMicroWFLogRecord(
                    ts=from_unix(int(cells[9])),
                    message=",".join(cells),
                    threat=cells[2],
                    keywords=",".join([cells[0], cells[2], cells[6], cells[7], cells[8]]),
                    fkey=lineno,
                )

    @export(record=TrendMicroWFFirewallRecord)
    def wffirewall(self) -> Iterator[TrendMicroWFFirewallRecord]:
        """Return Trend Micro Worry-free firewall log history records.

        Yields TrendMicroWFFirewallRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): timestamp.
            local_ip (net.ipadress): Local IPv4/IPv6.
            remote_ip (net.ipaddress): Remote IPv4/IPv6.
            port (uint16): Port of suspicious connection.
            direction (string): Direction of the traffic
            path (string): Path to object that initiated/received connection
            description (string): Description of the detected threat
        """
        for firewall_log in self.target.fs.glob_ext(self.LOG_FILE_FIREWALL):
            with firewall_log.open() as log:
                try:
                    while entry := c_pfwlog.firewall_entry(log):
                        yield TrendMicroWFFirewallRecord(
                            ts=from_unix(entry.timestamp),
                            local_ip=entry.local_ip.strip(b"\x00").decode("utf-8"),
                            remote_ip=entry.remote_ip.strip(b"\x00").decode("utf-8"),
                            port=entry.port,
                            direction=("out" if entry.direction == b"\x01" else "in"),
                            path=entry.path.strip(b"\x00").decode(),
                            description=entry.description.encode().strip(b"\x00").decode(),
                        )
                except EOFError:
                    pass
