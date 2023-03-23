import ipaddress
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from dissect.sql import SQLite3
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

McAfeeMscLogRecord = TargetRecordDescriptor(
    "application/av/mcafee/msc/log",
    [
        ("datetime", "ts"),
        ("string", "threat"),
        ("string", "message"),
        ("string", "keywords"),
        ("string", "fkey"),
    ],
)

McAfeeMscFirewallRecord = TargetRecordDescriptor(
    "application/av/mcafee/msc/firewall",
    [
        ("datetime", "ts"),
        ("net.ipaddress", "ip"),
        ("uint16", "port"),
        ("string", "protocol"),
        ("string", "message"),
        ("string", "keywords"),
        ("string", "fkey"),
    ],
)

re_cdata = re.compile(r"<!\[CDATA\[(.*?)\]\]>", flags=re.M)
re_strip_tags = re.compile(r"<[^!][^>]*>")


class McAfeePlugin(Plugin):
    __namespace__ = "mcafee"

    DIRS = [
        "sysvol/ProgramData/McAfee/MSC/Logs",  # Windows
        "/opt/McAfee/ens/log/tp",  # Linux/Mac according to docs
        "/opt/McAfee/ens/log/esp",  # Linux/Mac according to docs
    ]
    LOG_FILE_PATTERN = "*.log"
    TEMPLATE_ID_INFECTION = 102
    MARKER_INFECTION = "%INFECTION_INFO%"
    MARKER_SUSPICIOUS_TCP_CONNECTION = "TCP port "
    MARKER_SUSPICIOUS_UDP_CONNECTION = "UDP port "
    TABLE_LOG = "log"
    TABLE_FIELD = "field"

    def check_compatible(self) -> bool:
        if not self.get_log_files():
            raise UnsupportedPluginError("No McAfee Log files found")

    def get_log_files(self) -> Iterator[Path]:
        for path in self.DIRS:
            yield from self.target.fs.path(path).glob(self.LOG_FILE_PATTERN)

    def _clean_message(self, message: str) -> str:
        return re.sub(re_strip_tags, "", (" ".join(re.findall(re_cdata, message))))

    @export(record=McAfeeMscLogRecord)
    def msc(self) -> Iterator[McAfeeMscLogRecord]:
        """Return msc log history records from McAfee.

        Yields McAfeeMscLogRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): timestamp.
            ip (net.ipadress): IP of suspicious connection (if available).
            tcp_port (net.tcp.Port): TCP Port of suspicious incoming connection (if available).
            udp_port (net.udp.Port): UDP Port of suspicious incoming connection (if available).
            threat (string): Description of the detected threat (if available).
            message (string): Message as reported in the user interface (might include template slots).
            keywords (string): Unparsed fields that might be visible in user interface.
            fkey (string): Foreign key for reference for further investigation.
        """

        len_marker = len(self.MARKER_SUSPICIOUS_UDP_CONNECTION)

        for log_file in self.get_log_files():
            with log_file.open() as open_log:
                database = SQLite3(open_log)
                fields = defaultdict(dict)
                fields_table = database.table(self.TABLE_FIELD)

                for field in fields_table.rows():
                    fields[field.fkey][field.field_id] = field.data
                log_table = database.table(self.TABLE_LOG)

                for entry in log_table.rows():
                    fkey = entry.fkey
                    log_fields = fields[fkey]
                    ip = None
                    protocol = None
                    port = None
                    threat = None

                    for key, log_field in log_fields.items():
                        try:
                            ipaddress.ip_address(log_field)
                            ip = log_field
                            continue
                        except ValueError:
                            pass

                        if log_field.startswith(
                            (self.MARKER_SUSPICIOUS_TCP_CONNECTION, self.MARKER_SUSPICIOUS_UDP_CONNECTION)
                        ):
                            port = int(log_field[len_marker:])
                            protocol = log_field[:3]
                            continue

                        if key == self.TEMPLATE_ID_INFECTION and entry.details_info.find(self.MARKER_INFECTION) > -1:
                            threat = log_field

                    if threat:
                        yield McAfeeMscLogRecord(
                            ts=from_unix(entry.date),
                            threat=threat,
                            message=self._clean_message(entry.details_info),
                            keywords=",".join(log_fields.values()),
                            fkey=entry.fkey,
                        )
                    else:
                        yield McAfeeMscFirewallRecord(
                            ts=from_unix(entry.date),
                            ip=ip,
                            protocol=protocol,
                            port=port,
                            message=self._clean_message(entry.details_info),
                            keywords=",".join(log_fields.values()),
                            fkey=entry.fkey,
                        )
