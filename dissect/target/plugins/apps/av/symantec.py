from __future__ import annotations

import csv
import io
import ipaddress
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Final

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

SEPLogRecord = TargetRecordDescriptor(
    "application/av/symantec/sep/log",
    [
        ("datetime", "ts"),
        ("string", "virus"),
        ("string", "user"),
        ("path", "source_file"),
        ("string", "action_taken"),
        ("string", "virus_type"),
        ("varint", "scan_id"),
        ("varint", "quarantine_id"),
        ("varint", "virus_id"),
        ("varint", "depth"),
        ("boolean", "still_infected"),
        ("boolean", "quarantined"),
        ("boolean", "compressed"),
        ("boolean", "cleanable"),
        ("boolean", "deletable"),
        ("varint", "confidence"),
        ("varint", "prevalence"),
        ("varint", "risk"),
        ("uri", "download_url"),
        ("varint", "line_no"),
    ],
)

SEPFirewallRecord = TargetRecordDescriptor(
    "application/av/symantec/sep/firewall",
    [
        ("datetime", "ts"),
        ("string", "protocol"),
        ("net.ipaddress", "local_ip"),
        ("net.ipaddress", "remote_ip"),
        ("net.ipaddress", "local_ip6"),
        ("net.ipaddress", "remote_ip6"),
        ("varint", "local_port"),
        ("varint", "remote_port"),
        ("boolean", "outbound"),
        ("datetime", "begin_time"),
        ("datetime", "end_time"),
        ("varint", "repetition"),
        ("boolean", "blocked"),
        ("string", "severity"),
        ("varint", "rule_id"),
        ("string", "remote_host"),
        ("string", "rule_name"),
        ("path", "application"),
        ("string", "user"),
        ("varint", "line_no"),
    ],
)


class SymantecPlugin(Plugin):
    """Symantec Endpoint Security Suite Plugin.

    References:
        - https://malwaremaloney.blogspot.com/2021/01/
    """

    __namespace__ = "symantec"

    LOG_SEP_AV = "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Logs/AV/*"
    LOG_SEP_NET = "sysvol/ProgramData/Symantec/Symantec Endpoint Protection/*/Data/Logs/tralog.log"

    LOGS = (LOG_SEP_AV, LOG_SEP_NET)

    # Special values
    MARKER_INFECTION = 5
    QUARANTINE_SUCCESS = 2
    CLEANABLE = 0
    DELETABLE = 4
    STILL_INFECTED = 1
    OUTBOUND = 2
    BLOCKED = 1
    COMPRESSED = 1

    TCP_INIT = 301
    TCP_CLOSE = 304
    UDP_DATA = 302

    # Log fields
    AV_TIMESTAMP = 0
    AV_EVENT = 1
    AV_USER = 5
    AV_VIRUS = 6
    AV_FILE = 7
    AV_ACTION_TAKEN = 10
    AV_VIRUS_TYPE = 11
    AV_SCAN_ID = 14
    AV_EVENT_DATA = 17
    AV_QUARANTINE_ID = 18
    AV_VIRUS_ID = 19
    AV_QUARANTINE_STATUS = 20
    AV_COMPRESSED = 23
    AV_DEPTH = 24
    AV_STILL_INFECTED = 25
    AV_CLEANABLE = 28
    AV_DELETABLE = 29
    AV_CONFIDENCE = 65
    AV_PREVALENCE = 67
    AV_DOWNLOADED_FROM = 68
    AV_RISK = 71

    # Firwall fields
    FW_TIMESTAMP = 1
    FW_PROTOCOL = 2
    FW_LOCAL_IP = 3
    FW_REMOTE_IP = 4
    FW_LOCAL_PORT = 5
    FW_REMOTE_PORT = 6
    FW_DIRECTION = 7
    FW_BEGIN_TIME = 8
    FW_END_TIME = 9
    FW_REPETITION = 10
    FW_ACTION = 11
    FW_SEVERITY = 13
    FW_RULE_ID = 14
    FW_REMOTE_HOST_NAME = 15
    FW_RULE_NAME = 16
    FW_APPLICATION = 17
    FW_LOCATION = 20
    FW_USER = 21
    FW_LOCAL_IP6 = 25
    FW_REMOTE_IP6 = 26

    PROTOCOL: Final[dict[int, str]] = {
        301: "TCP initiated",
        302: "UDP datagram",
        303: "Ping request",
        304: "TCP completed",
        305: "Traffic (other)",
        306: "ICMPv4 packet",
        307: "Ethernet packet",
        308: "IP packet",
        309: "ICMPv6 packet",
    }

    SEVERITY = ["Critical"] * 4 + ["Major"] * 4 + ["Minor"] * 4 + ["Info"] * 4

    ACTION: Final[dict[int, str]] = {
        1: "Quarantine",
        2: "Rename",
        3: "Delete",
        4: "Leave Alone",
        5: "Clean",
        6: "Remove Macros",
        7: "Save file as...",
        8: "Sent to backend",
        9: "Restore from Quarantine",
        11: "Undo Action",
        12: "Error",
        13: "Backup to quarantine (backup view)",
        14: "Pending Analysis",
        15: "Partially Fixed",
        16: "Terminate Process Required",
        17: "Exclude from Scanning",
        18: "Reboot Processing",
        19: "Clean by Deletion",
        20: "Access Denied",
        21: "TERMINATE PROCESS ONLY",
        22: "NO REPAIR",
        23: "FAIL",
        24: "RUN POWERTOOL",
        25: "NO REPAIR POWERTOOL",
        110: "INTERESTING PROCESS CAL",
        111: "INTERESTING PROCESS DETECTED",
        1000: "INTERESTING PROCESS HASHED DETECTED",
        1001: "DNS HOST FILE EXCEPTION",
    }

    VIRUS_TYPE: Final[dict[int, str]] = {
        48: "Heuristic",
        64: "Reputation",
        80: "Hack Tools",
        96: "Spyware",
        112: "Trackware",
        128: "Dialers",
        144: "Remote Access",
        160: "Adware",
        176: "Joke Programs",
        224: "Heuristic Application",
        256: "Test",
    }

    def __init__(self, target: Target):
        super().__init__(target)
        self.codepage = self.target.codepage or "ascii"

    def check_compatible(self) -> None:
        for log_file in self.LOGS:
            if list(self.target.fs.glob(log_file)):
                return
        raise UnsupportedPluginError("No Symantec SEP logs found")

    def _fw_cell(self, line: list, cell_id: int) -> str:
        return line[cell_id].decode("utf-8")

    def _fw_hex_cell(self, line: list, cell_id: int) -> int:
        return int(self._fw_cell(line, cell_id), 16)

    def _septime(self, ts: str) -> str:
        # Date/Time stored as 12 digit hex number (6 pairs of 2 digits)
        # Offsets for year (+1970) and month (+1), no TZ
        year = int(ts[0:2], 16)
        month = int(ts[2:4], 16)
        day = int(ts[4:6], 16)
        hour = int(ts[6:8], 16)
        minute = int(ts[8:10], 16)
        second = int(ts[10:12], 16)
        return f"{year + 1970}-{month + 1:0>2}-{day:0>2}T{hour:0>2}:{minute:0>2}:{second:0>2}"

    def _fw_line(self, line: bytes, line_no: int) -> Iterator[SEPFirewallRecord]:
        try:
            cells = line.split(b"\t")
            protocol_id = self._fw_hex_cell(cells, self.FW_PROTOCOL)
            tcp_udp = protocol_id in [self.TCP_INIT, self.TCP_CLOSE, self.UDP_DATA]

            yield SEPFirewallRecord(
                ts=wintimestamp(self._fw_hex_cell(cells, self.FW_TIMESTAMP)),
                protocol=self.PROTOCOL.get(protocol_id, "Unknown"),
                local_ip=ipaddress.ip_address(struct.pack("<i", self._fw_hex_cell(cells, self.FW_LOCAL_IP))),
                remote_ip=ipaddress.ip_address(struct.pack("<i", self._fw_hex_cell(cells, self.FW_REMOTE_IP))),
                local_ip6=ipaddress.ip_address(ipaddress.v6_int_to_packed(self._fw_hex_cell(cells, self.FW_LOCAL_IP6))),
                remote_ip6=ipaddress.ip_address(
                    ipaddress.v6_int_to_packed(self._fw_hex_cell(cells, self.FW_REMOTE_IP6))
                ),
                local_port=self._fw_hex_cell(cells, self.FW_LOCAL_PORT) if tcp_udp else None,
                remote_port=self._fw_hex_cell(cells, self.FW_REMOTE_PORT) if tcp_udp else None,
                outbound=self._fw_hex_cell(cells, self.FW_DIRECTION) == self.OUTBOUND,
                begin_time=wintimestamp(self._fw_hex_cell(cells, self.FW_BEGIN_TIME)),
                end_time=wintimestamp(self._fw_hex_cell(cells, self.FW_END_TIME)),
                repetition=self._fw_hex_cell(cells, self.FW_REPETITION),
                blocked=self._fw_hex_cell(cells, self.FW_ACTION) == self.BLOCKED,
                severity=self.SEVERITY[self._fw_hex_cell(cells, self.FW_SEVERITY)],
                rule_id=self._fw_hex_cell(cells, self.FW_RULE_ID),
                remote_host=self._fw_cell(cells, self.FW_REMOTE_HOST_NAME),
                rule_name=self._fw_cell(cells, self.FW_RULE_NAME),
                application=Path(self._fw_cell(cells, self.FW_APPLICATION)),
                user=self._fw_cell(cells, self.FW_USER),
                line_no=line_no,
                _target=self.target,
            )
        except Exception as e:
            self.target.log.warning("Error: %s on firewall log line: %d", e, line_no)

    def _line(self, line: str, line_no: int) -> Iterator[SEPLogRecord]:
        try:
            rows = csv.reader(io.StringIO(line))

            for cells in rows:
                if int(cells[self.AV_EVENT]) != self.MARKER_INFECTION:
                    return

                yield SEPLogRecord(
                    ts=self._septime(cells[self.AV_TIMESTAMP]),
                    virus=cells[self.AV_VIRUS],
                    virus_type=self.VIRUS_TYPE.get(int(cells[self.AV_VIRUS_TYPE]), "Unknown"),
                    user=cells[self.AV_USER],
                    source_file=cells[self.AV_FILE],
                    action_taken=self.ACTION.get(int(cells[self.AV_ACTION_TAKEN]), "Unknown"),
                    scan_id=cells[self.AV_SCAN_ID],
                    quarantine_id=cells[self.AV_QUARANTINE_ID],
                    virus_id=cells[self.AV_VIRUS_ID],
                    quarantined=int(cells[self.AV_QUARANTINE_STATUS]) == self.QUARANTINE_SUCCESS,
                    compressed=int(cells[self.AV_COMPRESSED]) == self.COMPRESSED,
                    depth=cells[self.AV_DEPTH],
                    still_infected=(int(cells[self.AV_STILL_INFECTED]) == self.STILL_INFECTED),
                    cleanable=int(cells[self.AV_CLEANABLE]) == self.DELETABLE,
                    deletable=int(cells[self.AV_DELETABLE]) == self.CLEANABLE,
                    confidence=cells[self.AV_CONFIDENCE],
                    prevalence=cells[self.AV_PREVALENCE],
                    risk=cells[self.AV_RISK],
                    download_url=cells[self.AV_DOWNLOADED_FROM],
                    line_no=line_no,
                    _target=self.target,
                )
        except Exception as e:
            self.target.log.warning("Error: %s on log line: %d", e, line_no)

    @export(record=SEPLogRecord)
    def logs(self) -> Iterator[SEPLogRecord]:
        """Return log records.

        Yields SEPLogRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp associated with the event.
            virus (string): Name of the virus.
            user (string): Name of the user associated with the event.
            source_file (path): File that contains the virus.
            action_taken (string): Action taken by SEP.
            virus_type (string): Description of the type of virus.
            scan_id (varint): ID of the scan associated with the event.
            event_data (string): String or bytes from a virus event.
            quarantine_id (varint): ID associated with the quarantined virus.
            still_infected (boolean): Whether the system is still infected.
            quarantined (boolean): True if the virus has been quarantined succesfully.
            compressed (boolean): True if the virus was in a compressed file.
            depth (varint): How many layers of compression the virus was hidden in.
            cleanable (boolean): Whether the virus is cleanable.
            deletable (boolean): Whether the virus can be deleted.
            confidence (varint): Confidence level about threat verdict (higher is more confident).
            prevalence (varint): Prevalence of the threat (higher is more prevalent).
            risk (varint): Risk level of the threat (1-4, higher is more dangerous, 0 = unknown).
            download_url (uri): Source of the virus (if available).
            line_no (varint): Reference line number in log file.
        """
        for log_path in self.target.fs.glob(self.LOG_SEP_AV):
            with self.target.fs.path(log_path).open("rt", 0, self.codepage) as csv_file:
                line_no = 0
                while line := csv_file.readline():
                    line_no += 1
                    yield from self._line(line, line_no)

    @export(record=SEPFirewallRecord)
    def firewall(self) -> Iterator[SEPFirewallRecord]:
        """Return log firewall records.

        Yields SEPFirewallRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp associated with the event.
            protocol (string): Protocol name associated with the firewall record.
            local_ip ("net.ipaddress"): Local IP address associated with the event.
            remote_ip ("net.ipaddress"): Remote IP address associated with the event.
            local_ip6 ("net.ipaddress"): Local IPv6 address associated with the event.
            remote_ip6 ("net.ipaddress"): Remote IPv6 address associated with the event.
            local_port (varint): Local port associated with the event.
            remote_port (varint): Local port associated with the event.
            outbound (boolean): True in case of outbound traffic/connection.
            begin_time (datetime): Start of the event.
            end_time (datetime): End of the event.
            repetition (varint): How many times this event happened within the time frame.
            blocked (boolean): Whether the traffic/connection was succesfully blocked.
            severity (string): Severity of the event.
            rule_id (varint): Firewall rule ID associated with this event.
            rule_name (string): Name of the Firewall rule associated with this event.
            remote_host (string): Name of the remote host if it can be traced.
            application (path): Application responsible for/affected by event.
            user (string): User associated with the event.
            line_no (varint): Reference line number in log file.
        """

        for log_path in self.target.fs.glob(self.LOG_SEP_NET):
            log = self.target.fs.path(log_path).open("rb")
            line_no = 0
            while line := log.readline():
                line_no += 1
                if line_no == 1:
                    continue
                yield from self._fw_line(line, line_no)
