from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from dissect.sql import SQLite3
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

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

McAfeeAtpRemediationRecord = TargetRecordDescriptor(
    "application/av/mcafee/atp/remediation",
    [
        ("datetime", "ts"),
        ("string", "alert_id"),
        ("string", "threat"),
        ("string", "severity"),
        ("string", "process"),
        ("string", "target"),
        ("string", "action"),
        ("string", "status"),
        ("string", "message"),
        ("string", "story_graph_key"),
        ("path", "source"),
        ("string", "raw"),
    ],
)

re_cdata = re.compile(r"<!$begin:math:display$CDATA\\\[\(\.\*\?\)$end:math:display$\]>", flags=re.MULTILINE)
re_strip_tags = re.compile(r"<[^!][^>]*>")


class McAfeePlugin(Plugin):
    """McAfee antivirus plugin."""

    __namespace__ = "mcafee"

    DIRS = (
        "sysvol/ProgramData/McAfee/MSC/Logs",  # Windows
        "/opt/McAfee/ens/log/tp",  # Linux/Mac according to docs
        "/opt/McAfee/ens/log/esp",  # Linux/Mac according to docs
    )
    ATP_DIRS = (
        "sysvol/ProgramData/McAfee/Endpoint Security/ATP",  # Windows
    )

    LOG_FILE_PATTERN = "*.log"
    TEMPLATE_ID_INFECTION = 102
    MARKER_INFECTION = "%INFECTION_INFO%"
    MARKER_SUSPICIOUS_TCP_CONNECTION = "TCP port "
    MARKER_SUSPICIOUS_UDP_CONNECTION = "UDP port "
    TABLE_LOG = "log"
    TABLE_FIELD = "field"

    def check_compatible(self) -> None:
        if not list(self.get_log_files()) and not list(self.get_atp_files()):
            raise UnsupportedPluginError("No McAfee Log or ATP JSON files found")

    def get_log_files(self) -> Iterator[Path]:
        for path in self.DIRS:
            yield from self.target.fs.path(path).glob(self.LOG_FILE_PATTERN)

    def get_atp_files(self) -> Iterator[Path]:
        for path in self.ATP_DIRS:
            yield from self.target.fs.path(path).glob("*.json")

    def _clean_message(self, message: str) -> str:
        return re.sub(re_strip_tags, "", (" ".join(re.findall(re_cdata, message))))

    def _get_first(self, obj: dict[str, Any], *names: str) -> Any:
        for name in names:
            value = obj.get(name)
            if value not in (None, "", [], {}):
                return value
        return None

    def _walk_dicts(self, value: Any) -> Iterator[dict[str, Any]]:
        if isinstance(value, dict):
            yield value
            for subvalue in value.values():
                yield from self._walk_dicts(subvalue)
        elif isinstance(value, list):
            for item in value:
                yield from self._walk_dicts(item)

    def _parse_atp_timestamp(self, value: Any):
        if value in (None, ""):
            return None

        if isinstance(value, (int, float)):
            if value > 10_000_000_000:
                value = value / 1000
            try:
                return from_unix(value)
            except Exception:
                return None

        if isinstance(value, str) and value.isdigit():
            value = int(value)
            if value > 10_000_000_000:
                value = value / 1000
            try:
                return from_unix(value)
            except Exception:
                return None

        return None

    def _iter_remediation_entries(self, data: dict[str, Any]) -> Iterator[dict[str, Any]]:
        remediation = data.get("Remediation")
        if remediation is None:
            return

        for item in self._walk_dicts(remediation):
            if any(key in item for key in ("AlertID", "AlertId", "ThreatName", "DetectionName", "Action", "Status")):
                yield item

    @export(record=McAfeeMscLogRecord)
    def msc(self) -> Iterator[McAfeeMscLogRecord]:
        """Return msc log history records from McAfee.

        Yields McAfeeMscLogRecord with the following fields:

        .. code-block:: text

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

    @export(record=McAfeeAtpRemediationRecord)
    def atp(self) -> Iterator[McAfeeAtpRemediationRecord]:
        """Return remediation alert records from McAfee ATP JSON files."""

        for atp_file in self.get_atp_files():
            try:
                with atp_file.open("rt") as fh:
                    data = json.load(fh)
            except Exception:
                continue

            story_graph = data.get("Story_Graph")
            story_graph_key = None
            if isinstance(story_graph, dict):
                story_graph_key = self._get_first(
                    story_graph,
                    "Key",
                    "key",
                    "StoryGraphKey",
                    "Story_Graph_Key",
                )

            for entry in self._iter_remediation_entries(data):
                ts = self._parse_atp_timestamp(
                    self._get_first(
                        entry,
                        "Timestamp",
                        "Time",
                        "EventTime",
                        "CreateTime",
                        "CreationTime",
                        "UTC",
                    )
                )

                alert_id = self._get_first(entry, "AlertID", "AlertId", "Id", "ID")
                threat = self._get_first(entry, "ThreatName", "DetectionName", "Threat", "Name")
                severity = self._get_first(entry, "Severity", "ThreatSeverity")
                process = self._get_first(entry, "ProcessName", "ProcessPath", "Initiator", "Actor")
                target = self._get_first(
                    entry, "FileName", "FilePath", "TargetFile", "TargetPath", "RegistryKey", "RegistryPath", "Target"
                )
                action = self._get_first(entry, "Action", "RemediationType", "Operation")
                status = self._get_first(entry, "Status", "Result", "Disposition")
                message = self._get_first(entry, "Message", "Description", "Details")

                yield McAfeeAtpRemediationRecord(
                    ts=ts,
                    alert_id=str(alert_id) if alert_id is not None else None,
                    threat=str(threat) if threat is not None else None,
                    severity=str(severity) if severity is not None else None,
                    process=str(process) if process is not None else None,
                    target=str(target) if target is not None else None,
                    action=str(action) if action is not None else None,
                    status=str(status) if status is not None else None,
                    message=str(message) if message is not None else None,
                    story_graph_key=str(story_graph_key) if story_graph_key is not None else atp_file.name,
                    source=atp_file,
                    raw=json.dumps(entry, sort_keys=True),
                )