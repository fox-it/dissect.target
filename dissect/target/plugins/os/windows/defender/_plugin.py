from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.os.windows.defender.mplog import (
    DEFENDER_MPLOG_BLOCK_PATTERNS,
    DEFENDER_MPLOG_LINE,
    DEFENDER_MPLOG_PATTERNS,
    DefenderMPLogBMTelemetryRecord,
    DefenderMPLogDetectionAddRecord,
    DefenderMPLogDetectionEventRecord,
    DefenderMPLogEMSRecord,
    DefenderMPLogExclusionRecord,
    DefenderMPLogLowfiRecord,
    DefenderMPLogMinFilBlockedFileRecord,
    DefenderMPLogMinFilUSSRecord,
    DefenderMPLogOriginalFileNameRecord,
    DefenderMPLogProcessImageRecord,
    DefenderMPLogResourceScanRecord,
    DefenderMPLogRTPRecord,
    DefenderMPLogThreatActionRecord,
    DefenderMPLogThreatRecord,
)
from dissect.target.plugins.os.windows.defender.quarantine import (
    DefenderFileQuarantineRecord,
    DefenderQuarantineRecord,
    QuarantineEntry,
    recover_quarantined_file_streams,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from flow.record import Record

DEFENDER_EVTX_FIELDS = [
    ("datetime", "ts"),
    ("uint32", "EventID"),
    ("string", "Provider_Name"),
    ("string", "Action_ID"),
    ("string", "Action_Name"),
    ("string", "Additional_Actions_ID"),
    ("string", "Additional_Actions_String"),
    ("string", "Category_ID"),
    ("string", "Category_Name"),
    ("string", "Channel"),
    ("string", "Computer"),
    ("string", "Correlation_ActivityID"),
    ("string", "Correlation_RelatedActivityID"),
    ("string", "Detection_ID"),
    ("datetime", "Detection_Time"),
    ("string", "Detection_User"),
    ("string", "Engine_Version"),
    ("string", "Error_Code"),
    ("string", "Error_Description"),
    ("string", "EventID_Qualifiers"),
    ("string", "EventRecordID"),
    ("string", "Execution_ID"),
    ("string", "Execution_Name"),
    ("string", "Execution_ProcessID"),
    ("string", "Execution_ThreadID"),
    ("string", "FWLink"),
    ("string", "Keywords"),
    ("string", "Level"),
    ("string", "Opcode"),
    ("string", "Origin_ID"),
    ("string", "Origin_Name"),
    ("string", "Path"),
    ("string", "Post_Clean_Status"),
    ("string", "Pre_Execution_Status"),
    ("string", "Process_Name"),
    ("string", "Product_Name"),
    ("string", "Product_Version"),
    ("string", "Provider_Guid"),
    ("string", "Remediation_User"),
    ("string", "Security_intelligence_Version"),
    ("string", "Security_UserID"),
    ("string", "Severity_ID"),
    ("string", "Severity_Name"),
    ("string", "Source_ID"),
    ("string", "Source_Name"),
    ("string", "State"),
    ("string", "Status_Code"),
    ("string", "Status_Description"),
    ("string", "Task"),
    ("string", "Threat_ID"),
    ("string", "Threat_Name"),
    ("string", "Type_ID"),
    ("string", "Type_Name"),
    ("string", "Version"),
]

DEFENDER_LOG_DIR = "sysvol/windows/system32/winevt/logs"
DEFENDER_LOG_FILENAME_GLOB = "Microsoft-Windows-Windows Defender*"
EVTX_PROVIDER_NAME = "Microsoft-Windows-Windows Defender"

DEFENDER_QUARANTINE_DIR = "sysvol/programdata/microsoft/windows defender/quarantine"
DEFENDER_MPLOG_DIR = "sysvol/programdata/microsoft/windows defender/support"
DEFENDER_KNOWN_DETECTION_TYPES = [b"internalbehavior", b"regkey", b"runkey"]

DEFENDER_EXCLUSION_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions"

DefenderLogRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/evtx",
    DEFENDER_EVTX_FIELDS,
)

DefenderExclusionRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/exclusion",
    [
        ("datetime", "regf_mtime"),
        ("string", "type"),
        ("string", "value"),
    ],
)


def parse_iso_datetime(datetime_value: str) -> datetime.datetime:
    """Parse ISO8601 serialized datetime with ``Z`` ending."""
    return datetime.datetime.strptime(datetime_value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)


def filter_records(records: Iterable, field_name: str, field_value: Any) -> Iterator[DefenderLogRecord]:
    """Apply a filter on an Iterable of records, returning only records that have the given field value for the given
    field name.
    """

    def filter_func(record: Record) -> bool:
        return hasattr(record, field_name) and getattr(record, field_name) == field_value

    return filter(filter_func, records)


class MicrosoftDefenderPlugin(Plugin):
    """Plugin that parses artifacts created by Microsoft Defender.

    This includes the EVTX logs, as well as recovery of artefacts from the quarantine folder.
    """

    __namespace__ = "defender"

    def check_compatible(self) -> None:
        # Either the Defender log folder, the quarantine folder or the exclusions registry key
        # has to exist for this plugin to be compatible.

        if not any(
            [
                self.target.fs.path(DEFENDER_LOG_DIR).exists(),
                self.target.fs.path(DEFENDER_QUARANTINE_DIR).exists(),
                (
                    self.target.has_function("registry")
                    and len(list(self.target.registry.keys(DEFENDER_EXCLUSION_KEY))) > 0
                ),
            ]
        ):
            raise UnsupportedPluginError("No Defender objects found")

    @export(record=DefenderLogRecord)
    def evtx(self) -> Iterator[DefenderLogRecord]:
        """Parse Microsoft Defender evtx log files."""

        defender_evtx_field_names = [field_name for _, field_name in DEFENDER_EVTX_FIELDS]

        evtx_records = self.target.evtx(logs_dir=DEFENDER_LOG_DIR, log_file_glob=DEFENDER_LOG_FILENAME_GLOB)
        defender_evtx_records = filter_records(evtx_records, "Provider_Name", "Microsoft-Windows-Windows Defender")

        for evtx_record in defender_evtx_records:
            record_fields = {}
            for field_name in defender_evtx_field_names:
                if not hasattr(evtx_record, field_name):
                    continue

                value = getattr(evtx_record, field_name)

                if field_name == "Detection_Time" and value:
                    value = parse_iso_datetime(value)

                record_fields[field_name] = value

            yield DefenderLogRecord(**record_fields, _target=self.target)

    @export(record=[DefenderQuarantineRecord, DefenderFileQuarantineRecord])
    def quarantine(self) -> Iterator[DefenderQuarantineRecord | DefenderFileQuarantineRecord]:
        """Parse the quarantine folder of Microsoft Defender for quarantine entry resources.

        Quarantine entry resources contain metadata about detected threats that Microsoft Defender has placed in
        quarantine.
        """
        for entry in self.get_quarantine_entries():
            # These fields are present for all (currently known) quarantine entry types
            fields = {
                "ts": entry.timestamp,
                "quarantine_id": entry.quarantine_id,
                "scan_id": entry.scan_id,
                "threat_id": entry.threat_id,
                "detection_name": entry.detection_name,
            }
            for resource in entry.resources:
                fields.update({"detection_type": resource.detection_type})
                if resource.detection_type == b"file":
                    # These fields are only available for file based detections
                    fields.update(
                        {
                            "detection_path": resource.detection_path,
                            "creation_time": resource.creation_time,
                            "last_write_time": resource.last_write_time,
                            "last_accessed_time": resource.last_access_time,
                            "resource_id": resource.resource_id,
                        }
                    )
                    yield DefenderFileQuarantineRecord(**fields, _target=self.target)
                else:
                    # For these types, we know that they have no known additional data to add to the Quarantine Record.
                    if resource.detection_type not in DEFENDER_KNOWN_DETECTION_TYPES:
                        self.target.log.warning(
                            "Unknown Defender Detection Type %s, yielding a generic quarantine record.",
                            resource.detection_type,
                        )
                    # For anything other than a file, we yield a generic DefenderQuarantineRecord.
                    yield DefenderQuarantineRecord(**fields, _target=self.target)

    @export(record=DefenderExclusionRecord)
    def exclusions(self) -> Iterator[DefenderExclusionRecord]:
        """Yield Microsoft Defender exclusions from the Registry."""

        # Iterate through all possible versions of the key for Defender exclusions
        for exclusions_registry_key in self.target.registry.keys(DEFENDER_EXCLUSION_KEY):
            # Every subkey of the exclusions key is a 'type' of exclusion, e.g. 'path' 'process' or 'extension'.
            for exclusion_type_subkey in exclusions_registry_key.subkeys():
                # Every value is an exclusion for a said type. The 'name' property of said registry value holds
                # what is being excluded from Defender (e.g. powershell.exe, notepad.txt)
                for exclusion in exclusion_type_subkey.values():
                    exclusion_value = exclusion.name
                    exclusion_type = exclusion_type_subkey.name
                    # Due to the fact that every exclusion is a registry value and not a registry key, we can only know
                    # the last modified timestamp of the exclusion type for a given exclusion, not a timestamp for the
                    # exclusion itself. We reflect this to the analyst by using the regf_mtime field.
                    yield DefenderExclusionRecord(
                        regf_mtime=exclusion_type_subkey.timestamp,
                        type=exclusion_type,
                        value=exclusion_value,
                        _target=self.target,
                    )

    def _mplog_processimage(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogProcessImageRecord]:
        yield DefenderMPLogProcessImageRecord(**data)

    def _mplog_minfiluss(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogMinFilUSSRecord]:
        yield DefenderMPLogMinFilUSSRecord(**data)

    def _mplog_blockedfile(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogMinFilBlockedFileRecord]:
        yield DefenderMPLogMinFilBlockedFileRecord(**data)

    def _mplog_bmtelemetry(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogBMTelemetryRecord]:
        data["ts"] = datetime.datetime.strptime(data["ts"], "%m-%d-%Y %H:%M:%S").replace(tzinfo=tzinfo)
        yield DefenderMPLogBMTelemetryRecord(**data)

    def _mplog_ems(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogEMSRecord]:
        yield DefenderMPLogEMSRecord(**data)

    def _mplog_originalfilename(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogOriginalFileNameRecord]:
        yield DefenderMPLogOriginalFileNameRecord(**data)

    def _mplog_exclusion(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogExclusionRecord]:
        yield DefenderMPLogExclusionRecord(**data)

    def _mplog_lowfi(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogLowfiRecord]:
        yield DefenderMPLogLowfiRecord(**data)

    def _mplog_detectionadd(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogDetectionAddRecord]:
        yield DefenderMPLogDetectionAddRecord(**data)

    def _mplog_threat(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogThreatRecord]:
        yield DefenderMPLogThreatRecord(**data)

    def _mplog_resourcescan(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogResourceScanRecord]:
        data["start_time"] = datetime.datetime.strptime(data["start_time"], "%m-%d-%Y %H:%M:%S").replace(tzinfo=tzinfo)
        data["end_time"] = datetime.datetime.strptime(data["end_time"], "%m-%d-%Y %H:%M:%S").replace(tzinfo=tzinfo)
        data["ts"] = data["start_time"]
        rest = data.pop("rest")
        yield DefenderMPLogResourceScanRecord(
            threats=re.findall("Threat Name:([^\n]+)", rest),
            resources=re.findall("Resource Path:([^\n]+)", rest),
            **data,
        )

    def _mplog_threataction(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogThreatActionRecord]:
        data["ts"] = datetime.datetime.strptime(data["ts"], "%m-%d-%Y %H:%M:%S").replace(tzinfo=tzinfo)
        rest = data.pop("rest")
        yield DefenderMPLogThreatActionRecord(
            threats=re.findall("Threat Name:([^\n]+)", rest),
            resources=re.findall("(?:Path|File Name):([^\n]+)", rest),
            actions=re.findall("Action:([^\n]+)", rest),
            **data,
        )

    def _mplog_rtp_log(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogRTPRecord]:
        times = {}
        for dtkey in ["ts", "last_perf", "first_rtp_scan"]:
            try:
                times[dtkey] = datetime.datetime.strptime(data[dtkey], "%m-%d-%Y %H:%M:%S").replace(tzinfo=tzinfo)
            except ValueError:  # noqa: PERF203
                pass

        yield DefenderMPLogRTPRecord(
            _target=self.target,
            source_log=data["source_log"],
            **times,
            plugin_states=re.findall(r"^\s+(.*)$", data["plugin_states"])[0],
            process_exclusions=re.findall(DEFENDER_MPLOG_LINE, data["process_exclusions"]),
            path_exclusions=re.findall(DEFENDER_MPLOG_LINE, data["path_exclusions"]),
            ext_exclusions=re.findall(DEFENDER_MPLOG_LINE, data["ext_exclusions"]),
        )

    def _mplog_detectionevent(
        self, data: dict, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogDetectionEventRecord]:
        yield DefenderMPLogDetectionEventRecord(**data)

    def _mplog_line(
        self, mplog_line: str, source: Path, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[
        DefenderMPLogProcessImageRecord
        | DefenderMPLogMinFilUSSRecord
        | DefenderMPLogMinFilBlockedFileRecord
        | DefenderMPLogEMSRecord
        | DefenderMPLogOriginalFileNameRecord
        | DefenderMPLogExclusionRecord
        | DefenderMPLogLowfiRecord
        | DefenderMPLogDetectionAddRecord
        | DefenderMPLogThreatRecord
        | DefenderMPLogDetectionEventRecord
    ]:
        for pattern, record in DEFENDER_MPLOG_PATTERNS:
            if match := pattern.match(mplog_line):
                data = match.groupdict()
                data["_target"] = self.target
                data["source_log"] = source
                yield from getattr(self, f"_mplog_{record.name.split('/')[-1:][0]}")(data, tzinfo=tzinfo)

    def _mplog_block(
        self, mplog_line: str, mplog: TextIO, source: Path, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[DefenderMPLogResourceScanRecord | DefenderMPLogThreatActionRecord | DefenderMPLogRTPRecord]:
        block = ""
        for prefix, suffix, pattern, record in DEFENDER_MPLOG_BLOCK_PATTERNS:
            if prefix.search(mplog_line):
                block += mplog_line

                while mplog_line := mplog.readline():
                    block += mplog_line
                    if suffix.search(mplog_line):
                        break
                match = pattern.match(block)
                if not match:
                    return

                data = match.groupdict()
                data["_target"] = self.target
                data["source_log"] = source
                yield from getattr(self, f"_mplog_{record.name.split('/')[-1:][0]}")(data, tzinfo=tzinfo)

    def _mplog(
        self, mplog: TextIO, source: Path, tzinfo: datetime.tzinfo = datetime.timezone.utc
    ) -> Iterator[
        DefenderMPLogProcessImageRecord
        | DefenderMPLogMinFilUSSRecord
        | DefenderMPLogMinFilBlockedFileRecord
        | DefenderMPLogBMTelemetryRecord
        | DefenderMPLogEMSRecord
        | DefenderMPLogOriginalFileNameRecord
        | DefenderMPLogExclusionRecord
        | DefenderMPLogLowfiRecord
        | DefenderMPLogDetectionAddRecord
        | DefenderMPLogThreatRecord
        | DefenderMPLogDetectionEventRecord
        | DefenderMPLogResourceScanRecord
        | DefenderMPLogThreatActionRecord
        | DefenderMPLogRTPRecord
    ]:
        while mplog_line := mplog.readline():
            yield from self._mplog_line(mplog_line, source, tzinfo=tzinfo)
            yield from self._mplog_block(mplog_line, mplog, source, tzinfo=tzinfo)

    @export(
        record=[
            DefenderMPLogProcessImageRecord,
            DefenderMPLogMinFilUSSRecord,
            DefenderMPLogMinFilBlockedFileRecord,
            DefenderMPLogBMTelemetryRecord,
            DefenderMPLogEMSRecord,
            DefenderMPLogOriginalFileNameRecord,
            DefenderMPLogExclusionRecord,
            DefenderMPLogLowfiRecord,
            DefenderMPLogDetectionAddRecord,
            DefenderMPLogThreatRecord,
            DefenderMPLogDetectionEventRecord,
            DefenderMPLogResourceScanRecord,
            DefenderMPLogThreatActionRecord,
            DefenderMPLogRTPRecord,
        ]
    )
    def mplog(
        self,
    ) -> Iterator[
        DefenderMPLogProcessImageRecord
        | DefenderMPLogMinFilUSSRecord
        | DefenderMPLogMinFilBlockedFileRecord
        | DefenderMPLogBMTelemetryRecord
        | DefenderMPLogEMSRecord
        | DefenderMPLogOriginalFileNameRecord
        | DefenderMPLogExclusionRecord
        | DefenderMPLogLowfiRecord
        | DefenderMPLogDetectionAddRecord
        | DefenderMPLogThreatRecord
        | DefenderMPLogDetectionEventRecord
        | DefenderMPLogResourceScanRecord
        | DefenderMPLogThreatActionRecord
        | DefenderMPLogRTPRecord
    ]:
        """Return the contents of the Defender MPLog file.

        References:
            - https://www.crowdstrike.com/blog/how-to-use-microsoft-protection-logging-for-forensic-investigations/
            - https://www.intrinsec.com/hunt-mplogs/
            - https://github.com/Intrinsec/mplog_parser
        """
        target_tz = self.target.datetime.tzinfo

        mplog_directory = self.target.fs.path(DEFENDER_MPLOG_DIR)

        if not (mplog_directory.exists() and mplog_directory.is_dir()):
            return

        for mplog_file in mplog_directory.glob("MPLog-*"):
            for encoding in ["UTF-16", "UTF-8"]:
                try:
                    with mplog_file.open("rt", encoding=encoding) as mplog:
                        yield from self._mplog(mplog, self.target.fs.path(mplog_file), tzinfo=target_tz)
                    break
                except UnicodeError:
                    continue

    @arg(
        "-o",
        "--output",
        dest="output_dir",
        type=Path,
        required=True,
        help="Path to recover quarantined file to.",
    )
    @export(output="none")
    def recover(self, output_dir: Path) -> None:
        """Recover files that have been placed into quarantine by Microsoft Defender.

        Microsoft Defender RC4 encrypts the output of the 'BackupRead' function when it places a file into quarantine.
        This means multiple data streams can be contained in a single quarantined file, including zone identifier
        information.
        """
        if not output_dir.exists():
            raise ValueError("Output directory does not exist")

        quarantine_directory = self.target.fs.path(DEFENDER_QUARANTINE_DIR)
        resourcedata_directory = quarantine_directory.joinpath("ResourceData")
        if resourcedata_directory.exists() and resourcedata_directory.is_dir():
            recovered_files = []
            for entry in self.get_quarantine_entries():
                for resource in entry.resources:
                    if resource.detection_type != b"file":
                        # We can only recover file entries
                        continue
                    # First two characters of the resource ID is the subdirectory that will contain the quarantined file
                    subdir = resource.resource_id[0:2]
                    resourcedata_location = resourcedata_directory.joinpath(subdir).joinpath(resource.resource_id)
                    if not resourcedata_location.exists():
                        self.target.log.warning("Could not find a ResourceData file for %s", resource.resource_id)
                        continue
                    if not resourcedata_location.is_file():
                        self.target.log.warning("%s is not a file!", resourcedata_location)
                        continue
                    if resourcedata_location in recovered_files:
                        # We already recovered this file
                        continue
                    with resourcedata_location.open() as fh:
                        # We restore the file with the resource_id as its filename. While we could 'guess' the filename
                        # based on the information we have from the associated quarantine entry, there is a potential
                        # that different files have the same filename. Analysts can use the quarantine records to cross
                        # reference.
                        for dest_filename, dest_buf in recover_quarantined_file_streams(fh, resource.resource_id):
                            output_filename = output_dir.joinpath(dest_filename)
                            self.target.log.info("Saving %s", output_filename)
                            output_filename.write_bytes(dest_buf)

                    # Make sure we do not recover the same file multiple times if it has multiple entries
                    recovered_files.append(resourcedata_location)

    def get_quarantine_entries(self) -> Iterator[QuarantineEntry]:
        """Yield Windows Defender quarantine entries."""
        quarantine_directory = self.target.fs.path(DEFENDER_QUARANTINE_DIR)
        entries_directory = quarantine_directory.joinpath("entries")

        if not entries_directory.is_dir():
            return
        for guid_path in entries_directory.iterdir():
            if not guid_path.exists() or not guid_path.is_file():
                continue
            with guid_path.open() as entry_fh:
                entry = QuarantineEntry(entry_fh)

            # Warn on discovery of fields that we do not have knowledge of what they are / do.
            for resource in entry.resources:
                for unknown_field in resource.unknown_fields:
                    self.target.log.warning("Encountered an unknown field identifier: %s", unknown_field.Identifier)
            yield entry
