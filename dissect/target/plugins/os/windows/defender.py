from typing import Generator, Iterable, Any
from datetime import datetime, timezone

from flow.record import Record

from dissect.target import plugin
from dissect.target.helpers.record import TargetRecordDescriptor

DEFENDER_EVTX_FIELDS = [
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


DefenderLogRecordDescriptor = TargetRecordDescriptor(
    "filesystem/windows/defender/evtx",
    [("datetime", "ts")] + DEFENDER_EVTX_FIELDS,
)

DEFENDER_LOG_DIR = "sysvol/windows/system32/winevt/logs"
DEFENDER_LOG_FILENAME_GLOB = "Microsoft-Windows-Windows Defender*"

EVTX_PROVIDER_NAME = "Microsoft-Windows-Windows Defender"


class MicrosoftDefenderPlugin(plugin.Plugin):
    """Plugin that parses artifacts created by Microsoft Defender"""

    __namespace__ = "defender"

    def check_compatible(self):
        return self.target.fs.path(DEFENDER_LOG_DIR).exists()

    @plugin.export(record=DefenderLogRecordDescriptor)
    def evtx(self) -> Generator[Record, None, None]:
        """Parse Microsoft Defender evtx log files"""

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

            yield DefenderLogRecordDescriptor(**record_fields)


def parse_iso_datetime(datetime_value: str) -> datetime:
    """Parse ISO8601 serialized datetime with `Z` ending"""
    return datetime.strptime(datetime_value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def filter_records(records: Iterable, field_name: str, field_value: Any) -> Generator[Record, None, None]:
    def filter_func(record: Record) -> bool:
        return hasattr(record, field_name) and getattr(record, field_name) == field_value

    return filter(filter_func, records)
