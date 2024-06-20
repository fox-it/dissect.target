import re

from dissect.target.plugins.os.windows.defender_helpers.defender_records import (
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

DEFENDER_MPLOG_TS_PATTERN = r"(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z) "

# Loosely based on https://github.com/Intrinsec/mplog_parser but feel free to add patterns

DEFENDER_MPLOG_PATTERNS = [
    # Process Image
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r"ProcessImageName: (?P<process_image_name>.*), ",
                    r"Pid: (?P<pid>\d*), ",
                    r"TotalTime: (?P<total_time>\d*), ",
                    r"Count: (?P<count>\d*), ",
                    r"MaxTime: (?P<max_time>\d*), ",
                    r"MaxTimeFile: (?P<max_time_file>.*), ",
                    r"EstimatedImpact: (?P<estimated_impact>\d*)",
                ]
            )
        ),
        DefenderMPLogProcessImageRecord,
    ),
    # Mini-filter Unsuccessful scan status
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r"\[Mini-filter\] (Unsuccessful scan status)[^:]*: (?P<path>.+) ",
                    r"Process: (?P<process>.+), ",
                    r"Status: (?P<status>.+), ",
                    r"State: (?P<state>.+), ",
                    r"ScanRequest (?P<scan_request>.+), ",
                    r"FileId: (?P<file_id>.+), ",
                    r"Reason: (?P<reason>.+), ",
                    r"IoStatusBlockForNewFile: (?P<io_status_block_for_new_file>.+), ",
                    r"DesiredAccess:(?P<desired_access>.+), ",
                    r"FileAttributes:(?P<file_attributes>.+), ",
                    r"ScanAttributes:(?P<scan_attributes>.+), ",
                    r"AccessStateFlags:(?P<access_state_flags>.+), ",
                    r"BackingFileInfo: (?P<backing_file_info>.+)",
                ]
            )
        ),
        DefenderMPLogMinFilUSSRecord,
    ),
    # EMS Scan
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"process: (?P<process>\w*) ",
                    r"pid: (?P<pid>\d*), ",
                    r"sigseq: (?P<sigseq>\w*), ",
                    r"sendMemoryScanReport: (?P<send_memory_scan_report>\d*), ",
                    r"source: (?P<source>\d*)",
                ]
            )
        ),
        DefenderMPLogEMSRecord,
    ),
    # Original filename
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"original file name \"(?P<original_file_name>.*)\" ",
                    r"for \"(?P<full_path>.*)\", ",
                    r"hr=(?P<hr>\w*)",
                ]
            )
        ),
        DefenderMPLogOriginalFileNameRecord,
    ),
    # Mini-filter Blocked file
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"\[Mini-filter\] Blocked file: (?P<blocked_file>.+) ",
                    r"Process: (?P<process>.+), ",
                    r"Status: (?P<status>.+), ",
                    r"State: (?P<state>.+), ",
                    r"ScanRequest (?P<scan_request>.+), ",
                    r"FileId: (?P<file_id>.+), ",
                    r"Reason: (?P<reason>.+), ",
                    r"IoStatusBlockForNewFile: (?P<io_status_block_for_new_file>.+), ",
                    r"DesiredAccess:(?P<desired_access>.+), ",
                    r"FileAttributes:(?P<file_attributes>.+), ",
                    r"ScanAttributes:(?P<scan_attributes>.+), ",
                    r"AccessStateFlags:(?P<access_state_flags>.+), ",
                    r"BackingFileInfo: (?P<backing_file_info>.+)",
                ]
            )
        ),
        DefenderMPLogMinFilBlockedFileRecord,
    ),
    # Exclusion
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r"\[Exclusion\] (?P<full_path_with_drive_letter>.+) ",
                    r"-> (?P<full_path_with_device_path>.+)",
                ]
            )
        ),
        DefenderMPLogExclusionRecord,
    ),
    # Lowfi
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"lowfi: (?P<lowfi>.+)",
                ]
            )
        ),
        DefenderMPLogLowfiRecord,
    ),
    # Detection add
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"DETECTION_ADD\S* (?P<detection>.*)",
                ]
            )
        ),
        DefenderMPLogDetectionAddRecord,
    ),
    # Threat
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"threat: (?P<threat>.*)",
                ]
            )
        ),
        DefenderMPLogThreatRecord,
    ),
    # Detection event
    (
        re.compile(
            "".join(
                [
                    DEFENDER_MPLOG_TS_PATTERN,
                    r".*",
                    r"DETECTIONEVENT MPSOURCE_\S+ HackTool:(?P<threat_type>.*) file:(?P<command>.*)",
                ]
            )
        ),
        DefenderMPLogDetectionEventRecord,
    ),
]


DEFENDER_MPLOG_BLOCK_PATTERNS = [
    (
        re.compile(r"Begin Resource Scan"),
        re.compile(r"End Scan"),
        re.compile(
            "".join(
                [
                    r"Begin Resource Scan.*\n",
                    r"Scan ID:(?P<scan_id>[^\n]+)\n",
                    r"Scan Source:(?P<scan_source>\d+)\n",
                    r"Start Time:(?P<start_time>[0-9\-\:\s]*)\n",
                    r"End Time:(?P<end_time>[0-9\-\:\s]*)\n",
                    r".*",
                    r"Resource Schema:(?P<resource_schema>[^\n]+)\n",
                    r"Resource Path:(?P<resource_path>[^\n]+)\n",
                    r"Result Count:(?P<result_count>\d+)\n",
                    r"(?P<rest>.*)\n",
                    r"End Scan",
                ]
            ),
            re.MULTILINE | re.DOTALL,
        ),
        DefenderMPLogResourceScanRecord,
    ),
    # Threat actions
    (
        re.compile(r"Beginning threat actions"),
        re.compile(r"Finished threat actions"),
        re.compile(
            "".join(
                [
                    r"Beginning threat actions\n",
                    r"Start time:(?P<ts>[0-9\-\:\s]*)\n",
                    r"(?P<rest>.*)\n",
                    r"Finished threat actions",
                ]
            ),
            re.MULTILINE | re.DOTALL,
        ),
        DefenderMPLogThreatActionRecord,
    ),
    # RTP
    (
        re.compile(r"\*\*RTP Perf Log\*\*"),
        re.compile(r"\*\*END RTP Perf Log\*\*"),
        re.compile(
            "".join(
                [
                    r"\*+RTP Perf Log\*+\n",
                    r"RTP Start:(?P<ts>.*)\n",
                    r"Last Perf:(?P<last_perf>.*)\n",
                    r"First RTP Scan:(?P<first_rtp_scan>.*)\n",
                    r"Plugin States:(?P<plugin_states>.*)\n",
                    r"Process Exclusions:\n(?P<process_exclusions>.*)",
                    r"Path Exclusions:\n(?P<path_exclusions>.*)",
                    r"Ext Exclusions:\n(?P<ext_exclusions>.*)",
                    r"Worker Threads",
                ]
            ),
            re.MULTILINE | re.DOTALL,
        ),
        DefenderMPLogRTPRecord,
    ),
    # BM Telemetry (block)
    (
        re.compile(r"BEGIN BM telemetry"),
        re.compile(r"END BM telemetry"),
        re.compile(
            "".join(
                [
                    r"BEGIN BM telemetry\n",
                    r"(GUID):(?P<guid>.+)\n",
                    r"(SignatureID):(?P<signature_id>.+)\n",
                    r"(SigSha):(?P<sigsha>.+)\n",
                    r"(ThreatLevel):(?P<threat_level>.+)\n",
                    r"(ProcessID):(?P<process_id>.+)\n",
                    r"(ProcessCreationTime):(?P<process_creation_time>.+)\n",
                    r"(SessionID):(?P<session_id>.+)\n",
                    r"(CreationTime):(?P<ts>.+)\n",
                    r"(ImagePath):(?P<image_path>.+)\n",
                    r"(Taint Info):(?P<taint_info>.+)\n",
                    r"(Operations):(?P<operations>.+)\n",
                    r"END BM telemetry",
                ]
            )
        ),
        DefenderMPLogBMTelemetryRecord,
    ),
]

DEFENDER_MPLOG_LINE = re.compile(r"^\s+(.*)$", re.MULTILINE)
