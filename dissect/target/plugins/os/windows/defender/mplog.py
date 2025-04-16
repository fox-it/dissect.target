from __future__ import annotations

import re

from dissect.target.helpers.record import TargetRecordDescriptor

DefenderMPLogProcessImageRecord = TargetRecordDescriptor(
    "windows/defender/mplog/processimage",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "process_image_name"),
        ("varint", "pid"),
        ("varint", "total_time"),
        ("varint", "count"),
        ("varint", "max_time"),
        ("string", "max_time_file"),
        ("varint", "estimated_impact"),
    ],
)

DefenderMPLogMinFilUSSRecord = TargetRecordDescriptor(
    "windows/defender/mplog/minfiluss",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("path", "path"),
        ("string", "process"),
        ("string", "status"),
        ("string", "state"),
        ("string", "scan_request"),
        ("string", "file_id"),
        ("string", "reason"),
        ("string", "io_status_block_for_new_file"),
        ("string", "desired_access"),
        ("string", "file_attributes"),
        ("string", "scan_attributes"),
        ("string", "access_state_flags"),
        ("string", "backing_file_info"),
    ],
)

DefenderMPLogMinFilBlockedFileRecord = TargetRecordDescriptor(
    "windows/defender/mplog/blockedfile",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "blocked_file"),
        ("string", "process"),
        ("string", "status"),
        ("string", "state"),
        ("string", "scan_request"),
        ("string", "file_id"),
        ("string", "reason"),
        ("string", "io_status_block_for_new_file"),
        ("string", "desired_access"),
        ("string", "file_attributes"),
        ("string", "scan_attributes"),
        ("string", "access_state_flags"),
        ("string", "backing_file_info"),
    ],
)


DefenderMPLogBMTelemetryRecord = TargetRecordDescriptor(
    "windows/defender/mplog/bmtelemetry",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "guid"),
        ("varint", "signature_id"),
        ("string", "sigsha"),
        ("varint", "threat_level"),
        ("varint", "process_id"),
        ("varint", "process_creation_time"),
        ("varint", "session_id"),
        ("path", "image_path"),
        ("string", "taint_info"),
        ("string", "operations"),
    ],
)

DefenderMPLogEMSRecord = TargetRecordDescriptor(
    "windows/defender/mplog/ems",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "process"),
        ("varint", "pid"),
        ("string", "sigseq"),
        ("varint", "send_memory_scan_report"),
        ("varint", "source"),
    ],
)

DefenderMPLogOriginalFileNameRecord = TargetRecordDescriptor(
    "windows/defender/mplog/originalfilename",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "original_file_name"),
        ("path", "full_path"),
        ("string", "hr"),
    ],
)

DefenderMPLogExclusionRecord = TargetRecordDescriptor(
    "windows/defender/mplog/exclusion",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("path", "full_path_with_drive_letter"),
        ("path", "full_path_with_device_path"),
    ],
)

DefenderMPLogLowfiRecord = TargetRecordDescriptor(
    "windows/defender/mplog/lowfi",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("command", "lowfi"),
    ],
)

DefenderMPLogDetectionAddRecord = TargetRecordDescriptor(
    "windows/defender/mplog/detectionadd",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "detection"),
    ],
)


DefenderMPLogThreatRecord = TargetRecordDescriptor(
    "windows/defender/mplog/threat",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("command", "threat"),
    ],
)

DefenderMPLogDetectionEventRecord = TargetRecordDescriptor(
    "windows/defender/mplog/detectionevent",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "threat_type"),
        ("command", "command"),
    ],
)

DefenderMPLogResourceScanRecord = TargetRecordDescriptor(
    "windows/defender/mplog/resourcescan",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string", "scan_id"),
        ("varint", "scan_source"),
        ("datetime", "start_time"),
        ("datetime", "end_time"),
        ("string", "resource_schema"),
        ("path", "resource_path"),
        ("varint", "result_count"),
        ("string[]", "threats"),
        ("path[]", "resources"),
    ],
)

DefenderMPLogThreatActionRecord = TargetRecordDescriptor(
    "windows/defender/mplog/threataction",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("string[]", "threats"),
        ("path[]", "resources"),
        ("string[]", "actions"),
    ],
)

DefenderMPLogRTPRecord = TargetRecordDescriptor(
    "windows/defender/mplog/rtp_log",
    [
        ("datetime", "ts"),
        ("path", "source_log"),
        ("datetime", "last_perf"),
        ("datetime", "first_rtp_scan"),
        ("string", "plugin_states"),
        ("path[]", "process_exclusions"),
        ("path[]", "path_exclusions"),
        ("string[]", "ext_exclusions"),
    ],
)

DEFENDER_MPLOG_TS_PATTERN = r"(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z)"

# Loosely based on https://github.com/Intrinsec/mplog_parser but feel free to add patterns

DEFENDER_MPLOG_PATTERNS = [
    # Process Image
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s
                ProcessImageName:\s(?P<process_image_name>.*),\s
                Pid:\s(?P<pid>\d*),\s
                TotalTime:\s(?P<total_time>\d*),\s
                Count:\s(?P<count>\d*),\s
                MaxTime:\s(?P<max_time>\d*),\s
                MaxTimeFile:\s(?P<max_time_file>.*),\s
                EstimatedImpact:\s(?P<estimated_impact>\d*)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogProcessImageRecord,
    ),
    # Mini-filter Unsuccessful scan status
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s
                \[Mini-filter\]\s
                (Unsuccessful\sscan\sstatus)[^:]*:\s(?P<path>.+)\s
                Process:\s(?P<process>.+),\s
                Status:\s(?P<status>.+),\s
                State:\s(?P<state>.+),\s
                ScanRequest\s(?P<scan_request>.+),\s
                FileId:\s(?P<file_id>.+),\s
                Reason:\s(?P<reason>.+),\s
                IoStatusBlockForNewFile:\s(?P<io_status_block_for_new_file>.+),\s
                DesiredAccess:(?P<desired_access>.+),\s
                FileAttributes:(?P<file_attributes>.+),\s
                ScanAttributes:(?P<scan_attributes>.+),\s
                AccessStateFlags:(?P<access_state_flags>.+),\s
                BackingFileInfo:\s(?P<backing_file_info>.+)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogMinFilUSSRecord,
    ),
    # EMS Scan
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                process:\s(?P<process>\w*)\s
                pid:\s(?P<pid>\d*),\s
                sigseq:\s(?P<sigseq>\w*),\s
                sendMemoryScanReport:\s(?P<send_memory_scan_report>\d*),\s
                source:\s(?P<source>\d*)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogEMSRecord,
    ),
    # Original filename
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                original\sfile\sname\s\"(?P<original_file_name>.*)\"\sfor\s\"(?P<full_path>.*)\",\shr=(?P<hr>\w*)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogOriginalFileNameRecord,
    ),
    # Mini-filter Blocked file
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                \[Mini-filter\]\s
                Blocked\sfile:\s(?P<blocked_file>.+)\s
                Process:\s(?P<process>.+),\s
                Status:\s(?P<status>.+),\s
                State:\s(?P<state>.+),\s
                ScanRequest\s(?P<scan_request>.+),\s
                FileId:\s(?P<file_id>.+),\s
                Reason:\s(?P<reason>.+),\s
                IoStatusBlockForNewFile:\s(?P<io_status_block_for_new_file>.+),\s
                DesiredAccess:(?P<desired_access>.+),\s
                FileAttributes:(?P<file_attributes>.+),\s
                ScanAttributes:(?P<scan_attributes>.+),\s
                AccessStateFlags:(?P<access_state_flags>.+),\s
                BackingFileInfo:\s(?P<backing_file_info>.+)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogMinFilBlockedFileRecord,
    ),
    # Exclusion
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s
                \[Exclusion\]\s(?P<full_path_with_drive_letter>.+)\s->\s(?P<full_path_with_device_path>.+)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogExclusionRecord,
    ),
    # Lowfi
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                lowfi:\s(?P<lowfi>.+)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogLowfiRecord,
    ),
    # Detection add
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                DETECTION_ADD\S*\s(?P<detection>.*)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogDetectionAddRecord,
    ),
    # Threat
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                threat:\s(?P<threat>.*)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogThreatRecord,
    ),
    # Detection event
    (
        re.compile(
            rf"""
                {DEFENDER_MPLOG_TS_PATTERN}\s.*
                DETECTIONEVENT\sMPSOURCE_\S+\sHackTool:(?P<threat_type>.*)\sfile:(?P<command>.*)
            """,
            re.VERBOSE,
        ),
        DefenderMPLogDetectionEventRecord,
    ),
]


DEFENDER_MPLOG_BLOCK_PATTERNS = [
    (
        re.compile(r"Begin Resource Scan"),
        re.compile(r"End Scan"),
        re.compile(
            r"""
                Begin\sResource\sScan.*\n
                Scan\sID:(?P<scan_id>[^\n]+)\n
                Scan\sSource:(?P<scan_source>\d+)\n
                Start\sTime:(?P<start_time>[0-9\-\:\s]*)\n
                End\sTime:(?P<end_time>[0-9\-\:\s]*)\n
                .*
                Resource\sSchema:(?P<resource_schema>[^\n]+)\n
                Resource\sPath:(?P<resource_path>[^\n]+)\n
                Result\sCount:(?P<result_count>\d+)\n
                (?P<rest>.*)\n
                End\sScan
            """,
            re.VERBOSE | re.MULTILINE | re.DOTALL,
        ),
        DefenderMPLogResourceScanRecord,
    ),
    # Threat actions
    (
        re.compile(r"Beginning threat actions"),
        re.compile(r"Finished threat actions"),
        re.compile(
            r"""
            Beginning\sthreat\sactions\n
            Start\stime:(?P<ts>[0-9\-\:\s]*)\n
            (?P<rest>.*)\n
            Finished\sthreat\sactions
            """,
            re.VERBOSE | re.MULTILINE | re.DOTALL,
        ),
        DefenderMPLogThreatActionRecord,
    ),
    # RTP
    (
        re.compile(r"\*\*RTP Perf Log\*\*"),
        re.compile(r"\*\*END RTP Perf Log\*\*"),
        re.compile(
            r"""
            \*+RTP\sPerf\sLog\*+\n
            RTP\sStart:(?P<ts>.*)\n
            Last\sPerf:(?P<last_perf>.*)\n
            First\sRTP\sScan:(?P<first_rtp_scan>.*)\n
            Plugin\sStates:(?P<plugin_states>.*)\n
            Process\sExclusions:\n(?P<process_exclusions>.*)
            Path\sExclusions:\n(?P<path_exclusions>.*)
            Ext\sExclusions:\n(?P<ext_exclusions>.*)
            Worker\sThreads
            """,
            re.VERBOSE | re.MULTILINE | re.DOTALL,
        ),
        DefenderMPLogRTPRecord,
    ),
    # BM Telemetry (block)
    (
        re.compile(r"BEGIN BM telemetry"),
        re.compile(r"END BM telemetry"),
        re.compile(
            r"""
                BEGIN\sBM\stelemetry\n
                (GUID):(?P<guid>.+)\n
                (SignatureID):(?P<signature_id>.+)\n
                (SigSha):(?P<sigsha>.+)\n
                (ThreatLevel):(?P<threat_level>.+)\n
                (ProcessID):(?P<process_id>.+)\n
                (ProcessCreationTime):(?P<process_creation_time>.+)\n
                (SessionID):(?P<session_id>.+)\n
                (CreationTime):(?P<ts>.+)\n
                (ImagePath):(?P<image_path>.+)\n
                (Taint\sInfo):(?P<taint_info>.+)\n
                (Operations):(?P<operations>.+)\n
                END\sBM\stelemetry
            """,
            re.VERBOSE,
        ),
        DefenderMPLogBMTelemetryRecord,
    ),
]

DEFENDER_MPLOG_LINE = re.compile(r"^\s+(.*)$", re.MULTILINE)
