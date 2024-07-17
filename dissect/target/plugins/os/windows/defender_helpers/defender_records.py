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
