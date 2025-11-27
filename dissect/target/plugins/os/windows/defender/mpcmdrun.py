from __future__ import annotations

from dissect.target.helpers.record import TargetRecordDescriptor

DefenderMpCmdRunLogRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/mpcmdrunlog",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("string", "command"),
        ("path", "source"),
    ],
)
