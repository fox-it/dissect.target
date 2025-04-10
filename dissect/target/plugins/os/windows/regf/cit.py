from __future__ import annotations

import datetime
import struct
from binascii import crc32
from io import BytesIO
from typing import TYPE_CHECKING, Union, get_args

from dissect.cstruct import cstruct
from dissect.util.compression import lznt1
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
    create_extended_descriptor,
)
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record import Record

    from dissect.target.target import Target

# Resources:
# - generaltel.dll
# - win32k.sys (Windows 7)
# - win32kbase.sys (Windows 10)
cit_def = """
typedef QWORD FILETIME;

flag TELEMETRY_ANSWERS {
    Unknown0        = 0x4,
    Unknown1        = 0x8,
    POWERBROADCAST  = 0x10000,
    DEVICECHANGE    = 0x20000,
    IME_CONTROL     = 0x40000,
    WINHELP         = 0x80000,
};

typedef struct _CIT_HEADER {
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Size;                   /* Size of the entire buffer */
    FILETIME    CurrentTimeLocal;   /* Maybe the time when the saved CIT was last updated? */
    DWORD   Crc32;                  /* Crc32 of the entire buffer, skipping this field */
    DWORD   EntrySize;
    DWORD   EntryCount;
    DWORD   EntryDataOffset;
    DWORD   SystemDataSize;
    DWORD   SystemDataOffset;
    DWORD   BaseUseDataSize;
    DWORD   BaseUseDataOffset;
    FILETIME    StartTimeLocal;     /* Presumably when the aggregation started */
    FILETIME    PeriodStartLocal;   /* Presumably the starting point of the aggregation period */
    DWORD   AggregationPeriodInS;   /* Presumably the duration over which this data was gathered
                                     * Always 604800 (7 days) */
    DWORD   BitPeriodInS;           /* Presumably the amount of seconds a single bit represents
                                     * Always 3600 (1 hour) */
    DWORD   SingleBitmapSize;       /* This appears to be the sizes of the Stats buffers, always 21 */
    DWORD   _Unk0;                  /* Always 0x00000100? */
    DWORD   HeaderSize;
    DWORD   _Unk1;                  /* Always 0x00000000? */
} CIT_HEADER;

typedef struct _CIT_PERSISTED {
    DWORD   BitmapsOffset;          /* Array of Offset and Size (DWORD, DWORD) */
    DWORD   BitmapsSize;
    DWORD   SpanStatsOffset;        /* Array of Count and Duration (DWORD, DWORD) */
    DWORD   SpanStatsSize;
    DWORD   StatsOffset;            /* Array of WORD */
    DWORD   StatsSize;
} CIT_PERSISTED;

typedef struct _CIT_ENTRY {
    DWORD   ProgramDataOffset;      /* Offset to CIT_PROGRAM_DATA */
    DWORD   UseDataOffset;          /* Offset to CIT_PERSISTED */
    DWORD   ProgramDataSize;
    DWORD   UseDataSize;
} CIT_ENTRY;

typedef struct _CIT_PROGRAM_DATA {
    DWORD   FilePathOffset;         /* Offset to UTF-16-LE file path string */
    DWORD   FilePathSize;           /* strlen of string */
    DWORD   CommandLineOffset;      /* Offset to UTF-16-LE command line string */
    DWORD   CommandLineSize;        /* strlen of string */
    DWORD   PeTimeDateStamp;        /* aka Extra1 */
    DWORD   PeCheckSum;             /* aka Extra2 */
    DWORD   Extra3;                 /* aka Extra3, some flag from PROCESSINFO struct */
} CIT_PROGRAM_DATA;

typedef struct _CIT_BITMAP_ITEM {
    DWORD   Offset;
    DWORD   Size;
} CIT_BITMAP_ITEM;

typedef struct _CIT_SPAN_STAT_ITEM {
    DWORD   Count;
    DWORD   Duration;
} CIT_SPAN_STAT_ITEM;

typedef struct _CIT_SYSTEM_DATA_SPAN_STATS {
    CIT_SPAN_STAT_ITEM  ContextFlushes0;
    CIT_SPAN_STAT_ITEM  Foreground0;
    CIT_SPAN_STAT_ITEM  Foreground1;
    CIT_SPAN_STAT_ITEM  DisplayPower0;
    CIT_SPAN_STAT_ITEM  DisplayRequestChange;
    CIT_SPAN_STAT_ITEM  DisplayPower1;
    CIT_SPAN_STAT_ITEM  DisplayPower2;
    CIT_SPAN_STAT_ITEM  DisplayPower3;
    CIT_SPAN_STAT_ITEM  ContextFlushes1;
    CIT_SPAN_STAT_ITEM  Foreground2;
    CIT_SPAN_STAT_ITEM  ContextFlushes2;
} CIT_SYSTEM_DATA_SPAN_STATS;

typedef struct _CIT_USE_DATA_SPAN_STATS {
    CIT_SPAN_STAT_ITEM  ProcessCreation0;
    CIT_SPAN_STAT_ITEM  Foreground0;
    CIT_SPAN_STAT_ITEM  Foreground1;
    CIT_SPAN_STAT_ITEM  Foreground2;
    CIT_SPAN_STAT_ITEM  ProcessSuspended;
    CIT_SPAN_STAT_ITEM  ProcessCreation1;
} CIT_USE_DATA_SPAN_STATS;

typedef struct _CIT_SYSTEM_DATA_STATS {
    WORD    Unknown_BootIdRelated0;
    WORD    Unknown_BootIdRelated1;
    WORD    Unknown_BootIdRelated2;
    WORD    Unknown_BootIdRelated3;
    WORD    Unknown_BootIdRelated4;
    WORD    SessionConnects;
    WORD    ProcessForegroundChanges;
    WORD    ContextFlushes;
    WORD    MissingProgData;
    WORD    DesktopSwitches;
    WORD    WinlogonMessage;
    WORD    WinlogonLockHotkey;
    WORD    WinlogonLock;
    WORD    SessionDisconnects;
} CIT_SYSTEM_DATA_STATS;

typedef struct _CIT_USE_DATA_STATS {
    WORD    Crashes;
    WORD    ThreadGhostingChanges;
    WORD    Input;
    WORD    InputKeyboard;
    WORD    Unknown;
    WORD    InputTouch;
    WORD    InputHid;
    WORD    InputMouse;
    WORD    MouseLeftButton;
    WORD    MouseRightButton;
    WORD    MouseMiddleButton;
    WORD    MouseWheel;
} CIT_USE_DATA_STATS;

// PUU
typedef struct _CIT_POST_UPDATE_USE_INFO {
    DWORD   UpdateKey;
    WORD    UpdateCount;
    WORD    CrashCount;
    WORD    SessionCount;
    WORD    LogCount;
    DWORD   UserActiveDurationInS;
    DWORD   UserOrDispActiveDurationInS;
    DWORD   DesktopActiveDurationInS;
    WORD    Version;
    WORD    _Unk0;
    WORD    BootIdMin;
    WORD    BootIdMax;
    DWORD   PMUUKey;
    DWORD   SessionDurationInS;
    DWORD   SessionUptimeInS;
    DWORD   UserInputInS;
    DWORD   MouseInputInS;
    DWORD   KeyboardInputInS;
    DWORD   TouchInputInS;
    DWORD   PrecisionTouchpadInputInS;
    DWORD   InForegroundInS;
    DWORD   ForegroundSwitchCount;
    DWORD   UserActiveTransitionCount;
    DWORD   _Unk1;
    FILETIME    LogTimeStart;
    QWORD   CumulativeUserActiveDurationInS;
    WORD    UpdateCountAccumulationStarted;
    WORD    _Unk2;
    DWORD   BuildUserActiveDurationInS;
    DWORD   BuildNumber;
    DWORD   _UnkDeltaUserOrDispActiveDurationInS;
    DWORD   _UnkDeltaTime;
    DWORD   _Unk3;
} CIT_POST_UPDATE_USE_INFO;

// DP
typedef struct _CIT_DP_MEMOIZATION_ENTRY {
    DWORD   Unk0;
    DWORD   Unk1;
    DWORD   Unk2;
} CIT_DP_MEMOIZATION_ENTRY;

typedef struct _CIT_DP_MEMOIZATION_CONTEXT {
    _CIT_DP_MEMOIZATION_ENTRY   Entries[12];
} CIT_DP_MEMOIZATION_CONTEXT;

typedef struct _CIT_DP_DATA {
    WORD    Version;
    WORD    Size;
    WORD    LogCount;
    WORD    CrashCount;
    DWORD   SessionCount;
    DWORD   UpdateKey;
    QWORD   _Unk0;
    FILETIME    _UnkTime;
    FILETIME    LogTimeStart;
    DWORD   ForegroundDurations[11];
    DWORD   _Unk1;
    _CIT_DP_MEMOIZATION_CONTEXT MemoizationContext;
} CIT_DP_DATA;
"""

c_cit = cstruct().load(cit_def)


CITSystemRecord = TargetRecordDescriptor(
    "windows/registry/cit/system",
    [
        ("datetime", "period_start"),
        ("datetime", "start_time"),
        ("datetime", "current_time"),
        ("varint", "aggregation_period_in_s"),
        ("varint", "span_stats_context_flushes_0_count"),
        ("varint", "span_stats_context_flushes_0_duration"),
        ("varint", "span_stats_foreground_0_count"),
        ("varint", "span_stats_foreground_0_duration"),
        ("varint", "span_stats_foreground_1_count"),
        ("varint", "span_stats_foreground_1_duration"),
        ("varint", "span_stats_display_power_0_count"),
        ("varint", "span_stats_display_power_0_duration"),
        ("varint", "span_stats_display_request_change_count"),
        ("varint", "span_stats_display_request_change_duration"),
        ("varint", "span_stats_display_power_1_count"),
        ("varint", "span_stats_display_power_1_duration"),
        ("varint", "span_stats_display_power_2_count"),
        ("varint", "span_stats_display_power_2_duration"),
        ("varint", "span_stats_display_power_3_count"),
        ("varint", "span_stats_display_power_3_duration"),
        ("varint", "span_stats_context_flushes_1_count"),
        ("varint", "span_stats_context_flushes_1_duration"),
        ("varint", "span_stats_foreground_2_count"),
        ("varint", "span_stats_foreground_2_duration"),
        ("varint", "span_stats_context_flushes_2_count"),
        ("varint", "span_stats_context_flushes_2_duration"),
        ("varint", "stats_unk_boot_id_0"),
        ("varint", "stats_unk_boot_id_1"),
        ("varint", "stats_unk_boot_id_2"),
        ("varint", "stats_unk_boot_id_3"),
        ("varint", "stats_unk_boot_id_4"),
        ("varint", "stats_session_connects"),
        ("varint", "stats_process_foreground_changes"),
        ("varint", "stats_context_flushes"),
        ("varint", "stats_missing_prog_data"),
        ("varint", "stats_desktop_switches"),
        ("varint", "stats_winlogon_message"),
        ("varint", "stats_winlogon_lock_hotkey"),
        ("varint", "stats_winlogon_lock"),
        ("varint", "stats_session_disconnects"),
    ],
)


BITMAP_FIELDS = [
    ("datetime", "ts"),
    ("datetime", "period_start"),
    ("datetime", "start_time"),
    ("datetime", "current_time"),
    ("varint", "aggregation_period_in_s"),
    ("varint", "bit_period_in_s"),
]


CITSystemBitmapDisplayPowerRecord = TargetRecordDescriptor(
    "windows/registry/cit/system/bitmap/display_power",
    BITMAP_FIELDS,
)


CITSystemBitmapDisplayRequestChangeRecord = TargetRecordDescriptor(
    "windows/registry/cit/system/bitmap/display_request_change",
    BITMAP_FIELDS,
)


CITSystemBitmapInputRecord = TargetRecordDescriptor(
    "windows/registry/cit/system/bitmap/input",
    BITMAP_FIELDS,
)


CITSystemBitmapInputTouchRecord = TargetRecordDescriptor(
    "windows/registry/cit/system/bitmap/nput_touch",
    BITMAP_FIELDS,
)


CITSystemBitmapUnknownRecord = TargetRecordDescriptor(
    "windows/registry/cit/system/bitmap/unknown",
    BITMAP_FIELDS,
)


CITSystemBitmapForegroundRecord = TargetRecordDescriptor(
    "windows/registry/cit/system/bitmap/foreground",
    BITMAP_FIELDS,
)

CITProgramRecord = TargetRecordDescriptor(
    "windows/registry/cit/program",
    [
        ("datetime", "period_start"),
        ("datetime", "start_time"),
        ("datetime", "current_time"),
        ("varint", "aggregation_period_in_s"),
        ("path", "path"),
        ("string", "command_line"),
        ("datetime", "pe_timedatestamp"),
        ("varint", "pe_checksum"),
        ("varint", "extra3"),
        ("varint", "span_stats_process_creation_0_count"),
        ("varint", "span_stats_process_creation_0_duration"),
        ("varint", "span_stats_foreground_0_count"),
        ("varint", "span_stats_foreground_0_duration"),
        ("varint", "span_stats_foreground_1_count"),
        ("varint", "span_stats_foreground_1_duration"),
        ("varint", "span_stats_foreground_2_count"),
        ("varint", "span_stats_foreground_2_duration"),
        ("varint", "span_stats_process_suspended_count"),
        ("varint", "span_stats_process_suspended_duration"),
        ("varint", "span_stats_process_creation_1_count"),
        ("varint", "span_stats_process_creation_1_duration"),
        ("varint", "stats_crashes"),
        ("varint", "stats_thread_ghosting_changes"),
        ("varint", "stats_input"),
        ("varint", "stats_input_keyboard"),
        ("varint", "stats_unknown"),
        ("varint", "stats_input_touch"),
        ("varint", "stats_input_hid"),
        ("varint", "stats_input_mouse"),
        ("varint", "stats_mouse_left_button"),
        ("varint", "stats_mouse_right_button"),
        ("varint", "stats_mouse_middle_button"),
        ("varint", "stats_mouse_wheel"),
    ],
)


CITProgramBitmapForegroundRecord = TargetRecordDescriptor(
    "windows/registry/cit/program/bitmap/foreground",
    BITMAP_FIELDS,
)


CITRecords = Union[
    CITSystemRecord,
    CITSystemBitmapDisplayPowerRecord,
    CITSystemBitmapDisplayRequestChangeRecord,
    CITSystemBitmapInputRecord,
    CITSystemBitmapInputTouchRecord,
    CITSystemBitmapUnknownRecord,
    CITSystemBitmapForegroundRecord,
    CITProgramRecord,
]


CITPostUpdateUseInfoRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/registry/cit/puu",
    [
        ("datetime", "log_time_start"),
        ("varint", "update_key"),
        ("varint", "update_count"),
        ("varint", "crash_count"),
        ("varint", "session_count"),
        ("varint", "log_count"),
        ("varint", "user_active_duration_in_s"),
        ("varint", "user_or_display_active_duration_in_s"),
        ("varint", "desktop_active_duration_in_s"),
        ("varint", "version"),
        ("varint", "boot_id_min"),
        ("varint", "boot_id_max"),
        ("varint", "pmuu_key"),
        ("varint", "session_duration_in_s"),
        ("varint", "session_uptime_in_s"),
        ("varint", "user_input_in_s"),
        ("varint", "mouse_input_in_s"),
        ("varint", "keyboard_input_in_s"),
        ("varint", "touch_input_in_s"),
        ("varint", "precision_touchpad_input_in_s"),
        ("varint", "in_foreground_in_s"),
        ("varint", "foreground_switch_count"),
        ("varint", "user_active_transition_count"),
        ("varint", "cumulative_user_active_duration_in_s"),
        ("varint", "update_count_accumulation_started"),
        ("varint", "build_user_active_duration_in_s"),
        ("varint", "build_number"),
    ],
)


CITDPRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/registry/cit/dp",
    [
        ("datetime", "log_time_start"),
        ("varint", "update_key"),
        ("varint", "log_count"),
        ("varint", "crash_count"),
        ("varint", "session_count"),
    ],
)


CITDPDurationRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/registry/cit/dp/duration",
    [
        ("datetime", "log_time_start"),
        ("string", "application"),
        ("varint", "duration"),
    ],
)


CITTelemetryRecord = TargetRecordDescriptor(
    "windows/registry/cit/telemetry",
    [
        ("datetime", "regf_mtime"),
        ("varint", "version"),
        ("path", "path"),
        ("string", "value"),
    ],
)


CITModuleRecord = TargetRecordDescriptor(
    "windows/registry/cit/module",
    [
        ("datetime", "last_loaded"),
        ("datetime", "regf_mtime"),
        ("path", "tracked_module"),
        ("path", "executable"),
        ("datetime", "overflow_quota"),
        ("datetime", "overflow_value"),
    ],
)


class CIT:
    def __init__(self, buf: bytes):
        compressed_fh = BytesIO(buf)
        # Compressed size, uncompressed size
        _, _ = struct.unpack("<2I", compressed_fh.read(8))

        self.buf = lznt1.decompress(compressed_fh)

        self.header = c_cit.CIT_HEADER(self.buf)
        if self.header.MajorVersion != 0x0A:
            raise ValueError("Unsupported CIT version")

        digest = crc32(self.buf[0x14:], crc32(self.buf[:0x10]))
        if self.header.Crc32 != digest:
            raise ValueError("Crc32 mismatch")

        system_data_buf = self.data(self.header.SystemDataOffset, self.header.SystemDataSize, 0x18)
        self.system_data = SystemData(self, c_cit.CIT_PERSISTED(system_data_buf))

        base_use_data_buf = self.data(self.header.BaseUseDataOffset, self.header.BaseUseDataSize, 0x18)
        self.base_use_data = BaseUseData(self, c_cit.CIT_PERSISTED(base_use_data_buf))

        entry_data = self.buf[self.header.EntryDataOffset :]
        self.entries = [Entry(self, entry) for entry in c_cit.CIT_ENTRY[self.header.EntryCount](entry_data)]

    def data(self, offset: int, size: int, expected_size: int | None = None) -> bytes:
        if expected_size and size > expected_size:
            size = expected_size

        data = self.buf[offset : offset + size]

        if expected_size and size < expected_size:
            data.ljust(expected_size, b"\x00")

        return data

    def iter_bitmap(self, bitmap: bytes) -> Iterator[datetime.datetime]:
        bit_delta = datetime.timedelta(seconds=self.header.BitPeriodInS)
        ts = wintimestamp(self.header.PeriodStartLocal).replace(tzinfo=None)

        for byte in bitmap:
            if byte == b"\x00":
                ts += 8 * bit_delta
            else:
                for bit in range(8):
                    if byte & (1 << bit):
                        yield ts
                    ts += bit_delta


class Entry:
    def __init__(self, cit: CIT, entry: c_cit.CIT_ENTRY):
        self.cit = cit
        self.entry = entry

        program_buf = cit.data(entry.ProgramDataOffset, entry.ProgramDataSize, 0x1C)
        self.program_data = c_cit.CIT_PROGRAM_DATA(program_buf)

        use_data_buf = cit.data(entry.UseDataOffset, entry.UseDataSize, 0x18)
        self.use_data = ProgramUseData(cit, c_cit.CIT_PERSISTED(use_data_buf))

        self.file_path = None
        self.command_line = None

        if self.program_data.FilePathOffset:
            file_path_buf = cit.data(self.program_data.FilePathOffset, self.program_data.FilePathSize * 2)
            self.file_path = file_path_buf.decode("utf-16-le")

        if self.program_data.CommandLineOffset:
            command_line_buf = cit.data(self.program_data.CommandLineOffset, self.program_data.CommandLineSize * 2)
            self.command_line = command_line_buf.decode("utf-16-le")

    def __repr__(self) -> str:
        return f"<Entry file_path={self.file_path!r} command_line={self.command_line!r}>"


class BaseUseData:
    MIN_BITMAPS_SIZE = 0x8
    MIN_SPAN_STATS_SIZE = 0x30
    MIN_STATS_SIZE = 0x18

    def __init__(self, cit: CIT, entry: c_cit.CIT_ENTRY):
        self.cit = cit
        self.entry = entry

        bitmap_items = c_cit.CIT_BITMAP_ITEM[entry.BitmapsSize // len(c_cit.CIT_BITMAP_ITEM)](
            cit.data(entry.BitmapsOffset, entry.BitmapsSize, self.MIN_BITMAPS_SIZE)
        )
        bitmaps = [cit.data(item.Offset, item.Size) for item in bitmap_items]
        self.bitmaps = self._parse_bitmaps(bitmaps)
        self.span_stats = self._parse_span_stats(
            cit.data(entry.SpanStatsOffset, entry.SpanStatsSize, self.MIN_SPAN_STATS_SIZE)
        )
        self.stats = self._parse_stats(cit.data(entry.StatsOffset, entry.StatsSize, self.MIN_STATS_SIZE))

    def _parse_bitmaps(self, bitmaps: list[bytes]) -> BaseUseDataBitmaps:
        return BaseUseDataBitmaps(self.cit, bitmaps)

    def _parse_span_stats(self, span_stats_data: bytes) -> None:
        return None

    def _parse_stats(self, stats_data: bytes) -> None:
        return None


class BaseUseDataBitmaps:
    def __init__(self, cit: CIT, bitmaps: list[bytes]):
        self.cit = cit
        self._bitmaps = bitmaps

    def _parse_bitmap(self, idx: int) -> list[datetime.datetime]:
        return list(self.cit.iter_bitmap(self._bitmaps[idx]))


class SystemData(BaseUseData):
    MIN_BITMAPS_SIZE = 0x30
    MIN_SPAN_STATS_SIZE = 0x58
    MIN_STATS_SIZE = 0x1C

    def _parse_bitmaps(self, bitmaps: list[bytes]) -> SystemDataBitmaps:
        return SystemDataBitmaps(self.cit, bitmaps)

    def _parse_span_stats(self, span_stats_data: bytes) -> c_cit.CIT_SYSTEM_DATA_SPAN_STATS:
        return c_cit.CIT_SYSTEM_DATA_SPAN_STATS(span_stats_data)

    def _parse_stats(self, stats_data: bytes) -> c_cit.CIT_SYSTEM_DATA_STATS:
        return c_cit.CIT_SYSTEM_DATA_STATS(stats_data)


class SystemDataBitmaps(BaseUseDataBitmaps):
    def __init__(self, cit: CIT, bitmaps: list[bytes]):
        super().__init__(cit, bitmaps)
        self.display_power = self._parse_bitmap(0)
        self.display_request_change = self._parse_bitmap(1)
        self.input = self._parse_bitmap(2)
        self.input_touch = self._parse_bitmap(3)
        self.unknown = self._parse_bitmap(4)
        self.foreground = self._parse_bitmap(5)


class ProgramUseData(BaseUseData):
    def _parse_bitmaps(self, bitmaps: list[bytes]) -> ProgramDataBitmaps:
        return ProgramDataBitmaps(self.cit, bitmaps)

    def _parse_span_stats(self, span_stats_data: bytes) -> c_cit.CIT_USE_DATA_SPAN_STATS:
        return c_cit.CIT_USE_DATA_SPAN_STATS(span_stats_data)

    def _parse_stats(self, stats_data: bytes) -> c_cit.CIT_USE_DATA_STATS:
        return c_cit.CIT_USE_DATA_STATS(stats_data)


class ProgramDataBitmaps(BaseUseDataBitmaps):
    def __init__(self, cit: CIT, use_data: list[bytes]):
        super().__init__(cit, use_data)
        self.foreground = self._parse_bitmap(0)


def decode_name(name: str) -> bytes:
    """Decode the registry key name.

    The CIT key name in the registry has some strange encoding.
    This function is currently unused, but leaving it here for reference if someone needs it.
    """
    buf = name.encode()
    out = []

    for idx in range(0, len(name), 2):
        c0 = buf[idx]
        c1 = buf[idx + 1]

        c0 -= 0x30 if c0 <= 0x39 else 0x37
        c1 -= 0x30 if c1 <= 0x39 else 0x37

        out.append(c0 | (c1 * 16))

    return bytes(out)


def local_wintimestamp(target: Target, ts: int) -> datetime.datetime:
    return target.datetime.to_utc(wintimestamp(ts))


class CITPlugin(Plugin):
    """Plugin that parses CIT data from the registry.

    References:
        - https://dfir.ru/2018/12/02/the-cit-database-and-the-syscache-hive/
    """

    __namespace__ = "cit"

    KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT"

    def check_compatible(self) -> None:
        if not list(self.target.registry.keys(self.KEY)):
            raise UnsupportedPluginError("No CIT registry key found")

    @export(record=get_args(CITRecords))
    def cit(self) -> Iterator[CITRecords]:
        """Return CIT data from the registry for executed executable information.

        CIT data is stored at HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT\\System.
        It's supposedly application usage data that has yet-to-be flushed to the amcache.

        Some of its values are still unknown. Generally only available before Windows 10.
        """

        for key in self.target.registry.keys(f"{self.KEY}\\System"):
            for value in key.values():
                # The value name is a weird per-byte character-mirrored value that contains copies
                # of the PeriodStartLocal and AggregationperiodInS fields
                # The CIT\\Proc subkey also sometimes has a timestamp in it, which appears to be the time
                # it was processed by generaltel.dll

                data = value.value
                if len(data) <= 8:
                    continue

                try:
                    cit = CIT(data)

                    sysdata = cit.system_data
                    yield CITSystemRecord(
                        period_start=local_wintimestamp(self.target, cit.header.PeriodStartLocal),
                        start_time=local_wintimestamp(self.target, cit.header.StartTimeLocal),
                        current_time=local_wintimestamp(self.target, cit.header.CurrentTimeLocal),
                        aggregation_period_in_s=cit.header.AggregationPeriodInS,
                        span_stats_context_flushes_0_count=sysdata.span_stats.ContextFlushes0.Count,
                        span_stats_context_flushes_0_duration=sysdata.span_stats.ContextFlushes0.Duration,
                        span_stats_foreground_0_count=sysdata.span_stats.Foreground0.Count,
                        span_stats_foreground_0_duration=sysdata.span_stats.Foreground0.Duration,
                        span_stats_foreground_1_count=sysdata.span_stats.Foreground1.Count,
                        span_stats_foreground_1_duration=sysdata.span_stats.Foreground1.Duration,
                        span_stats_display_power_0_count=sysdata.span_stats.DisplayPower0.Count,
                        span_stats_display_power_0_duration=sysdata.span_stats.DisplayPower0.Duration,
                        span_stats_display_request_change_count=sysdata.span_stats.DisplayRequestChange.Count,
                        span_stats_display_request_change_duration=sysdata.span_stats.DisplayRequestChange.Duration,
                        span_stats_display_power_1_count=sysdata.span_stats.DisplayPower1.Count,
                        span_stats_display_power_1_duration=sysdata.span_stats.DisplayPower2.Duration,
                        span_stats_display_power_2_count=sysdata.span_stats.DisplayPower2.Count,
                        span_stats_display_power_2_duration=sysdata.span_stats.DisplayPower2.Duration,
                        span_stats_display_power_3_count=sysdata.span_stats.DisplayPower3.Count,
                        span_stats_display_power_3_duration=sysdata.span_stats.DisplayPower3.Duration,
                        span_stats_context_flushes_1_count=sysdata.span_stats.ContextFlushes1.Count,
                        span_stats_context_flushes_1_duration=sysdata.span_stats.ContextFlushes1.Duration,
                        span_stats_foreground_2_count=sysdata.span_stats.Foreground2.Count,
                        span_stats_foreground_2_duration=sysdata.span_stats.Foreground2.Duration,
                        span_stats_context_flushes_2_count=sysdata.span_stats.ContextFlushes2.Count,
                        span_stats_context_flushes_2_duration=sysdata.span_stats.ContextFlushes2.Duration,
                        stats_unk_boot_id_0=sysdata.stats.Unknown_BootIdRelated0,
                        stats_unk_boot_id_1=sysdata.stats.Unknown_BootIdRelated1,
                        stats_unk_boot_id_2=sysdata.stats.Unknown_BootIdRelated2,
                        stats_unk_boot_id_3=sysdata.stats.Unknown_BootIdRelated3,
                        stats_unk_boot_id_4=sysdata.stats.Unknown_BootIdRelated4,
                        stats_session_connects=sysdata.stats.SessionConnects,
                        stats_process_foreground_changes=sysdata.stats.ProcessForegroundChanges,
                        stats_context_flushes=sysdata.stats.ContextFlushes,
                        stats_missing_prog_data=sysdata.stats.MissingProgData,
                        stats_desktop_switches=sysdata.stats.DesktopSwitches,
                        stats_winlogon_message=sysdata.stats.WinlogonMessage,
                        stats_winlogon_lock_hotkey=sysdata.stats.WinlogonLockHotkey,
                        stats_winlogon_lock=sysdata.stats.WinlogonLock,
                        stats_session_disconnects=sysdata.stats.SessionDisconnects,
                        _target=self.target,
                    )

                    bitmap_pairs = [
                        (sysdata.bitmaps.display_power, CITSystemBitmapDisplayPowerRecord),
                        (sysdata.bitmaps.display_request_change, CITSystemBitmapDisplayRequestChangeRecord),
                        (sysdata.bitmaps.input, CITSystemBitmapInputRecord),
                        (sysdata.bitmaps.input_touch, CITSystemBitmapInputTouchRecord),
                        (sysdata.bitmaps.unknown, CITSystemBitmapUnknownRecord),
                        (sysdata.bitmaps.foreground, CITSystemBitmapForegroundRecord),
                    ]

                    for bitmap, record in bitmap_pairs:
                        yield from _yield_bitmap_records(self.target, cit, bitmap, record)

                    for entry in cit.entries:
                        program_data = entry.program_data
                        span_stats = entry.use_data.span_stats
                        stats = entry.use_data.stats

                        yield CITProgramRecord(
                            period_start=local_wintimestamp(self.target, cit.header.PeriodStartLocal),
                            start_time=local_wintimestamp(self.target, cit.header.StartTimeLocal),
                            current_time=local_wintimestamp(self.target, cit.header.CurrentTimeLocal),
                            aggregation_period_in_s=cit.header.AggregationPeriodInS,
                            path=self.target.fs.path(entry.file_path),
                            command_line=entry.command_line,
                            pe_timedatestamp=program_data.PeTimeDateStamp,
                            pe_checksum=program_data.PeCheckSum,
                            extra3=program_data.Extra3,
                            span_stats_process_creation_0_count=span_stats.ProcessCreation0.Count,
                            span_stats_process_creation_0_duration=span_stats.ProcessCreation0.Duration,
                            span_stats_foreground_0_count=span_stats.Foreground0.Count,
                            span_stats_foreground_0_duration=span_stats.Foreground0.Duration,
                            span_stats_foreground_1_count=span_stats.Foreground1.Count,
                            span_stats_foreground_1_duration=span_stats.Foreground1.Duration,
                            span_stats_foreground_2_count=span_stats.Foreground2.Count,
                            span_stats_foreground_2_duration=span_stats.Foreground2.Duration,
                            span_stats_process_suspended_count=span_stats.ProcessSuspended.Count,
                            span_stats_process_suspended_duration=span_stats.ProcessSuspended.Duration,
                            span_stats_process_creation_1_count=span_stats.ProcessCreation1.Count,
                            span_stats_process_creation_1_duration=span_stats.ProcessCreation1.Duration,
                            stats_crashes=stats.Crashes,
                            stats_thread_ghosting_changes=stats.ThreadGhostingChanges,
                            stats_input=stats.Input,
                            stats_input_keyboard=stats.InputKeyboard,
                            stats_unknown=stats.Unknown,
                            stats_input_touch=stats.InputTouch,
                            stats_input_hid=stats.InputHid,
                            stats_input_mouse=stats.InputMouse,
                            stats_mouse_left_button=stats.MouseLeftButton,
                            stats_mouse_right_button=stats.MouseRightButton,
                            stats_mouse_middle_button=stats.MouseMiddleButton,
                            stats_mouse_wheel=stats.MouseWheel,
                            _target=self.target,
                        )

                        yield from _yield_bitmap_records(
                            self.target, cit, entry.use_data.bitmaps.foreground, CITProgramBitmapForegroundRecord
                        )
                except Exception as e:
                    self.target.log.warning("Failed to parse CIT value: %s", value.name)
                    self.target.log.debug("", exc_info=e)

    @export(record=CITPostUpdateUseInfoRecord)
    def puu(self) -> Iterator[CITPostUpdateUseInfoRecord]:
        """Parse CIT PUU (Post Update Usage) data from the registry.

        Generally only available since Windows 10.
        """

        keys = [
            self.KEY,
            "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ]

        for reg_key in keys:
            for key in self.target.registry.keys(reg_key):
                try:
                    key_value = key.value("PUUActive").value
                    puu = c_cit.CIT_POST_UPDATE_USE_INFO(key_value)
                except RegistryValueNotFoundError:
                    continue

                except EOFError as e:
                    self.target.log.warning("Exception reading CIT structure in key %s", key.path)
                    self.target.log.debug("Unable to parse value %s", key_value, exc_info=e)
                    continue

                yield CITPostUpdateUseInfoRecord(
                    log_time_start=wintimestamp(puu.LogTimeStart),
                    update_key=puu.UpdateKey,
                    update_count=puu.UpdateCount,
                    crash_count=puu.CrashCount,
                    session_count=puu.SessionCount,
                    log_count=puu.LogCount,
                    user_active_duration_in_s=puu.UserActiveDurationInS,
                    user_or_display_active_duration_in_s=puu.UserOrDispActiveDurationInS,
                    desktop_active_duration_in_s=puu.DesktopActiveDurationInS,
                    version=puu.Version,
                    boot_id_min=puu.BootIdMin,
                    boot_id_max=puu.BootIdMax,
                    pmuu_key=puu.PMUUKey,
                    session_duration_in_s=puu.SessionDurationInS,
                    session_uptime_in_s=puu.SessionUptimeInS,
                    user_input_in_s=puu.UserInputInS,
                    mouse_input_in_s=puu.MouseInputInS,
                    keyboard_input_in_s=puu.KeyboardInputInS,
                    touch_input_in_s=puu.TouchInputInS,
                    precision_touchpad_input_in_s=puu.PrecisionTouchpadInputInS,
                    in_foreground_in_s=puu.InForegroundInS,
                    foreground_switch_count=puu.ForegroundSwitchCount,
                    user_active_transition_count=puu.UserActiveTransitionCount,
                    cumulative_user_active_duration_in_s=puu.CumulativeUserActiveDurationInS,
                    update_count_accumulation_started=puu.UpdateCountAccumulationStarted,
                    build_user_active_duration_in_s=puu.BuildUserActiveDurationInS,
                    build_number=puu.BuildNumber,
                    _target=self.target,
                    _user=self.target.registry.get_user(key),
                )

    @export(record=[CITDPRecord, CITDPDurationRecord])
    def dp(self) -> Iterator[CITDPRecord | CITDPDurationRecord]:
        """Parse CIT DP data from the registry.

        Generally only available since Windows 10.
        """

        keys = [
            self.KEY,
            "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ]
        applications = [
            ["Cummulative"],
            ["IEXPLORE.EXE"],
            ["MICROSOFTEDGE.EXE", "MICROSOFTEDGECP.EXE", "MICROSOFTEDGEBCHOST.EXE", "MICROSOFTEDGEDEVTOOLS.EXE"],
            ["CHROME.EXE"],
            ["WINWORD.EXE"],
            ["EXCEL.EXE"],
            ["FIREFOX.EXE"],
            ["MICROSOFT.PHOTOS.EXE"],
            ["OUTLOOK.EXE"],
            ["ACRORD32.EXE"],
            ["SKYPE.EXE"],
        ]

        for reg_key in keys:
            for key in self.target.registry.keys(reg_key):
                try:
                    key_value = key.value("DP").value
                    dp = c_cit.CIT_DP_DATA(key_value)
                except RegistryValueNotFoundError:
                    continue

                except EOFError as e:
                    self.target.log.warning("Exception reading CIT structure in key %s", key.path)
                    self.target.log.debug("Unable to parse value %s", key_value, exc_info=e)
                    continue

                user = self.target.registry.get_user(key)
                log_time_start = wintimestamp(dp.LogTimeStart)

                yield CITDPRecord(
                    log_time_start=log_time_start,
                    update_key=dp.UpdateKey,
                    log_count=dp.LogCount,
                    crash_count=dp.CrashCount,
                    session_count=dp.SessionCount,
                    _target=self.target,
                    _user=user,
                )

                for names, duration in zip(applications, dp.ForegroundDurations):
                    for name in names:
                        yield CITDPDurationRecord(
                            log_time_start=log_time_start,
                            application=name,
                            duration=duration,
                            _target=self.target,
                            _user=user,
                        )

    @export(record=CITTelemetryRecord)
    def telemetry(self) -> Iterator[CITTelemetryRecord]:
        """Parse CIT process telemetry answers from the registry.

        In some versions of Windows, processes would get "telemetry answers" set on their process struct, based on
        if certain events happened.

        Generally only available before Windows 10.
        """

        for key in self.target.registry.keys(f"{self.KEY}\\win32k"):
            for version_key in key.subkeys():
                for value in version_key.values():
                    yield CITTelemetryRecord(
                        regf_mtime=version_key.ts,
                        version=version_key.name,
                        path=self.target.fs.path(value.name),
                        value=str(c_cit.TELEMETRY_ANSWERS(value.value)).split(".")[1],
                        _target=self.target,
                    )

    @export(record=CITModuleRecord)
    def modules(self) -> Iterator[CITModuleRecord]:
        """Parse CIT tracked module information from the registry.

        Contains applications that loaded a tracked module. By default these are:

            \\System32\\mrt100.dll
            Microsoft.NET\\Framework\\v1.0.3705\\mscorwks.dll
            Microsoft.NET\\Framework\\v1.0.3705\\mscorsvr.dll
            Microsoft.NET\\Framework\\v1.1.4322\\mscorwks.dll
            Microsoft.NET\\Framework\\v1.1.4322\\mscorsvr.dll
            Microsoft.NET\\Framework\\v2.0.50727\\mscorwks.dll
            \\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll
            \\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll
            \\Microsoft.NET\\Framework64\\v2.0.50727\\mscorwks.dll

        When the amount of executables exceeds 64, the OverflowQuota value is set with the last timestamp.
        When the path length of an executable exceeds 520 characters, the OverflowValue value is set.

        Generally only available since Windows 10.
        """

        for key in self.target.registry.keys(f"{self.KEY}\\Module"):
            for monitored_dll in key.subkeys():
                try:
                    overflow_quota = wintimestamp(monitored_dll.value("OverflowQuota").value)
                except RegistryValueNotFoundError:
                    overflow_quota = None

                try:
                    overflow_value = wintimestamp(monitored_dll.value("OverflowValue").value)
                except RegistryValueNotFoundError:
                    overflow_value = None

                for value in monitored_dll.values():
                    if value.name in ("OverflowQuota", "OverflowValue"):
                        continue

                    yield CITModuleRecord(
                        last_loaded=wintimestamp(value.value),
                        regf_mtime=monitored_dll.ts,
                        tracked_module=self.target.fs.path(monitored_dll.name),
                        executable=self.target.fs.path(value.name),
                        # These are actually specific for the tracked module, but just include them in every record
                        overflow_quota=overflow_quota,
                        overflow_value=overflow_value,
                        _target=self.target,
                    )


def _yield_bitmap_records(
    target: Target, cit: CIT, bitmap: list[datetime.datetime], record: TargetRecordDescriptor
) -> Iterator[Record]:
    for entry in bitmap:
        yield record(
            ts=target.datetime.to_utc(entry),
            period_start=local_wintimestamp(target, cit.header.PeriodStartLocal),
            start_time=local_wintimestamp(target, cit.header.StartTimeLocal),
            current_time=local_wintimestamp(target, cit.header.CurrentTimeLocal),
            aggregation_period_in_s=cit.header.AggregationPeriodInS,
            bit_period_in_s=cit.header.BitPeriodInS,
            _target=target,
        )
