from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(value):
    if value:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


def _extract_protobuf_strings(data, start, end):
    """Extract all length-delimited protobuf string fields in a range."""
    strings = []
    pos = start
    while pos < end - 2:
        tag = data[pos]
        if (tag & 0x07) == 2 and tag > 0x08:  # wire type 2 = length-delimited
            slen = data[pos + 1]
            if 2 < slen < 200 and pos + 2 + slen <= end:
                try:
                    s = data[pos + 2 : pos + 2 + slen].decode("utf-8")
                    if s.isprintable():
                        field_num = tag >> 3
                        strings.append((field_num, s))
                except UnicodeDecodeError:
                    pass
        pos += 1
    return strings


def _parse_segb_records(data):
    """Parse SEGB (Segmented Binary) file and yield (timestamp, strings) tuples.

    Scans the entire file for Cocoa float64 timestamps in protobuf fixed64 fields,
    then extracts nearby protobuf string fields for context.
    """
    if len(data) < 0x30 or data[:4] != b"SEGB":
        return

    pos = 0x20
    last_ts_pos = -100  # deduplicate nearby timestamps

    while pos < len(data) - 9:
        tag = data[pos]
        if (tag & 0x07) == 1 and tag > 0x08:  # wire type 1 = fixed64
            try:
                val = struct.unpack("<d", data[pos + 1 : pos + 9])[0]
            except struct.error:
                pos += 1
                continue

            if 700000000 < val < 900000000 and pos - last_ts_pos > 8:
                ts = _cocoa_ts(val)
                search_start = max(0x20, pos - 50)
                search_end = min(len(data), pos + 250)
                strings = _extract_protobuf_strings(data, search_start, search_end)
                last_ts_pos = pos
                yield ts, strings

        pos += 1


# ── Record Descriptors ───────────────────────────────────────────────────

BiomeStreamRecord = TargetRecordDescriptor(
    "macos/biome/stream",
    [
        ("datetime", "ts"),
        ("string", "stream_name"),
        ("string", "strings"),
        ("string", "segment"),
        ("string", "data_source"),
        ("path", "source"),
    ],
)

BiomeStreamListRecord = TargetRecordDescriptor(
    "macos/biome/stream_list",
    [
        ("string", "stream_name"),
        ("varint", "segment_count"),
        ("varint", "total_size_bytes"),
        ("string", "data_source"),
        ("path", "source"),
    ],
)

BiomeAppInFocusRecord = TargetRecordDescriptor(
    "macos/biome/app_in_focus",
    [
        ("datetime", "ts"),
        ("string", "bundle_id"),
        ("string", "app_version"),
        ("string", "segment"),
        ("path", "source"),
    ],
)

BiomeAppIntentRecord = TargetRecordDescriptor(
    "macos/biome/app_intent",
    [
        ("datetime", "ts"),
        ("string", "bundle_id"),
        ("string", "intent_class"),
        ("string", "intent_verb"),
        ("string", "segment"),
        ("path", "source"),
    ],
)

BiomeGenericRecord = TargetRecordDescriptor(
    "macos/biome/generic",
    [
        ("datetime", "ts"),
        ("string", "stream_name"),
        ("string", "strings"),
        ("string", "segment"),
        ("path", "source"),
    ],
)

# Mapping of stream names to their namespace function names
DEDICATED_STREAMS = [
    "App.InFocus",
    "App.Intent",
    "App.WebUsage",
    "App.Activity",
    "App.MediaUsage",
    "Media.NowPlaying",
    "Notification.Usage",
    "_DKEvent.Wifi.Connection",
    "Device.Wireless.Bluetooth",
    "Device.Wireless.WiFi",
    "Device.Display.Backlight",
    "Device.Power.LowPowerMode",
    "Location.Semantic",
    "Safari.Navigations",
    "Safari.PageLoad",
    "ScreenTime.AppUsage",
    "UserFocus.InferredMode",
    "UserFocus.ComputedMode",
    "ProactiveHarvesting.ThirdPartyApp",
    "ProactiveHarvesting.Safari.PageView",
    "ProactiveHarvesting.Messages",
    "ProactiveHarvesting.Notes",
    "ProactiveHarvesting.Notifications",
    "ProactiveHarvesting.Mail",
    "IntelligenceEngine.Interaction.Donation",
    "_DKEvent.Safari.History",
    "_DKEvent.Activity.Level",
    "_DKEvent.Device.LowPowerMode",
    "Siri.Execution",
    "Messages.Read",
    "CarPlay.Connected",
    "Screen.Sharing",
]


class MacOSBiomePlugin(Plugin):
    """Plugin to parse macOS Biome data stores.

    Biome is Apple's successor to KnowledgeC, storing pattern-of-life
    data in SEGB (Segmented Binary) protobuf files.

    Locations:
    - ~/Library/Biome/ (user biome data)
    - /private/var/db/biome/ (system biome data)
    """

    __namespace__ = "biome"

    BIOME_GLOBS = [
        "Users/*/Library/Biome/streams/restricted/*/local/*",
        "private/var/db/biome/streams/restricted/*/local/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._stream_files = {}
        for pattern in self.BIOME_GLOBS:
            for path in self.target.fs.path("/").glob(pattern):
                if not path.is_file() or path.name == "tombstone" or "/tombstone/" in str(path):
                    continue
                parts = str(path).split("/")
                try:
                    restricted_idx = parts.index("restricted")
                    stream_name = parts[restricted_idx + 1]
                except (ValueError, IndexError):
                    continue
                data_source = "user" if "/Users/" in str(path) else "system"
                self._stream_files.setdefault(stream_name, []).append((path, data_source))

    def check_compatible(self) -> None:
        if not self._stream_files:
            raise UnsupportedPluginError("No Biome data found")

    def _read_segb(self, path):
        with path.open("rb") as fh:
            return fh.read()

    def _iter_stream(self, stream_name):
        for path, data_source in self._stream_files.get(stream_name, []):
            try:
                data = self._read_segb(path)
                yield path, data_source, data
            except Exception as e:
                self.target.log.warning("Error reading biome stream %s: %s", path, e)

    def _parse_stream_generic(self, stream_name):
        """Generic parser that yields BiomeGenericRecord for any stream."""
        for path, _data_source, data in self._iter_stream(stream_name):
            try:
                for ts, strings in _parse_segb_records(data):
                    str_vals = " | ".join(s for _, s in strings)
                    yield BiomeGenericRecord(
                        ts=ts,
                        stream_name=stream_name,
                        strings=str_vals,
                        segment=path.name,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing biome stream %s: %s", path, e)

    # ── List all streams ─────────────────────────────────────────────────

    @export(record=BiomeStreamListRecord)
    def streams(self) -> Iterator[BiomeStreamListRecord]:
        """List all available Biome streams with segment counts and sizes."""
        for stream_name, files in sorted(self._stream_files.items()):
            total_size = 0
            for path, _data_source in files:
                try:
                    stat = path.stat()
                    total_size += stat.st_size if hasattr(stat, "st_size") else 0
                except Exception:
                    pass
            yield BiomeStreamListRecord(
                stream_name=stream_name,
                segment_count=len(files),
                total_size_bytes=total_size,
                data_source=files[0][1],
                source=files[0][0],
                _target=self.target,
            )

    # ── All streams combined ─────────────────────────────────────────────

    @export(record=BiomeStreamRecord)
    def all(self) -> Iterator[BiomeStreamRecord]:
        """Parse all Biome streams into timestamped records with extracted strings."""
        for stream_name in sorted(self._stream_files):
            for path, data_source, data in self._iter_stream(stream_name):
                try:
                    for ts, strings in _parse_segb_records(data):
                        str_vals = " | ".join(s for _, s in strings)
                        yield BiomeStreamRecord(
                            ts=ts,
                            stream_name=stream_name,
                            strings=str_vals,
                            segment=path.name,
                            data_source=data_source,
                            source=path,
                            _target=self.target,
                        )
                except Exception as e:
                    self.target.log.warning("Error parsing biome stream %s: %s", path, e)

    # ── App In Focus ─────────────────────────────────────────────────────

    @export(record=BiomeAppInFocusRecord)
    def app_in_focus(self) -> Iterator[BiomeAppInFocusRecord]:
        """Parse App.InFocus — which app had focus and when."""
        for path, _data_source, data in self._iter_stream("App.InFocus"):
            try:
                for ts, strings in _parse_segb_records(data):
                    str_dict = dict(strings)
                    bundle_id = str_dict.get(6, "")
                    version = str_dict.get(9, "")
                    if bundle_id:
                        yield BiomeAppInFocusRecord(
                            ts=ts,
                            bundle_id=bundle_id,
                            app_version=version,
                            segment=path.name,
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing App.InFocus: %s", e)

    # ── App Intents ──────────────────────────────────────────────────────

    @export(record=BiomeAppIntentRecord)
    def app_intents(self) -> Iterator[BiomeAppIntentRecord]:
        """Parse App.Intent — app intents (messages, media, calls, etc.)."""
        for path, _data_source, data in self._iter_stream("App.Intent"):
            try:
                for ts, strings in _parse_segb_records(data):
                    str_vals = [val for _, val in strings]
                    bundle_id = intent_class = intent_verb = ""
                    for val in str_vals:
                        if "." in val and not val.startswith("IN") and not val.startswith("Send"):
                            bundle_id = val
                        elif val.startswith("IN") or val.endswith("Intent"):
                            intent_class = val
                        elif val[0].isupper() and len(val) < 30 and "." not in val:
                            intent_verb = val
                    yield BiomeAppIntentRecord(
                        ts=ts,
                        bundle_id=bundle_id,
                        intent_class=intent_class,
                        intent_verb=intent_verb,
                        segment=path.name,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing App.Intent: %s", e)

    # ── Dedicated stream functions (generic record) ──────────────────────

    @export(record=BiomeGenericRecord)
    def now_playing(self) -> Iterator[BiomeGenericRecord]:
        """Parse Media.NowPlaying — media playback events."""
        yield from self._parse_stream_generic("Media.NowPlaying")

    @export(record=BiomeGenericRecord)
    def web_usage(self) -> Iterator[BiomeGenericRecord]:
        """Parse App.WebUsage — web browsing events tracked by the OS."""
        yield from self._parse_stream_generic("App.WebUsage")

    @export(record=BiomeGenericRecord)
    def app_activity(self) -> Iterator[BiomeGenericRecord]:
        """Parse App.Activity — application activity events."""
        yield from self._parse_stream_generic("App.Activity")

    @export(record=BiomeGenericRecord)
    def media_usage(self) -> Iterator[BiomeGenericRecord]:
        """Parse App.MediaUsage — media usage events."""
        yield from self._parse_stream_generic("App.MediaUsage")

    @export(record=BiomeGenericRecord)
    def wifi_connections(self) -> Iterator[BiomeGenericRecord]:
        """Parse _DKEvent.Wifi.Connection — WiFi connection/disconnection events."""
        yield from self._parse_stream_generic("_DKEvent.Wifi.Connection")

    @export(record=BiomeGenericRecord)
    def bluetooth(self) -> Iterator[BiomeGenericRecord]:
        """Parse Device.Wireless.Bluetooth — Bluetooth connection events."""
        yield from self._parse_stream_generic("Device.Wireless.Bluetooth")

    @export(record=BiomeGenericRecord)
    def wifi(self) -> Iterator[BiomeGenericRecord]:
        """Parse Device.Wireless.WiFi — WiFi state events."""
        yield from self._parse_stream_generic("Device.Wireless.WiFi")

    @export(record=BiomeGenericRecord)
    def display(self) -> Iterator[BiomeGenericRecord]:
        """Parse Device.Display.Backlight — display on/off state."""
        yield from self._parse_stream_generic("Device.Display.Backlight")

    @export(record=BiomeGenericRecord)
    def low_power_mode(self) -> Iterator[BiomeGenericRecord]:
        """Parse Device.Power.LowPowerMode — low power mode state changes."""
        yield from self._parse_stream_generic("Device.Power.LowPowerMode")

    @export(record=BiomeGenericRecord)
    def location(self) -> Iterator[BiomeGenericRecord]:
        """Parse Location.Semantic — semantic location data."""
        yield from self._parse_stream_generic("Location.Semantic")

    @export(record=BiomeGenericRecord)
    def notifications(self) -> Iterator[BiomeGenericRecord]:
        """Parse Notification.Usage — notification events."""
        yield from self._parse_stream_generic("Notification.Usage")

    @export(record=BiomeGenericRecord)
    def safari_navigations(self) -> Iterator[BiomeGenericRecord]:
        """Parse Safari.Navigations — Safari URL navigations."""
        yield from self._parse_stream_generic("Safari.Navigations")

    @export(record=BiomeGenericRecord)
    def safari_page_load(self) -> Iterator[BiomeGenericRecord]:
        """Parse Safari.PageLoad — Safari page load events."""
        yield from self._parse_stream_generic("Safari.PageLoad")

    @export(record=BiomeGenericRecord)
    def safari_history(self) -> Iterator[BiomeGenericRecord]:
        """Parse _DKEvent.Safari.History — Safari history events (DuetKnowledge)."""
        yield from self._parse_stream_generic("_DKEvent.Safari.History")

    @export(record=BiomeGenericRecord)
    def screentime(self) -> Iterator[BiomeGenericRecord]:
        """Parse ScreenTime.AppUsage — Screen Time app usage data."""
        yield from self._parse_stream_generic("ScreenTime.AppUsage")

    @export(record=BiomeGenericRecord)
    def user_focus(self) -> Iterator[BiomeGenericRecord]:
        """Parse UserFocus.InferredMode — inferred Focus/Do Not Disturb mode."""
        yield from self._parse_stream_generic("UserFocus.InferredMode")

    @export(record=BiomeGenericRecord)
    def user_focus_computed(self) -> Iterator[BiomeGenericRecord]:
        """Parse UserFocus.ComputedMode — computed Focus mode."""
        yield from self._parse_stream_generic("UserFocus.ComputedMode")

    @export(record=BiomeGenericRecord)
    def activity_level(self) -> Iterator[BiomeGenericRecord]:
        """Parse _DKEvent.Activity.Level — device activity level."""
        yield from self._parse_stream_generic("_DKEvent.Activity.Level")

    @export(record=BiomeGenericRecord)
    def dk_low_power(self) -> Iterator[BiomeGenericRecord]:
        """Parse _DKEvent.Device.LowPowerMode — DuetKnowledge low power events."""
        yield from self._parse_stream_generic("_DKEvent.Device.LowPowerMode")

    @export(record=BiomeGenericRecord)
    def third_party_apps(self) -> Iterator[BiomeGenericRecord]:
        """Parse ProactiveHarvesting.ThirdPartyApp — third-party app usage."""
        yield from self._parse_stream_generic("ProactiveHarvesting.ThirdPartyApp")

    @export(record=BiomeGenericRecord)
    def safari_pageview(self) -> Iterator[BiomeGenericRecord]:
        """Parse ProactiveHarvesting.Safari.PageView — Safari page views."""
        yield from self._parse_stream_generic("ProactiveHarvesting.Safari.PageView")

    @export(record=BiomeGenericRecord)
    def harvested_messages(self) -> Iterator[BiomeGenericRecord]:
        """Parse ProactiveHarvesting.Messages — harvested message metadata."""
        yield from self._parse_stream_generic("ProactiveHarvesting.Messages")

    @export(record=BiomeGenericRecord)
    def harvested_notes(self) -> Iterator[BiomeGenericRecord]:
        """Parse ProactiveHarvesting.Notes — harvested notes metadata."""
        yield from self._parse_stream_generic("ProactiveHarvesting.Notes")

    @export(record=BiomeGenericRecord)
    def harvested_notifications(self) -> Iterator[BiomeGenericRecord]:
        """Parse ProactiveHarvesting.Notifications — harvested notification data."""
        yield from self._parse_stream_generic("ProactiveHarvesting.Notifications")

    @export(record=BiomeGenericRecord)
    def harvested_mail(self) -> Iterator[BiomeGenericRecord]:
        """Parse ProactiveHarvesting.Mail — harvested mail metadata."""
        yield from self._parse_stream_generic("ProactiveHarvesting.Mail")

    @export(record=BiomeGenericRecord)
    def intelligence_donations(self) -> Iterator[BiomeGenericRecord]:
        """Parse IntelligenceEngine.Interaction.Donation — Siri intelligence donations."""
        yield from self._parse_stream_generic("IntelligenceEngine.Interaction.Donation")

    @export(record=BiomeGenericRecord)
    def siri_execution(self) -> Iterator[BiomeGenericRecord]:
        """Parse Siri.Execution — Siri command executions."""
        yield from self._parse_stream_generic("Siri.Execution")

    @export(record=BiomeGenericRecord)
    def messages_read(self) -> Iterator[BiomeGenericRecord]:
        """Parse Messages.Read — message read events."""
        yield from self._parse_stream_generic("Messages.Read")

    @export(record=BiomeGenericRecord)
    def carplay(self) -> Iterator[BiomeGenericRecord]:
        """Parse CarPlay.Connected — CarPlay connection events."""
        yield from self._parse_stream_generic("CarPlay.Connected")

    @export(record=BiomeGenericRecord)
    def screen_sharing(self) -> Iterator[BiomeGenericRecord]:
        """Parse Screen.Sharing — screen sharing sessions."""
        yield from self._parse_stream_generic("Screen.Sharing")
