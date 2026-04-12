from __future__ import annotations

import plistlib
import struct
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# .binarycookies uses Cocoa epoch (2001-01-01)
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

BinaryCookieRecord = TargetRecordDescriptor(
    "macos/cookies/entries",
    [
        ("datetime", "creation_date"),
        ("datetime", "expiry_date"),
        ("string", "cookie_name"),
        ("string", "value"),
        ("string", "cookie_domain"),
        ("string", "cookie_path"),
        ("varint", "flags"),
        ("path", "source"),
    ],
)

HSTSRecord = TargetRecordDescriptor(
    "macos/cookies/hsts",
    [
        ("datetime", "ts"),
        ("string", "hsts_host"),
        ("boolean", "include_subdomains"),
        ("path", "source"),
    ],
)


class CookiesPlugin(Plugin):
    """Plugin to parse macOS cookie files.

    Parses .binarycookies files and HSTS.plist for Safari and system cookies.

    Locations:
    - ~/Library/Cookies/*.binarycookies
    - ~/Library/Containers/com.apple.Safari/Data/Library/Cookies/*.binarycookies
    - ~/Library/Cookies/HSTS.plist
    """

    __namespace__ = "cookies"

    COOKIE_GLOBS = [
        "Users/*/Library/Cookies/*.binarycookies",
        "Users/*/Library/Containers/com.apple.Safari/Data/Library/Cookies/*.binarycookies",
    ]
    HSTS_GLOB = "Users/*/Library/Cookies/HSTS.plist"

    def __init__(self, target):
        super().__init__(target)
        self._cookie_files = []
        for glob_pattern in self.COOKIE_GLOBS:
            self._cookie_files.extend(self.target.fs.path("/").glob(glob_pattern))
        self._hsts_files = list(self.target.fs.path("/").glob(self.HSTS_GLOB))

    def check_compatible(self) -> None:
        if not self._cookie_files and not self._hsts_files:
            raise UnsupportedPluginError("No cookie files found")

    def _cocoa_to_dt(self, ts):
        if ts is not None and ts > 0:
            try:
                return COCOA_EPOCH + timedelta(seconds=ts)
            except (ValueError, OverflowError):
                pass
        return None

    @export(record=BinaryCookieRecord)
    def entries(self) -> Iterator[BinaryCookieRecord]:
        """Parse cookies from .binarycookies files."""
        for cookie_path in self._cookie_files:
            try:
                yield from self._parse_binarycookies(cookie_path)
            except Exception as e:
                self.target.log.warning("Error parsing cookies at %s: %s", cookie_path, e)

    def _parse_binarycookies(self, cookie_path):
        with cookie_path.open("rb") as fh:
            data = fh.read()

        if len(data) < 8:
            return

        # Magic: "cook" (0x636F6F6B)
        magic = data[:4]
        if magic != b"cook":
            self.target.log.warning("Invalid binarycookies magic at %s", cookie_path)
            return

        num_pages = struct.unpack(">I", data[4:8])[0]
        if num_pages == 0:
            return

        # Page sizes (big-endian uint32 each)
        page_sizes = []
        offset = 8
        for _ in range(num_pages):
            if offset + 4 > len(data):
                return
            page_sizes.append(struct.unpack(">I", data[offset : offset + 4])[0])
            offset += 4

        # Parse each page
        for page_size in page_sizes:
            if offset + page_size > len(data):
                break
            page_data = data[offset : offset + page_size]
            offset += page_size

            yield from self._parse_page(page_data, cookie_path)

    def _parse_page(self, page_data, cookie_path):
        if len(page_data) < 8:
            return

        # Page header: 0x00000100, num_cookies
        page_magic = struct.unpack("<I", page_data[:4])[0]
        if page_magic != 0x00010000:
            return

        num_cookies = struct.unpack("<I", page_data[4:8])[0]

        # Cookie offsets
        cookie_offsets = []
        pos = 8
        for _ in range(num_cookies):
            if pos + 4 > len(page_data):
                return
            cookie_offsets.append(struct.unpack("<I", page_data[pos : pos + 4])[0])
            pos += 4

        for cookie_offset in cookie_offsets:
            try:
                record = self._parse_cookie(page_data, cookie_offset, cookie_path)
                if record:
                    yield record
            except Exception:
                continue

    def _parse_cookie(self, page_data, offset, cookie_path):
        if offset + 44 > len(page_data):
            return None

        cookie_size = struct.unpack("<I", page_data[offset : offset + 4])[0]
        if offset + cookie_size > len(page_data):
            return None

        cookie_data = page_data[offset : offset + cookie_size]
        if len(cookie_data) < 44:
            return None

        flags = struct.unpack("<I", cookie_data[8:12])[0]

        url_offset = struct.unpack("<I", cookie_data[16:20])[0]
        name_offset = struct.unpack("<I", cookie_data[20:24])[0]
        path_offset = struct.unpack("<I", cookie_data[24:28])[0]
        value_offset = struct.unpack("<I", cookie_data[28:32])[0]

        expiry_ts = struct.unpack("<d", cookie_data[32:40])[0]
        creation_ts = struct.unpack("<d", cookie_data[40:48])[0] if len(cookie_data) >= 48 else 0

        def read_string(data, off):
            if off >= len(data):
                return ""
            end = data.find(b"\x00", off)
            if end == -1:
                end = len(data)
            try:
                return data[off:end].decode("utf-8", errors="replace")
            except Exception:
                return ""

        return BinaryCookieRecord(
            creation_date=self._cocoa_to_dt(creation_ts),
            expiry_date=self._cocoa_to_dt(expiry_ts),
            cookie_name=read_string(cookie_data, name_offset),
            value=read_string(cookie_data, value_offset),
            cookie_domain=read_string(cookie_data, url_offset),
            cookie_path=read_string(cookie_data, path_offset),
            flags=flags,
            source=cookie_path,
            _target=self.target,
        )

    @export(record=HSTSRecord)
    def hsts(self) -> Iterator[HSTSRecord]:
        """Parse HSTS (HTTP Strict Transport Security) entries."""
        for hsts_path in self._hsts_files:
            try:
                yield from self._parse_hsts(hsts_path)
            except Exception as e:
                self.target.log.warning("Error parsing HSTS at %s: %s", hsts_path, e)

    def _parse_hsts(self, hsts_path):
        with hsts_path.open("rb") as fh:
            data = plistlib.loads(fh.read())

        entries = data.get("com.apple.CFNetwork.defaultStorageSession", [])
        if not isinstance(entries, list):
            entries = []

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ts = entry.get("HSTS Date Observed")
            if isinstance(ts, datetime):
                ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
            yield HSTSRecord(
                ts=ts,
                hsts_host=entry.get("HSTS Domain Name", entry.get("HSTS Host", "")),
                include_subdomains=bool(entry.get("kCFHTTPCookieDomainIncludeSubdomains", False)),
                source=hsts_path,
                _target=self.target,
            )
