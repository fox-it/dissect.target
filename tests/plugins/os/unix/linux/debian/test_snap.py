from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.linux.debian.snap import SnapPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_snap_packages(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if snap packages are discovered on unix systems."""

    fs_unix.map_file_fh("/etc/hostname", BytesIO(b"hostname"))
    fs_unix.map_file(
        "/var/lib/snapd/snaps/firefox_12345.snap",
        absolute_path("_data/plugins/os/unix/linux/debian/snap/firefox.snap"),
    )
    fs_unix.map_file(
        "/var/lib/snapd/snaps/firefox_67890.snap",
        absolute_path("_data/plugins/os/unix/linux/debian/snap/firefox.snap"),
    )

    target_unix_users.add_plugin(UnixPlugin)
    target_unix_users.add_plugin(SnapPlugin)

    assert target_unix_users.has_function("snap")

    results = list(target_unix_users.snaps())
    assert len(results) == 2

    assert results[0].hostname == "hostname"
    assert results[0].ts_modified == datetime(2024, 9, 17, 13, 18, 58, tzinfo=timezone.utc)
    assert results[0].name == "firefox"
    assert results[0].version == "129.0.2-1"
    assert results[0].author is None
    assert results[0].type is None
    assert results[0].path == "/var/lib/snapd/snaps/firefox_12345.snap"
