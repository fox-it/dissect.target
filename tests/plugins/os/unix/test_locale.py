from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.filesystem import (
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
    VirtualSymlink,
)
from dissect.target.plugins.os.unix.locale import UnixLocalePlugin, timezone_from_path
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_locale_plugin_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    # Locale locations originate from Ubuntu 20.
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))
    fs_unix.map_file_fh("/etc/default/locale", BytesIO(b"LANG=en_US.UTF-8"))
    fs_unix.map_file("/etc/default/keyboard", absolute_path("_data/plugins/os/unix/locale/keyboard"))
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert target_unix_users.timezone == "Europe/Amsterdam"
    assert target_unix_users.language == ["en_US"]
    keyboard = list(target_unix_users.keyboard())
    assert len(keyboard) == 1
    assert keyboard[0].layout == "us"
    assert keyboard[0].model == "pc105"
    assert keyboard[0].variant == ""
    assert keyboard[0].options == ""
    assert keyboard[0].backspace == "guess"


def test_locale_plugin_unix_quotes(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    # Older Fedora system
    fs_unix.map_file_fh("/etc/default/locale", BytesIO(b'LANG="en_US.UTF-8"'))
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert target_unix_users.language == ["en_US"]


def test_locale_etc_localtime_symlink(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.symlink("/usr/share/zoneinfo/Europe/Amsterdam", "/etc/localtime")
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert isinstance(fs_unix.get("/etc/localtime"), VirtualSymlink)
    assert target_unix_users.timezone == "Europe/Amsterdam"


def test_locale_etc_localtime_hardlink(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/usr/share/zoneinfo/Europe/Amsterdam", BytesIO(b"contents of Europe/Amsterdam"))
    fs_unix.link("/usr/share/zoneinfo/Europe/Amsterdam", "/etc/localtime")
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert isinstance(fs_unix.get("/etc/localtime"), VirtualFile)
    assert fs_unix.path("/etc/localtime").samefile(fs_unix.path("/usr/share/zoneinfo/Europe/Amsterdam"))

    entry = fs_unix.get("/etc/localtime")
    stat = entry.stat()
    stat.st_nlink = 2

    with patch.object(entry, "stat", return_value=stat):
        assert entry.stat().st_nlink == 2
        assert target_unix_users.timezone == "Europe/Amsterdam"


def test_locale_etc_localtime_regular_file(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/localtime", BytesIO(b"contents of Europe/Amsterdam"))
    fs_unix.map_file_fh("/usr/share/zoneinfo/UTC", BytesIO(b"contents of UTC"))
    fs_unix.map_file_fh("/usr/share/zoneinfo/Europe/Amsterdam", BytesIO(b"contents of Europe/Amsterdam"))
    fs_unix.map_file_fh("/usr/share/zoneinfo/America/New_York", BytesIO(b"contents of America/New_York"))
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert isinstance(fs_unix.get("/etc/localtime"), VirtualFile)
    assert isinstance(fs_unix.get("/usr/share/zoneinfo/UTC"), VirtualFile)
    assert isinstance(fs_unix.get("/usr/share/zoneinfo/Europe"), VirtualDirectory)
    assert isinstance(fs_unix.get("/usr/share/zoneinfo/Europe/Amsterdam"), VirtualFile)
    assert isinstance(fs_unix.get("/usr/share/zoneinfo/America/New_York"), VirtualFile)
    assert target_unix_users.timezone == "Europe/Amsterdam"


@pytest.mark.parametrize(
    ("input", "expected_output"),
    [
        ("/usr/share/zoneinfo/Europe/Amsterdam", "Europe/Amsterdam"),
        ("/usr/share/zoneinfo/UTC", "UTC"),
        ("Europe/Amsterdam", "Europe/Amsterdam"),
        ("Etc/UTC", "UTC"),
    ],
)
def test_locale_timezone_string_normalize(input: str, expected_output: str) -> None:
    """Test if we normalize zoneinfo paths correctly."""
    assert timezone_from_path(Path(input)) == expected_output
