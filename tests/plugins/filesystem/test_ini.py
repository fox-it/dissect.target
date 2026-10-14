from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.filesystem.ini import IniPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_ini(target_unix: Target, fs_unix: VirtualFilesystem) -> Target:
    fs_unix.map_dir("/etc/config", absolute_path("_data/plugins/filesystem/ini"))

    target_unix.add_plugin(IniPlugin)
    return target_unix


def test_ini_parses_records(target_ini: Target) -> None:
    """Test INI file discovery and parsing from a directory."""
    records = list(target_ini.ini("/etc/config"))

    assert len(records) == 6

    by_key = {(record.section, record.key): record for record in records}

    assert by_key[("Run", "Program")].value == "calc.exe"
    assert by_key[("Run", "NoValue")].value == "None"
    assert by_key[("Display", "Theme")].value == "Dark"
    assert by_key[("Shutdown", "Script")].value == "cleanup.cmd"

    paths = {str(record.path).lower() for record in records}
    assert "/etc/config/startup.ini" in paths
    assert "/etc/config/shutdown.ini" in paths
    assert "/etc/config/not_ini.txt" not in paths


def test_ini_parses_explicit_file(target_ini: Target) -> None:
    """Test parsing a single explicitly specified INI file."""
    records = list(target_ini.ini("/etc/config/startup.ini"))

    assert len(records) == 3
    assert {record.section for record in records} == {"Run", "Display"}
    assert all(str(record.path).lower().endswith("startup.ini") for record in records)


def test_ini_parses_utf16_encoded_file(target_ini: Target) -> None:
    """Test parsing UTF-16 encoded INI files."""
    records = list(target_ini.ini("/etc/config/utf16.ini"))

    assert len(records) == 2
    by_key = {(record.section, record.key): record for record in records}
    assert by_key[("Setting", "Timeout")].value == "30"
    assert by_key[("Setting", "Delay")].value == "60"
    assert all(str(record.path).lower().endswith("utf16.ini") for record in records)
