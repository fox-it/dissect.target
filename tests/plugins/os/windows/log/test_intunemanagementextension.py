from __future__ import annotations

import pathlib
import tempfile
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.windows.log.intunemanagementextension import (
    IntuneManagementExtensionLogParserPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

LOG_DIR = "ProgramData/Microsoft/IntuneManagementExtension/Logs"


def test_intunemanagementextension_check_compatible_missing_dir(
    target_win: Target,
) -> None:
    """Plugin should raise if the log directory is missing."""
    from dissect.target.exceptions import UnsupportedPluginError

    with pytest.raises(UnsupportedPluginError):
        target_win.add_plugin(IntuneManagementExtensionLogParserPlugin)


def test_intunemanagementextension_check_compatible_missing_logs(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Plugin should raise if the directory exists but contains no log files."""
    from dissect.target.exceptions import UnsupportedPluginError

    with tempfile.TemporaryDirectory() as tmpdir:
        fs_win.map_dir(LOG_DIR, pathlib.Path(tmpdir))
        with pytest.raises(UnsupportedPluginError):
            target_win.add_plugin(IntuneManagementExtensionLogParserPlugin)


def test_intunemanagementextension_check_compatible_success(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Plugin should load when an IntuneManagementExtension log exists."""
    fs_win.map_file(
        f"{LOG_DIR}/IntuneManagementExtension.log",
        absolute_path("_data/plugins/os/windows/log/intunemanagementextension/IntuneManagementExtension.log"),
    )

    target_win.add_plugin(IntuneManagementExtensionLogParserPlugin)


def test_intunemanagementextension_parsing_main_and_rotated(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Should parse valid IntuneManagementExtension log entries."""

    base = "_data/plugins/os/windows/log/intunemanagementextension"

    fs_win.map_file(
        f"{LOG_DIR}/IntuneManagementExtension.log",
        absolute_path(f"{base}/IntuneManagementExtension.log"),
    )
    fs_win.map_file(
        f"{LOG_DIR}/IntuneManagementExtension-20230101-100000.log",
        absolute_path(f"{base}/IntuneManagementExtension-20230101-100000.log"),
    )

    target_win.add_plugin(IntuneManagementExtensionLogParserPlugin)
    records = list(target_win.intunemanagementextension())

    assert len(records) == 3

    first, second, third = records

    expected_type = "windows_intune_managementextension_log"
    assert type(first).__name__ == expected_type
    assert type(second).__name__ == expected_type
    assert type(third).__name__ == expected_type

    assert first.component == "IntuneManagementExtension"
    assert second.component == "IntuneManagementExtension"
    assert third.component == "IntuneManagementExtension"

    assert first.thread == "1002"
    assert first.type == "2"
    assert first.context == "Agent"
    assert "Another entry." in first.message
    assert first.file_origin.endswith("IntuneManagementExtension.log")

    assert second.thread == "1003"
    assert second.type == "3"
    assert second.context == "Policy"
    assert "YYYY-MM-DD format test." in second.message
    assert second.file_origin.endswith("IntuneManagementExtension.log")

    assert third.thread == "1001"
    assert third.type == "1"
    assert third.context == "ManagedSoftware"
    assert "Test message one." in third.message
    assert third.file_origin.endswith("IntuneManagementExtension-20230101-100000.log")
