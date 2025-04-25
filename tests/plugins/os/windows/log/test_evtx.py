from __future__ import annotations

import shutil
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.log import evt, evtx
from dissect.target.plugins.scrape import scrape
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import VirtualFilesystem


def mock_registry_log_location(target_win: Target, reg_key_name: str, mock_log_path: str) -> None:
    # Mock eventlog registry key in a specific control set,
    # CurrentControlSet used in preconfigured value is a soft link
    registry_hive = target_win.registry._root

    eventlog_key = evt.WindowsEventlogsMixin.EVENTLOG_REGISTRY_KEY.replace("CurrentControlSet", "ControlSet001")

    try:
        registry_hive.key(eventlog_key)
    except RegistryKeyNotFoundError:
        registry_hive.map_key(eventlog_key, VirtualKey(registry_hive, eventlog_key))

    # Set 'File' registry value to eventlog file path
    registry_key = f"{eventlog_key}\\{reg_key_name}"
    registry_subkey = VirtualKey(registry_hive, registry_key)
    registry_hive.map_key(registry_key, registry_subkey)

    eventlog_security_value = VirtualValue(registry_hive, "File", mock_log_path)
    registry_hive.map_value(registry_key, "File", eventlog_security_value)


@pytest.mark.parametrize(
    ("is_in_directory", "is_in_registry", "duplicate"),
    [
        (True, False, False),
        (False, True, False),
        (True, True, False),
        (True, True, True),
    ],
)
def test_evtx_plugin(
    target_win: Target,
    fs_win: VirtualFilesystem,
    tmp_path: Path,
    is_in_directory: bool,
    is_in_registry: bool,
    duplicate: bool,
) -> None:
    with pytest.raises(UnsupportedPluginError):
        target_win.add_plugin(evtx.EvtxPlugin)

    # Map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmp_path)
    target_win.add_plugin(evtx.EvtxPlugin)

    evtx_log_file = absolute_path("_data/plugins/os/windows/log/evtx/TestLogX.evtx")
    expected_records = 0

    if is_in_directory:
        evtx_dir_file = tmp_path / "TestLogXDir.evtx"
        shutil.copyfile(evtx_log_file, evtx_dir_file)

        # Mock log file in a default directory
        fs_win.map_file("windows/system32/winevt/logs/TestLogMock.evtx", evtx_dir_file)
        expected_records += 5

    if is_in_registry:
        evtx_reg_file = tmp_path / "TestLogXReg.evtx"
        shutil.copyfile(evtx_log_file, evtx_reg_file)

        # Set a log path in the registry key and map that path
        mock_log_path = "somefolder/TestLogMock.EVTX"
        mock_registry_log_location(target_win, "Security", f"C:\\{mock_log_path}")
        fs_win.map_file(mock_log_path, evtx_reg_file)

        # Set path that should be skipped
        mock_registry_log_location(target_win, "MockApp", "C:\\somefolder\\BadFile.wrong")

        # Set path that doesn't exist
        mock_registry_log_location(target_win, "MockApp", "C:\\somefolder\\BadFile.evtx")

        expected_records += 5

    if duplicate:
        # Add a registry path that we should already pick up from the default directory
        # The only difference is that the directory file is mapped to sysvol, whereas we will reference it from C here
        # Expected records shouldn't change
        mock_registry_log_location(target_win, "Security Dupe", "c:/windows/system32/winevt/logs/TestLogMock.evtx")

    records = list(target_win.evtx())

    assert len(records) == expected_records

    # verify that out of all received records, only 5 are unique
    assert len({str(rec.EventID) for rec in records}) == 5


def test_evtx_scraping(target_win: Target) -> None:
    target_win.add_plugin(scrape.ScrapePlugin)

    plugin = evtx.EvtxPlugin(target_win)
    evtx_log_file = absolute_path("_data/plugins/os/windows/log/evtx/TestLogX.evtx")

    with evtx_log_file.open("rb") as fh:
        target_win.disks.add(fh)
        scraped_records = list(plugin.scraped_evtx())

    assert len(scraped_records) == 5


def test_evtx_normalize_values(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we normalize certain evtx fields correctly."""

    # Example Security.evtx originates from Windows 10 22H2 Pro build 19045.2006,
    # events exported after clean virtual machine post-install.
    security_evtx = absolute_path("_data/plugins/os/windows/log/evtx/Security.evtx")
    fs_win.map_file("Windows\\System32\\winevt\\Logs\\Security.evtx", security_evtx)

    target_win.add_plugin(evtx.EvtxPlugin)

    records = sorted(target_win.evtx(), key=lambda r: r.ts)

    # Verified amount of events in Event Viewer
    assert len(records) == 759

    assert records[0].ts == datetime(2025, 3, 4, 10, 27, 58, 245262, tzinfo=timezone.utc)
    assert records[0].Provider_Name == "Microsoft-Windows-Security-Auditing"
    assert records[0].EventID == 4616
    assert records[0].Channel == "Security"
    assert records[0].Computer == "DESKTOP-L7A1DDP"
    assert records[0].Correlation_ActivityID is None
    assert records[0].SubjectUserSid == "S-1-5-18"
    assert records[0].source == "sysvol\\windows\\system32\\winevt\\logs\\Security.evtx"

    assert records[69].ts == datetime(2025, 3, 4, 10, 28, 2, 905350, tzinfo=timezone.utc)
    assert records[69].PrivilegeList is None
    assert records[69].SidHistory is None

    # Should contain None instead of string "-"
    assert {getattr(r, "IpAddress", None) for r in records} == {None, "127.0.0.1"}


@pytest.mark.parametrize(
    ("key", "keys", "expected_key"),
    [
        ("source", {"source", "_target"}, "source_2_duplicate"),
        ("source", {"source", "source_2_duplicate", "_target"}, "source_3_duplicate"),
        ("source", {"source", "source_2", "_target"}, "source_2_duplicate"),
    ],
)
def test_evtx_key_deduplication(key: str, keys: set[str], expected_key: str) -> None:
    """Test if ``unique_keys`` correctly deduplicates key values."""

    assert evtx.unique_key(key, keys) == expected_key


def test_evtx_direct_mode() -> None:
    data_path = absolute_path("_data/plugins/os/windows/log/evtx/TestLogX.evtx")

    target = Target.open_direct([data_path])
    records = list(target.evtx())

    assert len(records) == 5
