from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.log import evt
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
    ("is_in_directory", "is_in_registry"),
    [
        (True, False),
        (False, True),
        (True, True),
    ],
)
def test_evt_plugin(
    target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path, is_in_directory: bool, is_in_registry: bool
) -> None:
    target_win.add_plugin(evt.EvtPlugin)

    evt_log_file = absolute_path("_data/plugins/os/windows/log/evt/TestLog.evt")
    expected_records = 0

    if is_in_directory:
        evt_dir_file = tmp_path / "TestLogDir.evt"
        shutil.copyfile(evt_log_file, evt_dir_file)

        fs_win.map_file("windows/system32/config/TestLog.evt", evt_dir_file)
        expected_records += 5

    if is_in_registry:
        evt_reg_file = tmp_path / "TestLogReg.evt"
        shutil.copyfile(evt_log_file, evt_reg_file)

        # Set a log path in the registry key and map that path
        mock_log_path = "somefolder/TestLogMock.EVT"
        mock_registry_log_location(target_win, "Security", f"C:\\{mock_log_path}")
        fs_win.map_file(mock_log_path, evt_reg_file)

        # Set path that should be skipped
        mock_registry_log_location(target_win, "MockApp", "C:\\somefolder\\BadFile.wrong")

        # Set path that doesn't exist
        mock_registry_log_location(target_win, "MockApp", "C:\\somefolder\\BadFile.evt")

        expected_records += 5

    records = list(target_win.evt())

    assert len(records) == expected_records

    # Verify that out of all received records, only 5 are unique
    assert len({str(rec.ts) for rec in records}) == 5


def test_evt_scraping(target_win: Target) -> None:
    target_win.add_plugin(scrape.ScrapePlugin)

    plugin = evt.EvtPlugin(target_win)
    evt_log_file = absolute_path("_data/plugins/os/windows/log/evt/TestLog.evt")

    with evt_log_file.open("rb") as fh:
        target_win.disks.add(fh)
        # Make sure that non-zero initial position does not break scraping
        fh.seek(200)
        scraped_records = list(plugin.scraped_evt())

    assert len(scraped_records) == 5


def test_evt_direct_mode() -> None:
    data_path = absolute_path("_data/plugins/os/windows/log/evt/TestLog.evt")

    target = Target.open_direct([data_path])
    records = list(target.evt())

    assert len(records) == 5
