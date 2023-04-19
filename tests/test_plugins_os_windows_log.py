import shutil

import pytest

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.general import scrape
from dissect.target.plugins.os.windows.log import evt, evtx

from ._utils import absolute_path


@pytest.mark.parametrize(
    "is_in_directory, is_in_registry",
    [
        (True, False),
        (False, True),
        (True, True),
    ],
)
def test_evt_plugin(target_win, fs_win, tmp_path, is_in_directory, is_in_registry):
    target_win.add_plugin(evt.EvtPlugin)

    evt_log_file = absolute_path("data/TestLog.evt")
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


@pytest.mark.parametrize(
    "is_in_directory, is_in_registry, duplicate",
    [
        (True, False, False),
        (False, True, False),
        (True, True, False),
        (True, True, True),
    ],
)
def test_evtx_plugin(target_win, fs_win, tmp_path, is_in_directory, is_in_registry, duplicate):
    with pytest.raises(UnsupportedPluginError):
        target_win.add_plugin(evtx.EvtxPlugin)

    # Map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmp_path)
    target_win.add_plugin(evtx.EvtxPlugin)

    evtx_log_file = absolute_path("data/TestLogX.evtx")
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


def mock_registry_log_location(target_win, reg_key_name, mock_log_path):
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


def test_evtx_scraping(target_win):
    target_win.add_plugin(scrape.ScrapePlugin)

    plugin = evtx.EvtxPlugin(target_win)
    evtx_log_file = absolute_path("data/TestLogX.evtx")

    with open(evtx_log_file, "rb") as f:
        target_win.disks.add(f)
        scraped_records = list(plugin.scraped_evtx())

    assert len(scraped_records) == 5


def test_evt_scraping(target_win):
    target_win.add_plugin(scrape.ScrapePlugin)

    plugin = evt.EvtPlugin(target_win)
    evt_log_file = absolute_path("data/TestLog.evt")

    with open(evt_log_file, "rb") as f:
        target_win.disks.add(f)
        # Make sure that non-zero initial position does not break scraping
        f.seek(200)
        scraped_records = list(plugin.scraped_evt())

    assert len(scraped_records) == 5
