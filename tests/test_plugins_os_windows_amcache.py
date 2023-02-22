import datetime
import sys
from unittest.mock import Mock, patch

import pytest
from flow.record.fieldtypes import path

from dissect.target.plugins.os.windows.amcache import AmcachePlugin

from ._utils import absolute_path


def test_amcache_new_format(target_win, fs_win):
    amcache_file = absolute_path("data/amcache-new.hve")
    fs_win.map_file("windows/appcompat/programs/amcache.hve", amcache_file)

    target_win.add_plugin(AmcachePlugin)

    files = list(target_win.amcache.files())
    programs = list(target_win.amcache.programs())

    applications = list(target_win.amcache.applications())
    application_files = list(target_win.amcache.application_files())
    application_shortcuts = list(target_win.amcache.shortcuts())
    drivers = list(target_win.amcache.drivers())
    containers = list(target_win.amcache.device_containers())

    assert len(files) == 0
    assert len(programs) == 0
    assert len(applications) == 118
    assert len(application_files) == 222
    assert len(application_shortcuts) == 65
    assert len(containers) == 9
    assert len(drivers) == 361


def test_amcache_old_format(target_win, fs_win):
    amcache_file = absolute_path("data/amcache-old.hve")
    fs_win.map_file("windows/appcompat/programs/amcache.hve", amcache_file)

    target_win.add_plugin(AmcachePlugin)

    files = list(target_win.amcache.files())
    programs = list(target_win.amcache.programs())

    applications = list(target_win.amcache.applications())
    application_files = list(target_win.amcache.application_files())
    application_shortcuts = list(target_win.amcache.shortcuts())
    drivers = list(target_win.amcache.drivers())
    containers = list(target_win.amcache.device_containers())

    assert len(files) == 69
    assert len(programs) == 0
    assert len(applications) == 326
    assert len(application_files) == 0
    assert len(application_shortcuts) == 0
    assert len(containers) == 16
    assert len(drivers) == 0


def test_amcache_windows_11_applaunches(target_win, fs_win):
    applaunch_file = absolute_path("data/PcaAppLaunchDic.txt")
    fs_win.map_file("windows/appcompat/pca/PcaAppLaunchDic.txt", applaunch_file)

    target_win.add_plugin(AmcachePlugin)
    applaunches = list(target_win.amcache.applaunches())

    assert len(applaunches) == 55
    assert applaunches[0].ts == datetime.datetime(2022, 12, 17, 13, 27, 53, 96000, tzinfo=datetime.timezone.utc)
    assert applaunches[0].path == path.from_windows(
        "C:\\ProgramData\\Sophos\\AutoUpdate\\Cache\\sophos_autoupdate1.dir\\su-setup32.exe"
    )


def new_read_key_subkeys(self, key):
    base_values = {
        "AppxPackageFullName": "Microsoft.Microsoft3DViewer_7.2105.4012.0_x64__8wekyb3d8bbwe",
        "AppxPackageRelativeId": "Microsoft.Microsoft3DViewer",
        "BinFileVersion": "7.2105.4012.0",
        "BinProductVersion": "7.2105.4012.0",
        "BinaryType": "pe64_amd64",
        "Language": 0,
        "LinkDate": "05/04/2021 17:43:39",
        "LongPathHash": "3dviewer.exe|40f275349895ac70",
        "LowerCaseLongPath": "c:\\program files\\windowsapps\\microsoft.0_x64__8wekyb3d8bbwe\\3dviewer.exe",
        "Name": "3DViewer.exe",
        "OriginalFileName": "3dviewer.exe",
        "ProductName": "view 3d",
        "ProductVersion": "7.2105.4012.0",
        "ProgramId": "0000df892556c2f7a6b7fa69f7009b5c08cb00000904",
        "Publisher": "microsoft corporation",
        "Size": 19456,
        "Usn": 32259776,
        "Version": "7.2105.4012.0",
    }

    mock_values = []
    for key, value in base_values.items():
        mock_value = Mock()
        mock_value.name = key
        mock_value.value = value
        mock_values.append(mock_value)

    mock_value = Mock()
    mock_value.name = "FileId"
    mock_value.value = self._mock_file_id
    mock_values.append(mock_value)

    mock_entry = Mock()
    mock_entry.timestamp = datetime.datetime(2021, 12, 31)
    mock_entry.values = Mock(return_value=mock_values)

    yield mock_entry


@pytest.mark.parametrize(
    "test_file_id,expected_file_id",
    [
        ("00008e01cdeb9a1c23cee421a647f29c45f67623be97", "8e01cdeb9a1c23cee421a647f29c45f67623be97"),
        ("", None),
        (None, None),
    ],
)
@patch.object(AmcachePlugin, "read_key_subkeys", new_read_key_subkeys)
def test_parse_inventory_application_file(target_win, test_file_id, expected_file_id):
    with patch("dissect.target.plugins.os.windows.amcache.ApplicationFileAppcompatRecord") as mock_record:
        amcache_plugin = AmcachePlugin(target_win)
        amcache_plugin._mock_file_id = test_file_id
        records = list(amcache_plugin.parse_inventory_application_file())

        assert len(records) == 1
        if sys.version_info[:2] < (3, 8):
            call_kwargs = mock_record.call_args[1]
        else:
            call_kwargs = mock_record.call_args.kwargs

        assert call_kwargs.get("digests", None) == [None, expected_file_id, None]
