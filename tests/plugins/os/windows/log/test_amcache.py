from __future__ import annotations

import datetime
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows.amcache import AmcachePlugin
from dissect.target.plugins.os.windows.log.amcache import AmcacheInstallPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_amcache_new_format(target_win: Target, fs_win: VirtualFilesystem) -> None:
    amcache_file = absolute_path("_data/plugins/os/windows/amcache/amcache-new.hve")
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


def test_amcache_old_format(target_win: Target, fs_win: VirtualFilesystem) -> None:
    amcache_file = absolute_path("_data/plugins/os/windows/amcache/amcache-old.hve")
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


def test_amcache_windows_11_applaunches(target_win: Target, fs_win: VirtualFilesystem) -> None:
    # Test file taken from https://github.com/AndrewRathbun/DFIRArtifactMuseum/blob/main/Windows/Amcache/Win11/RathbunVM/PcaAppLaunchDic.txt
    # Licensed under the MIT License, Copyright (c) 2022 DFIR Artifact Museum
    applaunch_file = absolute_path("_data/plugins/os/windows/amcache/pca/PcaAppLaunchDic.txt")
    fs_win.map_file("windows/appcompat/pca/PcaAppLaunchDic.txt", applaunch_file)

    target_win.add_plugin(AmcachePlugin)
    applaunches = list(target_win.amcache.applaunches())

    assert len(applaunches) == 55
    assert applaunches[0].ts == datetime.datetime(2022, 12, 17, 13, 27, 53, 96000, tzinfo=datetime.timezone.utc)
    assert applaunches[0].path == "C:\\ProgramData\\Sophos\\AutoUpdate\\Cache\\sophos_autoupdate1.dir\\su-setup32.exe"


def test_amcache_windows_11_general(target_win: Target, fs_win: VirtualFilesystem) -> None:
    # Test files taken from https://github.com/AndrewRathbun/DFIRArtifactMuseum/blob/main/Windows/Amcache/Win11/RathbunVM/PcaGeneralDb0.txt
    # and https://github.com/AndrewRathbun/DFIRArtifactMuseum/blob/main/Windows/Amcache/Win11/RathbunVM/PcaGeneralDb1.txt
    # Licensed under the MIT License, Copyright (c) 2022 DFIR Artifact Museum
    db0_file = absolute_path("_data/plugins/os/windows/amcache/pca/PcaGeneralDb0.txt")
    db1_file = absolute_path("_data/plugins/os/windows/amcache/pca/PcaGeneralDb1.txt")
    fs_win.map_file("windows/appcompat/pca/PcaGeneralDb0.txt", db0_file)
    fs_win.map_file("windows/appcompat/pca/PcaGeneralDb1.txt", db1_file)

    # To test path resolving
    fs_win.map_file_fh("C:\\Program Files\\freefilesync\\bin\\freefilesync_x64.exe", BytesIO(b""))

    target_win.add_plugin(AmcachePlugin)

    with patch(
        "dissect.target.plugins.os.windows.env.EnvironmentVariablePlugin._get_system_env_vars",
        return_value={"%programfiles%": "C:\\Program Files"},
    ):
        records = list(target_win.amcache.general())

        assert len(records) == 176
        assert records[0].ts == datetime.datetime(2022, 5, 12, 19, 48, 9, 548000, tzinfo=datetime.timezone.utc)
        assert records[0].path == "C:\\Program Files\\freefilesync\\freefilesync.exe"
        assert records[0].type == 2
        assert records[0].name == "freefilesync"
        assert records[0].copyright == "freefilesync.org"
        assert records[0].version == "11.20"
        assert records[0].program_id == "000617915288ba535b4198ae58be4d9e2a4200000904"
        assert records[0].exit_code == "Abnormal process exit with code 0x2"


def mock_read_key_subkeys(self: AmcachePlugin, key: str) -> Iterator[Mock]:
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
    mock_entry.timestamp = datetime.datetime(2021, 12, 31, tzinfo=datetime.timezone.utc)
    mock_entry.values = Mock(return_value=mock_values)

    yield mock_entry


@pytest.mark.parametrize(
    ("test_file_id", "expected_file_id"),
    [
        ("00008e01cdeb9a1c23cee421a647f29c45f67623be97", "8e01cdeb9a1c23cee421a647f29c45f67623be97"),
        ("", None),
        (None, None),
    ],
)
@patch.object(AmcachePlugin, "read_key_subkeys", mock_read_key_subkeys)
def test_parse_inventory_application_file(
    target_win: Target, test_file_id: str | None, expected_file_id: str | None
) -> None:
    with patch("dissect.target.plugins.os.windows.amcache.ApplicationFileAppcompatRecord") as mock_record:
        amcache_plugin = AmcachePlugin(target_win)
        amcache_plugin._mock_file_id = test_file_id
        records = list(amcache_plugin.parse_inventory_application_file())

        assert len(records) == 1
        call_kwargs = mock_record.call_args.kwargs

        assert call_kwargs.get("digest", None) == (None, expected_file_id, None)


def test_amcache_install_entry(target_win: Target) -> None:
    amcache_install_plugin = AmcacheInstallPlugin(target_win)

    amcache_install_plugin.logs = Path(absolute_path("_data/plugins/os/windows/amcache/install"))

    entries = list(amcache_install_plugin.amcache_install())

    created_order = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
        r"C:\Program Files\7-Zip\7-zip.dll",
        r"C:\Program Files\7-Zip\7-zip32.dll",
        r"C:\Program Files\7-Zip\7z.dll",
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files\7-Zip\7zFM.exe",
        r"C:\Program Files\7-Zip\7zG.exe",
        r"C:\Program Files\7-Zip\Uninstall.exe",
    ]
    assert len(entries) == 8

    for create, entry in zip(created_order, entries):
        assert str(entry.create) == create
        assert str(entry.path) == r"C:\Users\JohnCena"
        assert str(entry.longname) == r"7z2201-x64.exe"
        assert entry.filesize == 1575742
