from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.dem import DemLoader, DemOSPlugin
from dissect.target.target import Target
from tests._utils import mkdirs

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def mock_dem_dir(tmp_path: Path) -> Path:
    root = tmp_path
    mkdirs(
        root,
        [
            "User/demData/Applications/Mozilla Firefox/AppData/Mozilla/Firefox",
            "User/demData/Applications/Mozilla Firefox/Registry",
            "User/demData/Windows Settings/Windows Explorer/AppData/Microsoft/Windows/Recent/AutomaticDestinations",
            "User/demData/Microsoft Office 2069/Word/AppData/Microsoft/Word",
            "User/demData/Applications/Edge Chromium/LocalAppData/Microsoft/Edge/User Data",
            "User/demData/backup",  # These should be ignored
            "User/demData/FlexRepository",
        ],
    )
    file = root / "User/demData/Applications/Mozilla Firefox/AppData/Mozilla/Firefox/profiles.ini"
    file.write_text("kusjes=1")

    file = (
        root / "User/demData/Windows Settings/Windows Explorer/AppData/Microsoft/Windows/Recent/"
        "AutomaticDestinations/test.automaticDestinations-ms"
    )
    file.write_bytes(b"\x67\x67\x77\x70")

    file = root / "User/demData/Microsoft Office 2069/Word/AppData/Microsoft/Word/backup.wbk"
    file.write_bytes(b"\x64\x65\x6d\x73")

    file = root / "User/demData/Applications/Edge Chromium/LocalAppData/Microsoft/Edge/User Data/Last Browser"
    file.write_text("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")

    reg_file = root / "User/demData/Applications/Mozilla Firefox/Registry/Flex Profiles.reg"
    reg_file.write_text(
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_CURRENT_USER\\Software\\Key]\r\n"
        '"Version"="1.0"\r\n'
        '"WheredYouFindThis"=dword:00001337\r\n',
        encoding="utf-16",
    )

    return root / "User"


def test_target_open(mock_dem_dir: Path) -> None:
    """Test that we correctly use ``DemLoader`` when opening a ``Target``."""
    loader = loader_open(mock_dem_dir)
    assert isinstance(loader, DemLoader)
    assert DemLoader.detect(mock_dem_dir)
    assert loader.path == mock_dem_dir

    target = Target()
    loader.map(target)
    target.apply()


def test_dem_mapping(mock_dem_dir: Path) -> None:
    """Test that we correctly map DEM data into the ``Target``."""
    target = Target.open(mock_dem_dir)

    vfs_path = target.fs.path("sysvol/Users/User/AppData/Roaming/Mozilla/Firefox/profiles.ini")
    assert vfs_path.exists()
    assert vfs_path.read_text() == "kusjes=1"

    vfs_path = target.fs.path(
        "sysvol/Users/User/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/test.automaticDestinations-ms"
    )
    assert vfs_path.exists()
    assert vfs_path.read_bytes() == b"\x67\x67\x77\x70"

    vfs_path = target.fs.path("sysvol/Users/User/AppData/Roaming/Microsoft/Word/backup.wbk")
    assert vfs_path.exists()
    assert vfs_path.read_bytes() == b"\x64\x65\x6d\x73"

    vfs_path = target.fs.path("sysvol/Users/User/AppData/Local/Microsoft/Edge/User Data/Last Browser")
    assert vfs_path.exists()
    assert vfs_path.read_text() == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"


def test_dem_registry_mapping(mock_dem_dir: Path) -> None:
    """Test that we correctly map registry entries from DEM data into the ``Target``."""
    target = Target.open(mock_dem_dir)

    name, hive, path = next(target.registry.iterhives())
    assert name == "HKEY_CURRENT_USER"
    assert path.as_posix() == "demData"

    key = hive.key("Software\\Key")
    assert key.value("Version").value == "1.0"
    assert key.value("WheredYouFindThis").value == 0x1337


def test_dem_os_plugin(mock_dem_dir: Path) -> None:
    """Test that we correctly create a ``DemOSPlugin`` when mapping DEM data."""
    target = Target.open(mock_dem_dir)

    assert isinstance(target._os, DemOSPlugin)
    assert target.os == "windows"
    assert target.hostname == "User"
    assert target.version is None

    users = list(target.users())
    assert len(users) == 1
    assert users[0].name == "User"
    assert users[0].sid == "S-1-0-0"
