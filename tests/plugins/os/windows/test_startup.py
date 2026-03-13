from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.startup import StartupPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_startup(
    target_win_users: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive, hive_hku: VirtualHive
) -> None:
    """Test Windows Startp plugin."""

    # File persistency
    fs_win.map_file_fh("ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/SystemFoo.exe", BytesIO(b""))
    fs_win.map_file_fh("ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/SystemBar.exe", BytesIO(b""))
    fs_win.map_file_fh(
        "Users/John/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/UserFoo.exe", BytesIO(b"")
    )
    fs_win.map_file_fh(
        "Users/John/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini", BytesIO(b"")
    )

    # Registry overrides
    key_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    key = VirtualKey(hive_hku, key_name)
    key.add_value("Startup", "C:\\Users\\John\\Downloads\\User.exe")
    hive_hku.map_key(key_name, key)

    key_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
    key = VirtualKey(hive_hklm, key_name)
    key.add_value("Startup", "C:\\Temp\\System.exe")
    hive_hklm.map_key(key_name, key)

    target_win_users.add_plugin(StartupPlugin)
    records = sorted(target_win_users.startup(), key=lambda r: str(r.command.executable))
    assert len(records) == 5

    assert [r.command.executable for r in records] == [
        "/C:/Temp/System.exe",
        "/C:/Users/John/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/UserFoo.exe",
        "/C:/Users/John/Downloads/User.exe",
        "/sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/SystemBar.exe",
        "/sysvol/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/SystemFoo.exe",
    ]

    assert [r.source for r in records] == [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "\\C:\\Users\\John\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "HKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        "\\sysvol\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "\\sysvol\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ]
