from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualKey
from dissect.target.plugins.os.windows.regf.runkeys import RunKeysPlugin

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def add_key(hive: VirtualHive, path: str, key_name: str, value: str | bytes) -> None:
    key = VirtualKey(hive, path)
    key.add_value(key_name, value)
    hive.map_key(path, key)


def test_runkeys(target_win_users: Target, hive_hklm: VirtualHive, hive_hku: VirtualHive) -> None:
    """Test if we can detect and parse Windows runkeys."""
    add_key(
        hive_hklm,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SecurityHealth",
        "%windir%\\system32\\SecurityHealthSystray.exe",
    )
    add_key(
        hive_hku,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
        "SeemsLegit",
        "C:\\Temp\\Evil.exe",
    )

    target_win_users.add_plugin(RunKeysPlugin)
    records = list(target_win_users.runkeys())

    assert records[0].name == "SecurityHealth"
    assert records[0].command.executable == "%windir%\\system32\\SecurityHealthSystray.exe"
    assert records[0].source == "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

    assert records[1].name == "SeemsLegit"
    assert records[1].command.executable == "C:\\Temp\\Evil.exe"
    assert records[1].source == "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run"
