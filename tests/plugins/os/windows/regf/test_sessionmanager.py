from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualKey
from dissect.target.plugins.os.windows.regf.sessionmanager import SessionManagerPlugin

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def add_key(hive: VirtualHive, path: str, key_name: str, value: str | bytes) -> None:
    key = VirtualKey(hive, path)
    key.add_value(key_name, value)
    hive.map_key(path, key)


def test_sessionmanager(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    """Test if we can detect and parse Windows session manager run keys."""
    add_key(
        hive_hklm,
        "System\\ControlSet001\\Control\\Session Manager",
        "BootExecute",
        "evil",
    )

    target_win_users.add_plugin(SessionManagerPlugin)
    records = list(target_win_users.sessionmanager())

    assert records[0].command.executable == "evil"
    assert records[0].source == "HKLM\\System\\ControlSet001\\Control\\Session Manager\\BootExecute"
