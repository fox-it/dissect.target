from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.regutil import VirtualKey
from dissect.target.plugins.os.windows.regf.terminalserverclient import TerminalServerClientPlugin
from dissect.target.target import Target

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive


KEY = "Software\\Microsoft\\Terminal Server Client\\Servers"


def test_terminal_server_client(target_win_users: Target, hive_hku: VirtualHive) -> None:
    server_key = VirtualKey(hive_hku, f"{KEY}\\rdp.example.com")
    server_key.add_value("UsernameHint", "EXAMPLE\\analyst")
    hive_hku.map_key(server_key.path, server_key)

    target_win_users.add_plugin(TerminalServerClientPlugin)
    records = list(target_win_users.terminal_server_client())

    assert len(records) == 1
    assert records[0].server == "rdp.example.com"
    assert records[0].username_hint == "EXAMPLE\\analyst"
    assert records[0].regf_key_path == ("Software\\Microsoft\\Terminal Server Client\\Servers\\rdp.example.com")


def test_terminal_server_client_skips_missing_username_hint(target_win_users: Target, hive_hku: VirtualHive) -> None:
    server_key = VirtualKey(hive_hku, f"{KEY}\\rdp.example.com")
    hive_hku.map_key(server_key.path, server_key)

    target_win_users.add_plugin(TerminalServerClientPlugin)

    assert list(target_win_users.terminal_server_client()) == []


def test_terminal_server_client_incompatible() -> None:
    with pytest.raises(UnsupportedPluginError):
        TerminalServerClientPlugin(Target()).check_compatible()
