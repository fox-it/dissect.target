from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.shell.powershell import PowershellPlugin
from dissect.target.plugins.os.windows.log.evtx import EvtxPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

EVTX_PATH = absolute_path("_data/plugins/apps/shell/powershell/Microsoft-Windows-PowerShell%4Operational.evtx")


@pytest.fixture
def target_powershell(target_win: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_file(f"Windows\\System32\\winevt\\Logs\\{EVTX_PATH.name}", EVTX_PATH)

    target_win.add_plugin(EvtxPlugin)
    target_win.add_plugin(PowershellPlugin)

    return target_win


@pytest.mark.parametrize(
    ("target", "fs", "target_file"),
    [
        (
            "target_win_users",
            "fs_win",
            "users\\John\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\psreadline\\ConsoleHost_history.txt",
        ),
        ("target_unix_users", "fs_unix", "/root/.local/share/powershell/PSReadLine/ConsoleHost_history.txt"),
    ],
)
def test_powershell_history(target: str, fs: str, target_file: str, request: pytest.FixtureRequest) -> None:
    """Test parsing of Powershell ConsoleHost_history.txt files."""
    fs: VirtualFilesystem = request.getfixturevalue(fs)
    target: Target = request.getfixturevalue(target)

    history_file = absolute_path("_data/plugins/apps/shell/powershell/ConsoleHost_history.txt")
    fs.map_file(target_file, history_file)

    if target_file.startswith("users\\"):
        target_file = target_file.replace("users\\", "C:\\Users\\")

    target.add_plugin(PowershellPlugin)

    records = list(target.powershell.history())

    assert len(records) == 4
    assert records[0].command == 'Write-Host "Hello World!"'
    assert records[0].order == 0
    assert str(records[0].source) == target_file


def test_scriptblock(target_powershell: Target) -> None:
    """Test parsing of Powershell 4104 ScriptBlock events."""
    records = list(target_powershell.powershell.scriptblocks())

    assert len(records) == 6

    assert records[0].scriptblock_id == "f77de06b-b6b0-4b6b-80f5-bec298a20e88"
    assert records[0].scriptblock == "Set-ExecutionPolicy Bypass"
    assert records[0].script_complete