from __future__ import annotations

import pytest

from dissect.target.plugins.apps.shell.powershell import PowerShellHistoryPlugin
from tests._utils import absolute_path


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
def test_powershell(target: str, fs: str, target_file: str, request: pytest.FixtureRequest) -> None:
    fs = request.getfixturevalue(fs)
    target = request.getfixturevalue(target)

    history_file = absolute_path("_data/plugins/os/windows/powershell/ConsoleHost_history.txt")
    fs.map_file(target_file, history_file)

    if target_file.startswith("users\\"):
        target_file = target_file.replace("users\\", "C:\\Users\\")

    target.add_plugin(PowerShellHistoryPlugin)

    records = list(target.powershell_history())

    assert len(records) == 4
    assert records[0].command == 'Write-Host "Hello World!"'
    assert records[0].order == 0
    assert str(records[0].source) == target_file
