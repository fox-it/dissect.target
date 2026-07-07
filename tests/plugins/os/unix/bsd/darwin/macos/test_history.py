from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.bsd.darwin.macos._os import MacOSPlugin
from dissect.target.plugins.os.unix.history import CommandHistoryPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_macos_command_history(target_macos_users: Target, fs_macos: VirtualFilesystem) -> None:
    """Test if we parse macOS zsh shell history.

    References:
        - https://cfreds.nist.gov/all/Hexordia/2026MVSCTFMac
    """
    fs_macos.map_dir("/Users/alexmaurie/.zsh_sessions", absolute_path("_data/plugins/os/unix/bsd/darwin/macos/history"))
    target_macos_users.add_plugin(MacOSPlugin)
    target_macos_users.add_plugin(CommandHistoryPlugin)

    records = list(target_macos_users.commandhistory())
    assert len(records) == 7
    assert [r.command for r in records] == [
        '/bin/bash/ -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
        '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
        "echo >> /Users/alexmaurie/.zprofile",
        "echo 'eval \"$(/usr/local/bin/brew shellenv)\"' >> /Users/alexmaurie/.zprofile",
        'eval "$(/usr/local/bin/brew shellenv)"',
        "sudo tmutil setdestination /Volumes/bkp",
        "sudo tmutil setdestination /Volumes/bkp",
    ]
