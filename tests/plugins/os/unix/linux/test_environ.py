from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.proc import ProcPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_environ(target_linux_users: Target, fs_linux_proc: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.environ())
    assert len(results) == 4
