from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.proc import ProcPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_mounts(target_linux_users: Target, fs_linux_proc: VirtualFilesystem) -> None:
    target_linux_users.add_plugin(ProcPlugin)
    results = list(target_linux_users.mounts())

    assert len(results) == 6

    sum_pid_results = defaultdict(int)
    for result in results:
        sum_pid_results[result.pid] += 1

    assert sum_pid_results[1] == 2

    assert sum_pid_results[2] == 2

    assert sum_pid_results[3] == 2

    assert sum_pid_results[4] == 0
