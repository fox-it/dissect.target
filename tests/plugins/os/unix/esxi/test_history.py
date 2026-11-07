from __future__ import annotations

import datetime
import gzip
import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.esxi.history import ESXICommandHistoryPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

COMMANDHISTORY_DATA = """\
2026-01-01T02:03:04.891Z In(14) shell[37790689]: Interactive shell session started
2026-01-01T02:03:04.891Z In(14) shell[37790689]: [root]: ls -lah
2026-01-01T03:04:04.891Z ESXShell: ESXi Shell unavailable

"""


def test_esxi_history(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/var/run/log/shell.log", BytesIO(textwrap.dedent(COMMANDHISTORY_DATA).encode()))
    target_unix.add_plugin(ESXICommandHistoryPlugin)

    results = list(target_unix.commandhistory())
    assert len(results) == 3
