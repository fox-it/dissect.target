from __future__ import annotations

import gzip
import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.log.helpers import is_iso_fmt, iso_readlines

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem

syslog = """\
Dec 31 03:14:15 localhost systemd[1]: Starting Journal Service...
Jan  1 13:21:34 localhost systemd: Stopped target Swap.
Jan  2 03:14:15 localhost systemd[1]: Starting Journal Service...
Jan  3 13:21:34 localhost systemd: Stopped target Swap.
2024-12-31T13:37:00.123456+02:00 hostname systemd[1]: Started anacron.service - Run anacron jobs.
2024-12-31T13:37:00.123456+02:00 hostname anacron[1337]: Anacron 2.3 started on 2024-12-31
2024-12-31T13:37:00.123456+02:00 hostname anacron[1337]: Normal exit (0 jobs run)
2024-12-31T13:37:00.123456+02:00 hostname systemd[1]: anacron.service: Deactivated successfully.
"""


@pytest.mark.parametrize(
    ("max_lines", "expected_return_value"),
    [
        (3, False),
        (4, False),
        (5, True),
        (9, True),
    ],
)
def test_iso_readlines_max_lines(fs_unix: VirtualFilesystem, max_lines: int, expected_return_value: bool) -> None:
    """Assert that iso_readlines does not parse more than the provided max_lines."""

    fs_unix.map_file_fh("/var/log/syslog.2", BytesIO(gzip.compress(textwrap.dedent(syslog).encode())))
    assert any(iso_readlines(fs_unix.path("/var/log/syslog.2"), max_lines)) == expected_return_value


def test_is_iso_fmt(fs_unix: VirtualFilesystem) -> None:
    """Assert that is_iso_fmt does not parse more than three max_lines."""

    fs_unix.map_file_fh("/var/log/syslog.3", BytesIO(gzip.compress(textwrap.dedent(syslog).encode())))
    assert not is_iso_fmt(fs_unix.path("/var/log/syslog.3"))
