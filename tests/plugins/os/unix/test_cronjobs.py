from __future__ import annotations

import textwrap
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.cronjobs import CronjobPlugin, CronjobRecord

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_unix_cronjobs_system(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly infer the username of the cronjob from the command."""

    fs_unix.map_file_fh(
        "/etc/crontab", BytesIO(b"17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly")
    )
    target_unix_users.add_plugin(CronjobPlugin)

    results = list(target_unix_users.cronjobs())
    assert len(results) == 1
    assert results[0].minute == "17"
    assert results[0].hour == "*"
    assert results[0].day == "*"
    assert results[0].month == "*"
    assert results[0].weekday == "*"
    assert results[0].username == "root"
    assert results[0].command == "cd / && run-parts --report /etc/cron.hourly"


def test_unix_cronjobs_user(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly infer the username of the crontab from the file path."""

    fs_unix.map_file_fh("/var/spool/cron/crontabs/user", BytesIO(b"0 0 * * * /path/to/example.sh\n"))
    target_unix_users.add_plugin(CronjobPlugin)

    results = list(target_unix_users.cronjobs())
    assert len(results) == 1
    assert results[0].minute == "0"
    assert results[0].hour == "0"
    assert results[0].day == "*"
    assert results[0].month == "*"
    assert results[0].weekday == "*"
    assert results[0].username == "user"
    assert results[0].command == "/path/to/example.sh"


def test_unix_cronjobs_env(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we parse environment variables inside crontab files correctly."""

    crontab = """
    FOO=bar
    PATH=/path/to/some/example
    0 0 * * * example.sh
    """

    fs_unix.map_file_fh("/etc/crontab", BytesIO(textwrap.dedent(crontab).encode()))

    results = list(target_unix.cronjobs())
    assert len(results) == 3
    assert results[0].key == "FOO"
    assert results[0].value == "bar"
    assert results[1].key == "PATH"
    assert results[1].value == "/path/to/some/example"
    assert results[2].command == "example.sh"
    assert results[2].username is None


@pytest.mark.parametrize(
    ("cron_line", "expected_output", "expected_user"),
    [
        (
            "0 0 * * * FOO=bar    /path/to/some/script.sh",
            {
                "command": "FOO=bar    /path/to/some/script.sh",
                "day": "*",
                "hour": "0",
                "minute": "0",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            None,
        ),
        (
            "0 * * * * source some-file ; /path/to/some/script.sh",
            {
                "command": "source some-file ; /path/to/some/script.sh",
                "day": "*",
                "hour": "*",
                "minute": "0",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            None,
        ),
        (
            r"0 0 * * * sleep ${RANDOM:0:1} && /path/to/executable",
            {
                "command": r"sleep ${RANDOM:0:1} && /path/to/executable",
                "day": "*",
                "hour": "0",
                "minute": "0",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            None,
        ),
        (
            "*/5 * * * * /bin/bash -c 'source /some-file; echo \"FOO: $BAR\" >> /var/log/some.log 2>&1'",
            {
                "command": "/bin/bash -c 'source /some-file; echo \"FOO: $BAR\" >> /var/log/some.log 2>&1'",
                "day": "*",
                "hour": "*",
                "minute": "*/5",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            None,
        ),
        (
            "0 0 * * * example.sh",
            {
                "command": "example.sh",
                "day": "*",
                "hour": "0",
                "minute": "0",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            None,
        ),
        (
            "0 0 * * * root example.sh",
            {
                "command": "root example.sh",
                "day": "*",
                "hour": "0",
                "minute": "0",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            "root",
        ),
        (
            "0 0 * * * root\texample.sh",
            {
                "command": "example.sh",
                "day": "*",
                "hour": "0",
                "minute": "0",
                "month": "*",
                "source": "/etc/crontab",
                "weekday": "*",
            },
            "root",
        ),
    ],
)
def test_unix_cronjobs_fuzz(
    cron_line: str,
    expected_output: dict,
    expected_user: str | None,
    target_unix_users: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    """Test if we can handle different cronjob line formats without breaking."""

    fs_unix.map_file_fh("/etc/crontab", BytesIO(cron_line.encode()))
    results = list(target_unix_users.cronjobs())
    assert len(results) == 1
    assert {
        k: v for k, v in results[0]._asdict().items() if k in [f for _, f in CronjobRecord.target_fields]
    } == expected_output
    assert results[0].username == expected_user
