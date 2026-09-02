from __future__ import annotations

import stat
import textwrap
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock

from flow.record.fieldtypes import datetime as dt

from dissect.target.filesystem import VirtualFile
from dissect.target.helpers import fsutil
from dissect.target.plugins.os.unix.anacronjobs import AnacronjobPlugin, AnacronjobRecord, EnvironmentVariableRecord

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


ANACRONTAB_DEFAULT = """
 # environment variables
 SHELL=/bin/sh
 PATH=/sbin:/bin:/usr/sbin:/usr/bin
 MAILTO=root
 RANDOM_DELAY=30
 # the jobs will be started during the following hours only
 START_HOURS_RANGE=3-22
 # delay will be 5 minutes + RANDOM_DELAY for cron.daily
 1         5    cron.daily          nice run-parts /etc/cron.daily
 7         0    cron.weekly         nice run-parts /etc/cron.weekly
 @monthly  0    cron.monthly        nice run-parts /etc/cron.monthly
"""


def test_unix_anacrontab(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/anacrontab", BytesIO(textwrap.dedent(ANACRONTAB_DEFAULT).encode()))
    fs_unix.map_file_fh("/var/spool/anacron/cron.daily", BytesIO(b"20260206\n"))
    # File to tests enumeration of files references in run-parts commands
    fs_unix.map_file_fh("/etc/cron.daily/logrotate", BytesIO(b"#!/bin/sh\n/usr/sbin/logrotate\n"))

    # Virtual file
    # is set according to file birth and modification time
    weekly_virtual_file = VirtualFile(fs_unix, "/var/spool/anacron/cron.weekly", BytesIO(b"20260119\n"))
    weekly_virtual_file.lstat = Mock()
    weekly_virtual_file.lstat.return_value = fsutil.stat_result(
        [
            stat.S_IFREG,
            0,
            0,
            1,
            0,
            0,
            9,
            int(dt("2026-01-19 03:01:01+00:00").timestamp()),
            int(dt("2026-01-19 02:12:17+00:00").timestamp()),
            int(dt("2026-01-19 02:12:17+00:00").timestamp()),
        ]
    )
    fs_unix.map_file_entry("/var/spool/anacron/cron.weekly", weekly_virtual_file)

    target_unix_users.add_plugin(AnacronjobPlugin)

    results = list(target_unix_users.anacronjobs())

    assert len(results) == 9

    anacronjob_records = [r for r in results if isinstance(r, type(AnacronjobRecord()))]
    environmentvariable_records = [r for r in results if isinstance(r, type(EnvironmentVariableRecord()))]

    assert len(anacronjob_records) == 4
    assert len(environmentvariable_records) == 5

    assert anacronjob_records[0].period_name == "1"
    assert anacronjob_records[0].delay_in_minutes == 5
    assert anacronjob_records[0].job_identify == "cron.daily"
    assert anacronjob_records[0].command == "nice run-parts /etc/cron.daily"
    assert anacronjob_records[0].ts_last_exec == dt("2026-02-06 00:00:00+00:00")
    assert anacronjob_records[0].source == "/etc/anacrontab"
    assert anacronjob_records[0].hostname == "localhost"

    assert anacronjob_records[1].period_name == "1"
    assert anacronjob_records[1].delay_in_minutes == 5
    assert anacronjob_records[1].job_identify == "cron.daily"
    assert anacronjob_records[1].command == "/etc/cron.daily/logrotate"
    # If ts associated to timestamps files are not consistent with date in file, fallback to file content date
    assert anacronjob_records[1].ts_last_exec == dt("2026-02-06 00:00:00+00:00")
    assert anacronjob_records[1].source == "/etc/anacrontab"
    assert anacronjob_records[1].hostname == "localhost"

    assert anacronjob_records[2].period_name == "7"
    assert anacronjob_records[2].delay_in_minutes == 0
    assert anacronjob_records[2].job_identify == "cron.weekly"
    assert anacronjob_records[2].command == "nice run-parts /etc/cron.weekly"
    assert anacronjob_records[2].ts_last_exec == dt("2026-01-19 02:12:17+00:00")

    assert anacronjob_records[3].period_name == "@monthly"
    assert anacronjob_records[3].delay_in_minutes == 0
    assert anacronjob_records[3].job_identify == "cron.monthly"
    assert anacronjob_records[3].command == "nice run-parts /etc/cron.monthly"

    assert anacronjob_records[3].ts_last_exec is None

    # Test env variable
    assert environmentvariable_records[0].key == "SHELL"
    assert environmentvariable_records[0].value == "/bin/sh"
    assert environmentvariable_records[0].source == "/etc/anacrontab"
    assert environmentvariable_records[0].hostname == "localhost"

    assert environmentvariable_records[1].key == "PATH"
    assert environmentvariable_records[1].value == "/sbin:/bin:/usr/sbin:/usr/bin"

    assert environmentvariable_records[4].key == "START_HOURS_RANGE"
    assert environmentvariable_records[4].value == "3-22"


def test_freebsd_anacrontab(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test that anacrontab path on freebsd is also identified."""
    fs_unix.map_file_fh("/usr/local/etc/anacrontab", BytesIO(textwrap.dedent(ANACRONTAB_DEFAULT).encode()))
    target_unix_users.add_plugin(AnacronjobPlugin)

    results = list(target_unix_users.anacronjobs())
    assert len(results) == 8
