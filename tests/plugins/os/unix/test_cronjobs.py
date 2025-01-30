from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.cronjobs import CronjobPlugin
from dissect.target.target import Target


def test_unix_cronjobs_system(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """test if we correctly infer the username of the cronjob from the command."""

    fs_unix.map_file_fh("/etc/crontab", BytesIO(b"17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly"))
    target_unix_users.add_plugin(CronjobPlugin)

    results = list(target_unix_users.cronjobs())
    assert len(results) == 1
    assert results[0].minute == "17"
    assert results[0].hour == "*"
    assert results[0].day == "*"
    assert results[0].month == "*"
    assert results[0].weekday == "*"
    assert results[0].user == "root"
    assert results[0].command == "cd / && run-parts --report /etc/cron.hourly"


def test_unix_cronjobs_user(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """test if we correctly infer the username of the crontab from the file path."""

    fs_unix.map_file_fh("/var/spool/cron/crontabs/user", BytesIO(b"0 0 * * * /path/to/example.sh\n"))
    target_unix_users.add_plugin(CronjobPlugin)

    results = list(target_unix_users.cronjobs())
    assert len(results) == 1
    assert results[0].minute == "0"
    assert results[0].hour == "0"
    assert results[0].day == "*"
    assert results[0].month == "*"
    assert results[0].weekday == "*"
    assert results[0].user == "user"
    assert results[0].command == "/path/to/example.sh"
