import tarfile
import textwrap
from datetime import datetime, timezone
from io import BytesIO
from unittest.mock import patch
from zoneinfo import ZoneInfo

from flow.record.fieldtypes import datetime as dt
from flow.record.fieldtypes import path

from dissect.target import Target
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.plugins.general import default
from dissect.target.plugins.os.unix.log.messages import MessagesPlugin, MessagesRecord

from ._utils import absolute_path


def test_unix_log_messages_plugin(target_unix_users, fs_unix):
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))

    data_file = absolute_path("data/unix/logs/messages")
    fs_unix.map_file("var/log/messages", data_file)

    entry = fs_unix.get("var/log/messages")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix_users.add_plugin(MessagesPlugin)

        results = list(target_unix_users.messages())
        assert len(results) == 2

        assert results[0].ts == datetime(2022, 1, 1, 13, 21, 34, tzinfo=ZoneInfo("Europe/Amsterdam"))
        assert results[0].message == "Stopped target Swap."
        assert results[0].pid is None
        assert results[0].source == path.from_posix("/var/log/messages")

        assert results[1].ts == datetime(2021, 12, 31, 3, 14, 15, tzinfo=ZoneInfo("Europe/Amsterdam"))
        assert results[1].message == "Starting Journal Service..."
        assert results[1].pid == 1
        assert results[1].source == path.from_posix("/var/log/messages")

    # assure syslog() behaves the same as messages()
    syslogs = list(target_unix_users.syslog())
    assert len(syslogs) == len(results)
    assert isinstance(syslogs[0], type(MessagesRecord()))


def test_unix_log_messages_compressed_timezone_year_rollover():
    target = Target()
    bio = BytesIO()

    with tarfile.open(mode="w:gz", fileobj=bio) as tf:
        # UTC-6 tar filesystem
        timezone_contents = "America/Chicago"
        timezone_file = BytesIO(textwrap.dedent(timezone_contents).encode())
        timezone_tar_info = tarfile.TarInfo("etc/timezone")
        timezone_tar_info.size = len(timezone_contents)
        tf.addfile(timezone_tar_info, timezone_file)

        # Create a tar file with correct mtime
        messages_log_contents = """\
        Dec 31 03:14:00 localhost systemd[1]: Starting Journal Service...
        Jan  1 13:37:00 localhost systemd: Stopped target Swap."""
        messages_log_file = BytesIO(textwrap.dedent(messages_log_contents).encode())
        messages_log_tar_info = tarfile.TarInfo("var/log/messages")
        messages_log_tar_info.size = len(textwrap.dedent(messages_log_contents))
        messages_log_tar_info.mtime = 1640995800  # (Sat 1 January 2022 00:10:00 UTC)
        tf.addfile(messages_log_tar_info, messages_log_file)

    fs = TarFilesystem(bio)
    target.filesystems.add(fs)
    target.fs.mount("/", fs)
    target.add_plugin(default.DefaultPlugin)
    target.add_plugin(MessagesPlugin)
    results = list(target.messages())
    results.reverse()

    assert len(results) == 2
    assert isinstance(results[0], type(MessagesRecord()))
    assert isinstance(results[1], type(MessagesRecord()))
    assert results[0].ts == dt(2020, 12, 31, 3, 14, 0, tzinfo=ZoneInfo("America/Chicago"))
    assert results[1].ts == dt(2021, 1, 1, 13, 37, 0, tzinfo=ZoneInfo("America/Chicago"))
