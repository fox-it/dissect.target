from datetime import datetime
from io import BytesIO
from os import stat
from zoneinfo import ZoneInfo

from flow.record.fieldtypes import path

from dissect.target.plugins.os.unix.log.messages import MessagesPlugin, MessagesRecord

from ._utils import absolute_path


def test_unix_log_messages_plugin(target_unix_users, fs_unix):

    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))

    data_file = absolute_path("data/unix/logs/messages")
    fs_unix.map_file("var/log/messages", data_file)

    year = datetime.fromtimestamp(stat(absolute_path("data/unix/logs/messages")).st_mtime).year

    target_unix_users.add_plugin(MessagesPlugin)

    results = list(target_unix_users.messages())
    assert len(results) == 2

    assert results[0].ts == datetime(year, 1, 1, 13, 21, 34, tzinfo=ZoneInfo("Europe/Amsterdam"))
    assert results[0].message == "Stopped target Swap."
    assert results[0].pid is None
    assert results[0].source == path.from_posix("/var/log/messages")

    assert results[1].ts == datetime(year - 1, 12, 31, 3, 14, 15, tzinfo=ZoneInfo("Europe/Amsterdam"))
    assert results[1].message == "Starting Journal Service..."
    assert results[1].pid == 1
    assert results[1].source == path.from_posix("/var/log/messages")

    # assure syslog() behaves the same as messages()
    syslogs = list(target_unix_users.syslog())
    assert len(syslogs) == len(results)
    assert isinstance(syslogs[0], type(MessagesRecord()))
