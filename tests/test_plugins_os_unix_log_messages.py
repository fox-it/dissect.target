from datetime import datetime, timezone
from os import stat

from flow.record.fieldtypes import path

from dissect.target.plugins.os.unix.log.messages import MessagesPlugin

from ._utils import absolute_path


def test_unix_log_messages_plugin(target_unix, fs_unix):

    data_file = absolute_path("data/unix/logs/messages")
    fs_unix.map_file("var/log/messages", data_file)

    year = datetime.fromtimestamp(stat(absolute_path("data/unix/logs/messages")).st_ctime).year

    target_unix.add_plugin(MessagesPlugin)

    results = list(target_unix.messages())
    assert len(results) == 2

    assert results[0].ts == datetime(year, 12, 31, 3, 14, 15, tzinfo=timezone.utc)
    assert results[0].message == "Starting Journal Service..."
    assert results[0].pid == 1
    assert results[0].source == path.from_posix("/var/log/messages")

    assert results[1].ts == datetime(year + 1, 1, 1, 13, 21, 34, tzinfo=timezone.utc)
    assert results[1].message == "Stopped target Swap."
    assert results[1].pid is None
    assert results[1].source == path.from_posix("/var/log/messages")
