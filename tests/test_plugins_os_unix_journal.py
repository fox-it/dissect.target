from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.log.journal import JournalPlugin

from ._utils import absolute_path


def test_journal_plugin(target_unix, fs_unix):
    data_file = absolute_path("data/plugins/os/unix/log/journal")
    fs_unix.map_file("var/log/journal/1337/user-1000.journal", data_file)

    target_unix.add_plugin(JournalPlugin)

    results = list(target_unix.journal())
    record = results[0]

    assert len(results) == 2

    assert record.ts == dt("2023-05-19T16:22:38.841870+00:00")
    assert (
        record.message
        == "Window manager warning: last_user_time (928062) is greater than comparison timestamp (928031).  This most likely represents a buggy client sending inaccurate timestamps in messages such as _NET_ACTIVE_WINDOW.  Trying to work around..."  # noqa: E501
    )
    assert record.syslog_facility == 3
    assert record.syslog_identifier == "gnome-shell"
    assert record.pid == 2096
    assert record.transport == "stdout"
    assert str(record.filepath) == "/var/log/journal/1337/user-1000.journal"
