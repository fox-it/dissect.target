import logging

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.log.journal import JournalPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_journal_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """test linux systemd journal file parsing."""

    data_file = absolute_path("_data/plugins/os/unix/log/journal/journal")
    fs_unix.map_file("var/log/journal/1337/user-1000.journal", data_file)
    target_unix.add_plugin(JournalPlugin)

    results = list(target_unix.journal())
    assert len(results) == 2

    record = results[0]
    assert record.ts == dt("2023-05-19T16:22:38.841870+00:00")
    assert record.message == (
        "Window manager warning: last_user_time (928062) is greater than comparison timestamp (928031).  "
        "This most likely represents a buggy client sending inaccurate timestamps in messages such as "
        "_NET_ACTIVE_WINDOW.  Trying to work around..."
    )
    assert record.syslog_facility == "3"
    assert record.syslog_identifier == "gnome-shell"
    assert record.pid == 2096
    assert record.transport == "stdout"
    assert record.source == "/var/log/journal/1337/user-1000.journal"


def test_journal_plugin_benchmark(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """test if we can parse some large journal files. this demonstrates how slow the journal plugin is."""

    system_journal = absolute_path("_data/plugins/os/unix/log/journal/system.journal")
    user_journal = absolute_path("_data/plugins/os/unix/log/journal/user-1000.journal")

    fs_unix.map_file("/var/log/journal/deadbeef/system.journal", system_journal)
    fs_unix.map_file("/var/log/journal/deadbeef/user-1000.journal", user_journal)
    target_unix.add_plugin(JournalPlugin)

    results = list(target_unix.journal())
    assert len(results) == 252 + 17986


def test_journal_plugin_unused_object(
    caplog: pytest.LogCaptureFixture, target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    """test if we can handle OBJECT_UNUSED in journal files correctly."""

    # unused.journal is a modified copy of system.journal at offset 0x393260.
    # the next_entry_array_offset was set from 0x00 to 0x3C1337.
    data_file = absolute_path("_data/plugins/os/unix/log/journal/unused.journal")
    fs_unix.map_file("/var/log/journal/deadbeef/system.journal", data_file)
    target_unix.add_plugin(JournalPlugin)

    with caplog.at_level(logging.WARNING):
        results = list(target_unix.journal())

    assert "ObjectType OBJECT_UNUSED encountered for next OBJECT_ENTRY_ARRAY offset at 0x3C1337" in caplog.text
    assert len(results) == 252
