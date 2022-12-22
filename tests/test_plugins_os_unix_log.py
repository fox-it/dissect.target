from dissect.target.plugins.os.unix.log.wtmp import WtmpPlugin
from dissect.target.plugins.os.unix.log.lastlog import LastLogPlugin
from dissect.target.plugins.os.unix.log.btmp import BtmpPlugin

from ._utils import absolute_path


def test_wtmp_plugin(target_unix, fs_unix):

    data_file = absolute_path("data/unix-logs/wtmp")
    fs_unix.map_file("var/log/wtmp", data_file)

    target_unix.add_plugin(WtmpPlugin)

    results = list(target_unix.wtmp())
    assert len(results) == 70


def test_lastlog_plugin(target_unix_users, fs_unix):

    data_file = absolute_path("data/unix-logs/lastlog2")
    fs_unix.map_file("/var/log/lastlog", data_file)

    target_unix_users.add_plugin(LastLogPlugin)

    results = list(target_unix_users.lastlog())
    assert len(results) == 1

    assert results[0].uid == 1001
    assert results[0].ut_host == "127.0.0.1"
    assert results[0].ut_tty == "pts/0"


def test_btmp_plugin(target_unix, fs_unix):

    data_file = absolute_path("data/unix-logs/btmp")
    fs_unix.map_file("var/log/btmp", data_file)

    target_unix.add_plugin(BtmpPlugin)

    results = list(target_unix.btmp())
    assert len(results) == 10
