from dissect.target.plugins.os.unix.log.wtmp import WtmpPlugin
from dissect.target.plugins.os.unix.log.lastlog import LastlogPlugin
from dissect.target.plugins.os.unix.log.btmp import BtmpPlugin

from ._utils import absolute_path


def test_wtmp_plugin(target_unix, fs_unix):

    data_file = absolute_path("data/unix-logs/wtmp")
    fs_unix.map_file("var/log/wtmp", data_file)

    target_unix.add_plugin(WtmpPlugin)

    results = list(target_unix.wtmp())
    assert len(results) == 70


def test_lastlog_plugin(target_unix, fs_unix):

    data_file = absolute_path("data/unix-logs/lastlog")
    fs_unix.map_file("var/log/lastlog", data_file)

    target_unix.add_plugin(LastlogPlugin)

    results = list(target_unix.lastlog())
    assert len(results) == 10


def test_btmp_plugin(target_unix, fs_unix):

    data_file = absolute_path("data/unix-logs/btmp")
    fs_unix.map_file("var/log/btmp", data_file)

    target_unix.add_plugin(BtmpPlugin)

    results = list(target_unix.btmp())
    assert len(results) == 10
