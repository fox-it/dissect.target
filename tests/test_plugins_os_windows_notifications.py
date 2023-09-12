from flow.record.fieldtypes import datetime

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.plugins.os.windows.notifications import (
    NOTIFICATIONS_DIR,
    NotificationsPlugin,
)
from dissect.target.target import Target

from ._utils import absolute_path

USER_DIR = "Users\\John"


def test_notifications_appdb(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    test_file = absolute_path("data/plugins/os/windows/notifications/appdb.dat.v3.gz")
    appdb_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "appdb.dat")
    fs_win.map_file(appdb_file, test_file, compression="gzip")

    target_win_users.add_plugin(NotificationsPlugin)
    records = list(target_win_users.notifications.appdb())

    assert len(records) == 18

    record = records[0]
    assert len(record.records) == 6

    chunk = record.records[0]
    tiles = record.records[1:]
    assert chunk._desc.name == "windows/notification/appdb_chunk"
    assert chunk.timestamp == datetime("2016-06-02T10:00:34.019495+00:00")
    assert chunk.next_notification_id == 517
    assert chunk.push_ts1 is None
    assert chunk.push_ts2 is None
    assert chunk.push_uri == ""
    assert chunk.badge_id == 0
    assert chunk.badge_ts is None
    assert chunk.badge_data == ""

    tile_ids = [0x01F9, 0x01AF, 0x01B6, 0x01BC, 0x01F3]
    for tile_no, tile in enumerate(tiles):
        assert tile._desc.name == "windows/notification/appdb_tile"
        assert tile.id == tile_ids[tile_no]
        assert tile.arrival_time.year == 2016
        assert tile.expiry_time.year == 2016
        assert tile.type == 3
        assert tile.index == tile_no
        assert tile.name == ""
        assert tile.content.startswith("<?xml")

    record = records[3]
    assert len(record.records) == 9

    chunk = record.records[0]
    toasts = record.records[5:]
    assert chunk.badge_id == 0x7A
    assert chunk.badge_data.startswith("<badge")

    toast_ids = [0x00BF, 0x00C1, 0x00B7, 0x00C0]
    toast_name1 = ["0", "0", "0", "1"]
    for toast_num, toast in enumerate(toasts):
        assert toast._desc.name == "windows/notification/appdb_toast"
        assert toast.id == toast_ids[toast_num]
        assert toast.name1 in toast_name1[toast_num]
        assert toast.name2 == "MailGroup"

    record = records[8]
    assert len(record.records) == 6

    chunk = record.records[0]
    assert chunk.push_ts1 == datetime("2016-06-19T07:37:38+00:00")
    assert chunk.push_ts2 == datetime("2016-05-20T07:41:45.883432+00:00")
    assert chunk.push_uri == (
        "https://db5.notify.windows.com/?token=AwYAAAA%2bwMdZymXtvB9uG3YbJZX4U"
        "CXwsLBJA7it1REPu58SjiQ8%2bnxg%2bfk8vKU%2bQQPG5ZglOuCq%2fkArOGxBJr9z7G"
        "K%2bQFwyrTcaOyptsKNF2f%2fllCPmmGwXsFAFjS%2fkdC678PQ%3d"
    )


def test_notifications_wpndatabase(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    test_file = absolute_path("data/plugins/os/windows/notifications/wpndatabase.db")
    wpndatabase_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "wpndatabase.db")
    fs_win.map_file(wpndatabase_file, test_file)

    target_win_users.add_plugin(NotificationsPlugin)

    records = list(target_win_users.notifications.wpndatabase())

    assert len(records) == 3
