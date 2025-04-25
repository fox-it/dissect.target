from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime

from dissect.target.helpers import fsutil
from dissect.target.plugins.os.windows.notifications import (
    NOTIFICATIONS_DIR,
    NotificationsPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

USER_DIR = "Users\\John"


def test_notifications_appdb(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    test_file = absolute_path("_data/plugins/os/windows/notifications/appdb.dat.v3.gz")
    appdb_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "appdb.dat")
    fs_win.map_file(appdb_file, test_file, compression="gzip")
    target_win_users.add_plugin(NotificationsPlugin)

    records_by_type = defaultdict(list)
    for record in target_win_users.notifications.appdb():
        record_type = record._desc.name
        records_by_type[record_type].append(record)

    records_by_type_chunk = defaultdict(lambda: defaultdict(list))
    for record_type, records in records_by_type.items():
        if record_type != "windows/notification/appdb":
            for record in records:
                chunk_num = record.chunk_num
                records_by_type_chunk[record_type][chunk_num].append(record)

    assert len(records_by_type.get("windows/notification/appdb", [])) == 1
    assert len(records_by_type.get("windows/notification/appdb/push", [])) == 1
    assert len(records_by_type.get("windows/notification/appdb/badge", [])) == 2
    assert len(records_by_type.get("windows/notification/appdb/tile", [])) == 48
    assert len(records_by_type.get("windows/notification/appdb/toast", [])) == 35

    appdb_record = records_by_type["windows/notification/appdb"][0]
    assert appdb_record.timestamp == datetime("2016-06-02T10:00:34.019495+00:00")
    assert appdb_record.version == 3
    assert appdb_record.next_notification_id == 517

    push_record = records_by_type_chunk["windows/notification/appdb/push"][8][0]
    assert push_record.push_ts1 == datetime("2016-06-19T07:37:38+00:00")
    assert push_record.push_ts2 == datetime("2016-05-20T07:41:45.883432+00:00")
    assert push_record.push_uri == (
        "https://db5.notify.windows.com/?token=AwYAAAA%2bwMdZymXtvB9uG3YbJZX4U"
        "CXwsLBJA7it1REPu58SjiQ8%2bnxg%2bfk8vKU%2bQQPG5ZglOuCq%2fkArOGxBJr9z7G"
        "K%2bQFwyrTcaOyptsKNF2f%2fllCPmmGwXsFAFjS%2fkdC678PQ%3d"
    )

    badge_record = records_by_type_chunk["windows/notification/appdb/badge"][3][0]
    assert badge_record.badge_ts is None
    assert badge_record.badge_id == 0x7A
    assert badge_record.badge_data.startswith("<badge")

    badge_record = records_by_type_chunk["windows/notification/appdb/badge"][10][0]
    assert badge_record.badge_ts is None
    assert badge_record.badge_id == 0x18
    assert badge_record.badge_data.startswith("<badge")

    tiles = records_by_type_chunk["windows/notification/appdb/tile"][0]
    tile_ids = [0x01F9, 0x01AF, 0x01B6, 0x01BC, 0x01F3]
    for tile_no, tile in enumerate(tiles):
        assert tile.arrival_time.year == 2016
        assert tile.expiry_time.year == 2016
        assert tile.id == tile_ids[tile_no]
        assert tile.type == 3
        assert tile.index == tile_no
        assert tile.name == ""
        assert tile.content.startswith("<?xml")

    toasts = records_by_type_chunk["windows/notification/appdb/toast"][3]
    toast_ids = [0x00BF, 0x00C1, 0x00B7, 0x00C0]
    toast_name1 = ["0", "0", "0", "1"]
    for toast_num, toast in enumerate(toasts):
        assert toast.id == toast_ids[toast_num]
        assert toast.name1 in toast_name1[toast_num]
        assert toast.name2 == "MailGroup"


def test_notifications_wpndatabase(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    test_file = absolute_path("_data/plugins/os/windows/notifications/wpndatabase.db")
    wpndatabase_file = fsutil.join(USER_DIR, NOTIFICATIONS_DIR, "wpndatabase.db")
    fs_win.map_file(wpndatabase_file, test_file)

    target_win_users.add_plugin(NotificationsPlugin)

    records = list(target_win_users.notifications.wpndatabase())

    assert len(records) == 3
