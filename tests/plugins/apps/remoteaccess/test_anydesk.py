import operator
import uuid
from datetime import datetime, timezone

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.remoteaccess.anydesk import AnydeskPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_anydesk_plugin_log(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "ProgramData/AnyDesk/TestAnydesk.trace",
        absolute_path("_data/plugins/apps/remoteaccess/anydesk/TestAnydesk.trace"),
    )

    target_win_users.add_plugin(AnydeskPlugin)

    records = list(target_win_users.anydesk.logs())
    assert len(records) == 1

    assert records[0].ts == datetime(2021, 11, 11, 12, 34, 56, 789000, tzinfo=timezone.utc)
    assert records[0].message == "LEVEL Strip the headers, trace the source!"
    assert records[0].source == "sysvol/ProgramData/AnyDesk/TestAnydesk.trace"
    assert records[0].username is None
    assert records[0].user_id is None
    assert records[0].user_home is None


def test_anydesk_plugin_user_log(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "Users/John/AppData/Roaming/AnyDesk/TestAnydesk.trace",
        absolute_path("_data/plugins/apps/remoteaccess/anydesk/TestAnydesk.trace"),
    )

    target_win_users.add_plugin(AnydeskPlugin)

    records = list(target_win_users.anydesk.logs())
    records.sort(key=operator.attrgetter("source"))
    assert len(records) == 1

    user_details = target_win_users.user_details.find(username="John")
    assert records[0].ts == datetime(2021, 11, 11, 12, 34, 56, 789000, tzinfo=timezone.utc)
    assert records[0].message == "LEVEL Strip the headers, trace the source!"
    assert records[0].source == "C:/Users/John/AppData/Roaming/AnyDesk/TestAnydesk.trace"
    assert records[0].username == user_details.user.name
    assert records[0].user_id == user_details.user.sid
    assert records[0].user_home == user_details.user.home


def test_anydesk_plugin_multiple_trace_files(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    trace_file = absolute_path("_data/plugins/apps/remoteaccess/anydesk/Another.trace")
    trace_files = 0

    for str_path in AnydeskPlugin.SERVICE_GLOBS:
        if "var/log/" in str_path:
            continue
        fs_win.map_file(str_path.replace("sysvol/", "").replace("*", uuid.uuid4().hex[:6]), trace_file)
        trace_files += 1

    for str_path in AnydeskPlugin.USER_GLOBS:
        if str_path.startswith(".anydesk"):
            continue
        fs_win.map_file("Users\\John\\" + str_path.replace("*", uuid.uuid4().hex[:6]), trace_file)
        trace_files += 1

    target_win_users.add_plugin(AnydeskPlugin)
    records = list(target_win_users.anydesk.logs())

    assert len(target_win_users.anydesk.trace_files) == trace_files
    assert len(records) == trace_files * 419


def test_anydesk_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    trace_file = absolute_path("_data/plugins/apps/remoteaccess/anydesk/Another.trace")
    fs_unix.map_file("/var/log/anydesk/1337.trace", trace_file)
    fs_unix.map_file("/root/.anydesk/1337.trace", trace_file)
    fs_unix.map_file("/root/.anydesk_ad_1337/1337.trace", trace_file)

    target_unix_users.add_plugin(AnydeskPlugin)
    records = list(target_unix_users.anydesk.logs())

    assert len(target_unix_users.anydesk.trace_files) == 3
    assert len(records) == 3 * 419
