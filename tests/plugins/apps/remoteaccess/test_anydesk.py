from datetime import datetime, timezone
import operator

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
    assert records[0].description == "LEVEL Strip the headers, trace the source!"
    assert records[0].logfile == "sysvol/ProgramData/AnyDesk/TestAnydesk.trace"
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
    records.sort(key=operator.attrgetter("logfile"))
    assert len(records) == 2  # BUG: For some reason the path from the previous test is still present here.

    user_details = target_win_users.user_details.find(username="John")
    assert records[0].ts == datetime(2021, 11, 11, 12, 34, 56, 789000, tzinfo=timezone.utc)
    assert records[0].description == "LEVEL Strip the headers, trace the source!"
    assert records[0].logfile == "C:/Users/John/AppData/Roaming/AnyDesk/TestAnydesk.trace"
    assert records[0].username == user_details.user.name
    assert records[0].user_id == user_details.user.sid
    assert records[0].user_home == user_details.user.home


def test_anydesk_plugin_multiple_trace_files(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    trace_file = absolute_path("_data/plugins/apps/remoteaccess/anydesk/Another.trace")

    for str_path in AnydeskPlugin.SERVICE_GLOBS:
        fs_win.map_file(str_path.replace("sysvol/", "").replace("*", "example"), trace_file)

    for str_path in AnydeskPlugin.USER_GLOBS:
        fs_win.map_file("Users\\John\\" + str_path.replace("*", "example"), trace_file)

    target_win_users.add_plugin(AnydeskPlugin)

    records = list(target_win_users.anydesk.logs())
    trace_files_count = len(AnydeskPlugin.SERVICE_GLOBS + AnydeskPlugin.USER_GLOBS)

    # BUG: For some reason the paths from the previous tests are still present here.
    trace_files_count += 1

    assert len(target_win_users.anydesk.trace_files) == trace_files_count
    assert len(records) == 9 * 419 + 2
