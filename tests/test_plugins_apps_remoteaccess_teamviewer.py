from datetime import datetime

from dissect.target.plugins.apps.remoteaccess.teamviewer import TeamviewerPlugin

from ._utils import absolute_path


def test_teamviewer_plugin_global_log(target_win_users, fs_win):
    teamviewer_logfile = absolute_path("data/TestTeamviewer.log")
    target_logfile_name = "/sysvol/Program Files/TeamViewer/TestTeamviewer.log"

    _, _, map_path = target_logfile_name.partition("sysvol/")
    fs_win.map_file(map_path, teamviewer_logfile)

    tvp = TeamviewerPlugin(target_win_users)

    records = list(tvp.remoteaccess())
    assert len(records) == 1

    record = records[0]
    assert record.ts == datetime(2021, 11, 11, 12, 34, 56)
    assert record.description == "Strip the headers, trace the source!"
    assert record.logfile == target_logfile_name
    assert record.username is None
    assert record.user_id is None
    assert record.user_home is None


def test_teamviewer_plugin_user_log(target_win_users, fs_win):
    teamviewer_logfile = absolute_path("data/TestTeamviewer.log")
    user_details = target_win_users.user_details.find(username="John")
    target_logfile_name = f"{user_details.home_path}/appdata/roaming/teamviewer/teamviewer_TEST_logfile.log"

    _, _, map_path = target_logfile_name.partition("C:/")
    fs_win.map_file(map_path, teamviewer_logfile)

    tvp = TeamviewerPlugin(target_win_users)

    records = list(tvp.remoteaccess())
    assert len(records) == 1

    record = records[0]
    assert record.ts == datetime(2021, 11, 11, 12, 34, 56)
    assert record.description == "Strip the headers, trace the source!"
    assert record.logfile == target_logfile_name
    assert record.username == user_details.user.name
    assert record.user_id == user_details.user.sid
    assert record.user_home == user_details.user.home
