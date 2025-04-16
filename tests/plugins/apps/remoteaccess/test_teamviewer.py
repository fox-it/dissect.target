from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from textwrap import dedent
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.remoteaccess.teamviewer import TeamViewerPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_teamviewer_global_log(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    teamviewer_logfile = absolute_path("_data/plugins/apps/remoteaccess/teamviewer/TestTeamviewer.log")
    target_logfile_name = "/sysvol/Program Files/TeamViewer/TestTeamviewer.log"

    _, _, map_path = target_logfile_name.partition("sysvol/")
    fs_win.map_file(map_path, teamviewer_logfile)

    tvp = TeamViewerPlugin(target_win_users)

    records = list(tvp.logs())
    assert len(records) == 4

    assert records[0].ts == datetime(2021, 11, 11, 12, 34, 56, tzinfo=timezone.utc)
    assert records[0].message == "Strip the headers, trace the source!"
    assert records[0].source == target_logfile_name
    assert records[0].username is None
    assert records[0].user_id is None
    assert records[0].user_home is None


def test_teamviewer_user_log(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    teamviewer_logfile = absolute_path("_data/plugins/apps/remoteaccess/teamviewer/TestTeamviewer.log")
    user_details = target_win_users.user_details.find(username="John")
    target_logfile_name = f"{user_details.home_path}/appdata/roaming/teamviewer/teamviewer_TEST_logfile.log"

    _, _, map_path = target_logfile_name.partition("C:/")
    fs_win.map_file(map_path, teamviewer_logfile)

    tvp = TeamViewerPlugin(target_win_users)

    records = list(tvp.logs())
    assert len(records) == 4

    assert records[0].ts == datetime(2021, 11, 11, 12, 34, 56, tzinfo=timezone.utc)
    assert records[0].message == "Strip the headers, trace the source!"
    assert records[0].source == target_logfile_name
    assert records[0].username == user_details.user.name
    assert records[0].user_id == user_details.user.sid
    assert records[0].user_home == user_details.user.home


def test_teamviewer_special_date_parsing(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    teamviewer_logfile = absolute_path("_data/plugins/apps/remoteaccess/teamviewer/TestTeamviewer.log")
    user_details = target_win_users.user_details.find(username="John")
    target_logfile_name = f"{user_details.home_path}/appdata/roaming/teamviewer/teamviewer_TEST_logfile.log"

    _, _, map_path = target_logfile_name.partition("C:/")
    fs_win.map_file(map_path, teamviewer_logfile)

    tvp = TeamViewerPlugin(target_win_users)

    records = list(tvp.logs())
    assert len(records) == 4

    assert records[1].ts == datetime(2021, 11, 11, 12, 35, 55, 465000, tzinfo=timezone.utc)
    assert records[1].message == "Should be year 2021"

    assert records[2].ts == datetime(2021, 11, 11, 12, 36, 11, 111000, tzinfo=timezone.utc)
    assert records[2].message == "Should discard the milliseconds properly"

    assert records[3].ts == datetime(2021, 11, 11, 12, 37, 0, 0, tzinfo=timezone.utc)
    assert records[3].message == "Should be year 2021"


def test_teamviewer_timezone(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we correctly set the timezone in teamviewer logs."""

    log = """
    Start:          2024/12/31 01:02:03.123 (UTC+2:00)
    2024/12/31 01:02:03.200  1234  5678 G1   LanguageControl: device language is 'enUS'
    2024/12/31 01:02:03.300  1234  5678 G1   Example message 1
    2024/12/31 01:02:03.400  1234  5678 G1   Example message 2
    2024/12/31 01:02:03.500  1234  5678 G1   Example message 3
    2024/12/31 01:02:03.600  1234  5678 G1   Example message 4
    2024/12/31 01:02:03.700  1234  5678 G1!! Example message 5
    2024/12/31 01:02:03.800  1234  5678 G1   TeamViewer is going offline!
    2024/12/31 01:02:03.900  1234  5678 G1   NetworkControl shutdown done
    """
    fs_win.map_file_fh(
        "Users/John/AppData/Roaming/TeamViewer/TeamViewer1337_Logfile.log", BytesIO(dedent(log).encode())
    )

    target_win_users.add_plugin(TeamViewerPlugin)

    records = sorted(target_win_users.teamviewer.logs(), key=lambda r: r.ts)

    assert len(records) == 8

    # 01:02:03 with UTC+0200 becomes 23:02:03 UTC
    assert records[0].ts == datetime(2024, 12, 30, 23, 2, 3, 200000, tzinfo=timezone.utc)
    assert records[0].message == "1234  5678 G1   LanguageControl: device language is 'enUS'"
    assert records[0].source == "C:\\Users\\John\\AppData\\Roaming\\TeamViewer\\TeamViewer1337_Logfile.log"
    assert records[0].username == "John"
