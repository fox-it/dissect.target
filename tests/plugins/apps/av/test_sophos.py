from flow.record.fieldtypes import datetime as dt

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.av.sophos import (
    HitmanAlertRecord,
    SophosLogRecord,
    SophosPlugin,
)
from dissect.target.target import Target
from tests._utils import absolute_path


def test_sophos_hitman_plugin_log(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/apps/av/sophos/excalibur.db")
    fs_win.map_file("ProgramData/HitmanPro.Alert/excalibur.db", log_file)
    target_win.add_plugin(SophosPlugin)
    logs = list(target_win.sophos.hitmanlogs())
    assert len(logs) == 1
    log = logs[0]
    assert isinstance(log, type(HitmanAlertRecord()))
    assert log.ts == dt("2023-06-14T15:15:53.379862Z")
    assert log.alert == "ILoveYou"
    assert log.description == "Love Letter Virus"
    assert log.details.find("LOVE-LETTER-FOR-YOU.TXT.vbs") > -1


def test_sophos_home_plugin_log(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/apps/av/sophos/Clean.log")
    fs_win.map_file("ProgramData/Sophos/Clean/Logs/Clean.log", log_file)
    target_win.add_plugin(SophosPlugin)
    logs = list(target_win.sophos.sophoshomelogs())
    assert len(logs) == 1
    log = logs[0]
    assert log.ts == dt("2023-06-14T10:46:56.235000Z")
    assert isinstance(log, type(SophosLogRecord()))
    assert log.description == "EICAR-AV-Test"
    assert str(log.path) == "C:\\eicar_com.zip"
