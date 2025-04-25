from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.av.sophos import (
    HitmanAlertRecord,
    SophosLogRecord,
    SophosPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


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


def test_sophos_home_plugin_log_3_9_4_1(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/apps/av/sophos/Clean-3.9.4.1.log")
    fs_win.map_file("ProgramData/Sophos/Clean/Logs/Clean.log", log_file)
    target_win.add_plugin(SophosPlugin)
    logs = list(target_win.sophos.sophoshomelogs())
    assert len(logs) == 1
    log = logs[0]
    assert log.ts == dt("2023-06-14T10:46:56.235Z")
    assert isinstance(log, type(SophosLogRecord()))
    assert log.description == "EICAR-AV-Test"
    assert str(log.path) == "C:\\eicar_com.zip"


def test_sophos_home_plugin_log_3_10_3(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/apps/av/sophos/Clean-3.10.3.log")
    fs_win.map_file("ProgramData/Sophos/Clean/Logs/Clean.log", log_file)
    target_win.add_plugin(SophosPlugin)
    logs = list(target_win.sophos.sophoshomelogs())
    assert len(logs) == 1
    log = logs[0]
    assert log.ts == dt("2023-06-14T10:46:56.235000Z")
    assert isinstance(log, type(SophosLogRecord()))
    assert log.description == "EICAR-AV-Test"
    assert str(log.path) == "C:\\eicar_com.zip"
