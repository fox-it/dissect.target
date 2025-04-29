from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.av.symantec import (
    SEPFirewallRecord,
    SEPLogRecord,
    SymantecPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_symantec_firewall(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/apps/av/symantec/tralog.log")
    fs_win.map_file("ProgramData/Symantec/Symantec Endpoint Protection/Today/Data/Logs/tralog.log", log_file)
    target_win.add_plugin(SymantecPlugin)
    records = list(target_win.symantec.firewall())
    assert len(records) == 3
    assert isinstance(records[0], type(SEPFirewallRecord()))
    assert records[0].ts == dt("2023-08-18T13:44:28.219290Z")
    assert str(records[0].local_ip) == "10.0.2.15"
    assert str(records[0].remote_ip) == "10.0.2.2"
    assert bool(records[0].outbound) is False
    assert records[0].local_port == 25
    assert records[0].remote_port == 49510
    assert records[0].user == "who"
    assert records[0].repetition == 4
    assert bool(records[0].blocked) is True
    assert records[0].severity == "Info"
    assert records[0].rule_id == 0
    assert records[0].remote_host == ""
    assert records[0].rule_name == "Block all IP traffic"
    assert records[0].application == Path()
    assert records[0].line_no == 2


def test_symantec_log(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_file = absolute_path("_data/plugins/apps/av/symantec/cve.log")
    fs_win.map_file("ProgramData/Symantec/Symantec Endpoint Protection/Today/Data/Logs/av/cve.log", log_file)
    target_win.add_plugin(SymantecPlugin)
    records = list(target_win.symantec.logs())
    assert len(records) == 1
    assert isinstance(records[0], type(SEPLogRecord()))
    assert records[0].ts == dt("2023-08-18T15:18:46Z")
    assert records[0].virus == "EICAR Test String"
    assert records[0].source_file == Path("C:\\eicar.com")
    assert records[0].action_taken == "Pending Analysis"
    assert records[0].virus_type == "Test"
    assert records[0].scan_id == 1692364523
    assert records[0].quarantine_id == 0
    assert records[0].virus_id == 11101
    assert records[0].depth == 0
    assert bool(records[0].still_infected) is False
    assert bool(records[0].quarantined) is False
    assert bool(records[0].compressed) is False
    assert bool(records[0].cleanable) is False
    assert bool(records[0].deletable) is False
    assert records[0].confidence == 0
    assert records[0].prevalence == 0
    assert records[0].risk == 0
    assert records[0].download_url == ""
    assert records[0].line_no == 1
