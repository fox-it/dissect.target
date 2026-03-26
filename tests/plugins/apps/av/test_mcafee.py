from __future__ import annotations

import json
from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.av.mcafee import (
    McAfeeAtpRemediationRecord,
    McAfeeMscFirewallRecord,
    McAfeePlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_mcafee_plugin_log(target_win: Target, fs_win: VirtualFilesystem) -> None:
    log_dir = absolute_path("_data/plugins/apps/av/mcafee")
    fs_win.map_dir("ProgramData/McAfee/MSC/Logs", log_dir)

    target_win.add_plugin(McAfeePlugin)

    records = list(target_win.mcafee.msc())
    assert len(records) == 2
    for record in records:
        if isinstance(record, type(McAfeeMscFirewallRecord())):
            assert record.ip == "127.0.0.1"
            assert record.protocol == "TCP"
            assert record.port == 54996
            assert record.ts == dt("2023-03-07T10:32:34Z")
            assert record.fkey == "{C492A216-EFFC-4DAE-BE5E-2F5E064594C9}"
            assert (
                record.message
                == "The PC 127.0.0.1 tried to connect to TCP port 54996 on your PC without your permission."
            )
            assert record.keywords == "127.0.0.1,127.0.0.1,TCP port 54996"

        else:
            assert record.threat == "EICAR test file"
            assert record.ts == dt("2023-03-07T10:55:18Z")
            assert record.fkey == "{37E1F90E-471D-40D3-9FAA-37BE30C5B4AA}"
            assert (
                record.message
                == "Status Quarantined Scan type Custom  We found one or several threats on your PC. Threat name EICAR test file File C:\\Users\\admin\\Desktop\\eicar.com"  # noqa: E501
            )
            assert record.keywords == "Custom,EICAR test file,Quarantined"


def test_mcafee_plugin_atp(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    # Create a temporary directory and JSON file to simulate the target's disk
    atp_dir = tmp_path / "atp_data"
    atp_dir.mkdir()
    atp_file = atp_dir / "alert.json"
    
    valid_json = json.dumps({
        "Story_Graph": {"Key": "graph-12345"},
        "Remediation": {
            "ValidThreat": {
                "AlertID": "alert-999",
                "ThreatName": "EICAR-Test-File",
                "Severity": "Critical",
                "ProcessName": "cmd.exe",
                "FileName": "C:\\temp\\eicar.com",
                "Action": "Delete",
                "Status": "Success",
                "Timestamp": 1609459200000
            },
            "OperationalNoise": {
                "Action": "Update",
                "Status": "Running",
                "Details": "Background scan completed"
            }
        }
    })
    atp_file.write_text(valid_json, encoding="utf-8")
    
    # Map the temporary directory into the virtual filesystem
    fs_win.map_dir("ProgramData/McAfee/Endpoint Security/ATP", str(atp_dir))
    
    target_win.add_plugin(McAfeePlugin)
    
    # Execute the ATP parser
    records = list(target_win.mcafee.atp())
    
    # Assert noise was filtered out and only 1 record was generated
    assert len(records) == 1
    record = records[0]
    
    assert record.alert_id == "alert-999"
    assert record.threat == "EICAR-Test-File"
    assert record.severity == "Critical"
    assert record.process == "cmd.exe"
    assert record.target == "C:\\temp\\eicar.com"
    assert record.action == "Delete"
    assert record.status == "Success"
    assert record.story_graph_key == "graph-12345"
    assert record.ts == dt("2021-01-01T00:00:00Z")
    assert "EICAR" in record.raw
    assert record.source.name == "alert.json"


def test_mcafee_parse_atp_timestamp(target_win: Target) -> None:
    plugin = McAfeePlugin(target_win)
    
    # Standard Unix Epoch (seconds)
    assert plugin._parse_atp_timestamp(1609459200) == dt("2021-01-01T00:00:00Z")
    # Milliseconds
    assert plugin._parse_atp_timestamp(1609459200000) == dt("2021-01-01T00:00:00Z")
    # Microseconds
    assert plugin._parse_atp_timestamp(1609459200000000) == dt("2021-01-01T00:00:00Z")
    # String variants
    assert plugin._parse_atp_timestamp("1609459200000") == dt("2021-01-01T00:00:00Z")
    
    # Invalid data gracefully fails to None
    assert plugin._parse_atp_timestamp("invalid_string") is None
    assert plugin._parse_atp_timestamp(None) is None