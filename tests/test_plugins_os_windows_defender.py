import os
from configparser import ConfigParser
from datetime import datetime
from io import BytesIO
from pathlib import Path

from dissect.ntfs.secure import ACL, SecurityDescriptor
from dissect.target.plugins.os.windows import defender

from ._utils import absolute_path


def test_defender_evtx_logs(target_win, fs_win, tmpdir_name):

    # map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmpdir_name)

    log_file = absolute_path("data/defender-operational.evtx")
    fs_win.map_file("windows/system32/winevt/logs/Microsoft-Windows-Windows Defender%4Operational.evtx", log_file)

    target_win.add_plugin(defender.MicrosoftDefenderPlugin)

    records = list(target_win.defender.evtx())

    assert len(records) == 9

    # verify that all records have unique EventIDs
    assert len(list(r.EventID for r in records)) == 9
    assert {r.Provider_Name for r in records} == {"Microsoft-Windows-Windows Defender"}
    assert {r.Channel for r in records} == {"Microsoft-Windows-Windows Defender/Operational"}
    # Both informational records (no threat name) and detections are present
    assert {r.Threat_Name for r in records} == {None, "TrojanDropper:PowerShell/PowerSploit.S!MSR"}


def test_defender_quarantine_entries(target_win, fs_win, tmpdir_name):

    quarantine_dir = absolute_path("data/defender-quarantine")

    fs_win.map_dir("programdata/microsoft/windows defender/quarantine", quarantine_dir)

    target_win.add_plugin(defender.MicrosoftDefenderPlugin)

    records = list(target_win.defender.quarantine())

    assert len(records) == 1

    # Test whether the quarantining of a Cobalt Strike beacon is    properly parsed.
    mimikatz_record = records[0]
    detection_date = datetime.strptime("2022-12-02", "%Y-%m-%d").date()

    assert mimikatz_record.detection_type == "file"
    assert mimikatz_record.detection_name == "HackTool:Win64/Mikatz!dha"
    assert mimikatz_record.detection_path == "C:\\Users\\user\\Downloads\\mimikatz\\mimilib.dll"

    assert mimikatz_record.ts.date() == detection_date
    assert mimikatz_record.creation_time.date() == detection_date
    assert mimikatz_record.last_write_time.date() == detection_date
    assert mimikatz_record.last_accessed_time.date() == detection_date


def test_defender_quarantine_recovery(target_win, fs_win, tmpdir_name):
    # Map the quarantine folder from our test data
    quarantine_dir = absolute_path("data/defender-quarantine")
    fs_win.map_dir("programdata/microsoft/windows defender/quarantine", quarantine_dir)

    # Create a directory to recover to
    recovery_dst = Path(tmpdir_name).joinpath("recovery")
    os.mkdir(recovery_dst)

    # Recover
    target_win.add_plugin(defender.MicrosoftDefenderPlugin)
    target_win.defender.recover(output_dir=recovery_dst)

    # Set up variables to indicate what we expect to find
    payload_filename = "A6C8322B8A19AEED96EFBD045206966DA4C9619D"
    security_descriptor_filename = "A6C8322B8A19AEED96EFBD045206966DA4C9619D.security_descriptor"
    zone_identifier_filename = "A6C8322B8A19AEED96EFBD045206966DA4C9619D.ZoneIdentifierDATA"
    expected_zone_identifier = {
        "ZoneTransfer": {"zoneid": "3", "referrerurl": "C:\\Users\\user\\Downloads\\mimikatz_trunk.zip"}
    }
    expected_owner = "S-1-5-21-2614236324-1336345114-3023566343-1000"
    expected_group = "S-1-5-21-2614236324-1336345114-3023566343-513"

    expected_files = [payload_filename, security_descriptor_filename, zone_identifier_filename]
    expected_files.sort()

    directory_content = os.listdir(recovery_dst)
    directory_content.sort()
    assert expected_files == directory_content

    # Verify that the payloads are both properly restored by checking for the MZ header
    with open(recovery_dst.joinpath(payload_filename), "rb") as payload_file:
        header = payload_file.read(2)
        assert header == b"MZ"

    # Verify that the security descriptors are valid security descriptors
    with open(recovery_dst.joinpath(security_descriptor_filename), "rb") as descriptor_file:
        descriptor_buf = descriptor_file.read()
        descriptor = SecurityDescriptor(BytesIO(descriptor_buf))

        assert isinstance(descriptor.dacl, ACL)
        assert isinstance(descriptor.sacl, ACL)

        assert descriptor.owner == expected_owner
        assert descriptor.group == expected_group

    # Verify valid zone identifier for mimikatz file
    # First parse the recovered file as an INI
    zone_identifier = ConfigParser()
    zone_identifier.read(recovery_dst.joinpath(zone_identifier_filename))

    # Verify that sections are correct
    assert zone_identifier.sections() == list(expected_zone_identifier.keys())
    for section in expected_zone_identifier.keys():
        for option, value in expected_zone_identifier[section].items():
            # Verify that option exists for this section
            assert option in zone_identifier.options(section)

            # Verify that option has the expected value
            assert zone_identifier.get(section, option) == value
