import os
import platform
from datetime import datetime
from io import BytesIO
from pathlib import Path

import pytest
from dissect.ntfs.secure import ACL, SecurityDescriptor

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows import defender
from dissect.target.target import Target

from ._utils import absolute_path


def test_defender_evtx_logs(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    # map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmp_path)

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


def test_defender_quarantine_entries(target_win: Target, fs_win: VirtualFilesystem) -> None:
    quarantine_dir = absolute_path("data/defender-quarantine")

    fs_win.map_dir("programdata/microsoft/windows defender/quarantine", quarantine_dir)

    target_win.add_plugin(defender.MicrosoftDefenderPlugin)

    records = list(target_win.defender.quarantine())

    assert len(records) == 1

    # Test whether the quarantining of a Mimikatz binary is properly parsed.
    mimikatz_record = records[0]
    detection_date = datetime.strptime("2022-12-02", "%Y-%m-%d").date()

    assert mimikatz_record.detection_type == "file"
    assert mimikatz_record.detection_name == "HackTool:Win64/Mikatz!dha"
    assert mimikatz_record.detection_path == "C:\\Users\\user\\Downloads\\mimikatz\\mimilib.dll"

    assert mimikatz_record.ts.date() == detection_date
    assert mimikatz_record.creation_time.date() == detection_date
    assert mimikatz_record.last_write_time.date() == detection_date
    assert mimikatz_record.last_accessed_time.date() == detection_date


@pytest.mark.skipif(
    platform.system() == "Windows", reason="Path error? OSError: [Errno 22] Invalid argument. Needs to be fixed."
)
def test_defender_quarantine_recovery(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    # Map the quarantine folder from our test data
    quarantine_dir = absolute_path("data/defender-quarantine")
    fs_win.map_dir("programdata/microsoft/windows defender/quarantine", quarantine_dir)

    # Create a directory to recover to
    recovery_dst = tmp_path.joinpath("recovery")
    recovery_dst.mkdir()

    # Recover
    target_win.add_plugin(defender.MicrosoftDefenderPlugin)
    target_win.defender.recover(output_dir=recovery_dst)

    # Set up variables to indicate what we expect to find
    payload_filename = "A6C8322B8A19AEED96EFBD045206966DA4C9619D"
    security_descriptor_filename = "A6C8322B8A19AEED96EFBD045206966DA4C9619D.security_descriptor"
    zone_identifier_filename = "A6C8322B8A19AEED96EFBD045206966DA4C9619D.ZoneIdentifierDATA"
    expected_zone_identifier_content = (
        b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\user\\Downloads\\mimikatz_trunk.zip\r\n"
    )
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
    assert recovery_dst.joinpath(zone_identifier_filename).read_bytes() == expected_zone_identifier_content


def test_defender_exclusions(target_win: Target, hive_hklm: VirtualHive) -> None:
    # https://learn.microsoft.com/en-us/exchange/antispam-and-antimalware/windows-antivirus-software?view=exchserver-2019
    exclusions_example = {
        "Extensions": [".config", ".log", ".cfg"],
        "Processes": ["UmService.exe", "UmWorkerProcess.exe"],
        "Paths": ["C:\\System32\\Cluster\\"],
        "IpAddresses": [],
        "TemporaryPaths": [],
    }
    # Recreate the 'Exclusions' registry key based on the example dict
    exclusions_key = VirtualKey(hive_hklm, "Software\\Microsoft\\Windows Defender\\Exclusions")
    for exclusion_type, exclusions in exclusions_example.items():
        exclusion_type_key = VirtualKey(hive_hklm, exclusions_key.path + f"\\{exclusion_type}")
        for exclusion in exclusions:
            exclusion_type_key.add_value(exclusion, 0)
        exclusions_key.add_subkey(exclusion_type, exclusion_type_key)

    hive_hklm.map_key(exclusions_key.path, exclusions_key)
    target_win.add_plugin(defender.MicrosoftDefenderPlugin)

    exclusion_records = list(target_win.defender.exclusions())

    # If an exclusion type does not have any exclusions, no records are returned for that type.
    ip_address_exclusions = [exclusion for exclusion in exclusion_records if exclusion.type == "IpAddresses"]
    temporary_path_exclusions = [exclusion for exclusion in exclusion_records if exclusion.type == "TemporaryPaths"]
    assert len(ip_address_exclusions) == 0
    assert len(temporary_path_exclusions) == 0

    extension_exclusions = [exclusion for exclusion in exclusion_records if exclusion.type == "Extensions"]
    assert len(extension_exclusions) == 3

    assert any(exclusion.value == ".config" for exclusion in extension_exclusions)
    assert any(exclusion.value == ".log" for exclusion in extension_exclusions)
    assert any(exclusion.value == ".cfg" for exclusion in extension_exclusions)

    process_exclusions = [exclusion for exclusion in exclusion_records if exclusion.type == "Processes"]
    assert len(process_exclusions) == 2
    assert any(exclusion.value == "UmService.exe" for exclusion in process_exclusions)
    assert any(exclusion.value == "UmWorkerProcess.exe" for exclusion in process_exclusions)

    path_exclusions = [exclusion for exclusion in exclusion_records if exclusion.type == "Paths"]
    assert any(exclusion.value == "C:\\System32\\Cluster\\" for exclusion in path_exclusions)
    assert len(path_exclusions) == 1

    assert len(exclusion_records) == 6
