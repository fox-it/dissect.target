from __future__ import annotations

import io
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

import pytest
from dissect.ntfs.secure import ACL, SecurityDescriptor
from flow.record.fieldtypes import command
from flow.record.fieldtypes import datetime as dt

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.defender._plugin import MicrosoftDefenderPlugin
from dissect.target.plugins.os.windows.defender.quarantine import (
    STREAM_ID,
    c_defender,
    rc4_crypt,
    recover_quarantined_file_streams,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from flow.record import Record

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_defender_evtx_logs(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    # map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmp_path)

    log_file = absolute_path("_data/plugins/os/windows/defender/operational.evtx")
    fs_win.map_file("windows/system32/winevt/logs/Microsoft-Windows-Windows Defender%4Operational.evtx", log_file)

    target_win.add_plugin(MicrosoftDefenderPlugin)

    records = list(target_win.defender.evtx())

    assert len(records) == 9

    # verify that all records have unique EventIDs
    assert all(r.ts is not None for r in records)
    assert len([r.EventID for r in records]) == 9
    assert {r.Provider_Name for r in records} == {"Microsoft-Windows-Windows Defender"}
    assert {r.Channel for r in records} == {"Microsoft-Windows-Windows Defender/Operational"}
    # Both informational records (no threat name) and detections are present
    assert {r.Threat_Name for r in records} == {None, "TrojanDropper:PowerShell/PowerSploit.S!MSR"}


def test_defender_quarantine_entries(target_win: Target, fs_win: VirtualFilesystem) -> None:
    quarantine_dir = absolute_path("_data/plugins/os/windows/defender/quarantine")

    fs_win.map_dir("programdata/microsoft/windows defender/quarantine", quarantine_dir)

    target_win.add_plugin(MicrosoftDefenderPlugin)

    records = list(target_win.defender.quarantine())

    assert len(records) == 1

    # Test whether the quarantining of a Mimikatz binary is properly parsed.
    mimikatz_record = records[0]
    detection_date = datetime.strptime("2022-12-02", "%Y-%m-%d").replace(tzinfo=timezone.utc).date()

    assert mimikatz_record.detection_type == "file"
    assert mimikatz_record.detection_name == "HackTool:Win64/Mikatz!dha"
    assert mimikatz_record.detection_path == "C:\\Users\\user\\Downloads\\mimikatz\\mimilib.dll"

    assert mimikatz_record.ts.date() == detection_date
    assert mimikatz_record.creation_time.date() == detection_date
    assert mimikatz_record.last_write_time.date() == detection_date
    assert mimikatz_record.last_accessed_time.date() == detection_date


def test_defender_quarantine_recovery(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    # Map the quarantine folder from our test data
    quarantine_dir = absolute_path("_data/plugins/os/windows/defender/quarantine")
    fs_win.map_dir("programdata/microsoft/windows defender/quarantine", quarantine_dir)

    # Create a directory to recover to
    recovery_dst = tmp_path.joinpath("recovery")
    recovery_dst.mkdir()

    # Recover
    target_win.add_plugin(MicrosoftDefenderPlugin)
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

    directory_content = [p.name for p in recovery_dst.iterdir()]
    directory_content.sort()
    assert expected_files == directory_content
    # Replaced the mimikatz payload with `DUMMY_PAYLOAD` to avoid defender collecting it
    assert recovery_dst.joinpath(payload_filename).read_bytes() == b"DUMMY_PAYLOAD"

    # Verify that the security descriptors are valid security descriptors
    descriptor_buf = recovery_dst.joinpath(security_descriptor_filename).read_bytes()
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
    target_win.add_plugin(MicrosoftDefenderPlugin)

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


def _mplog_records(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path, log_filename: str) -> list[Record]:
    # map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmp_path)

    log_file = absolute_path(f"_data/plugins/os/windows/defender/mplog/{log_filename}.log")
    fs_win.map_file("ProgramData/Microsoft/Windows Defender/Support/MPLog-20240101-094808.log", log_file)

    target_win.add_plugin(MicrosoftDefenderPlugin)
    return list(target_win.defender.mplog())


def test_defender_mplogs_rtp(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    record = _mplog_records(target_win, fs_win, tmp_path, "rtp").pop()
    assert record.source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert record.ts == dt("2021-05-04 09:54:06+00:00")
    assert record.last_perf == dt("2021-05-04 09:54:06+00:00")
    assert record.first_rtp_scan == dt("2021-05-04 09:54:06+00:00")
    assert record.plugin_states == "AV:2  AS:2  RTP:2  OA:2  BM:2"
    assert record.process_exclusions == ["C:\\ReportingServicesService.exe", "C:\\ReportingServicesService.exe"]
    assert sorted(record.path_exclusions) == sorted(
        ["C:\\Windows\\Security\\Database\\*.chk", "%windidr%\\SoftwareDistribution\\Datastore\\*.*"]
    )
    assert sorted(record.ext_exclusions) == sorted([".DBF", ".NDF", ".RAR", ".XML", ".IDX", ".BAK", ".PDF", ".BKP"])


def test_defender_mplogs_resource_scan(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    record = _mplog_records(target_win, fs_win, tmp_path, "resourcescan").pop()
    assert record.source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert record.ts == dt("2023-01-01 00:00:00+00:00")
    assert record.scan_id == "{1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D}"
    assert record.scan_source == 4
    assert record.end_time == dt("2023-01-01 00:01:00+00:00")
    assert record.resource_schema == "webfile"
    assert (
        record.resource_path
        == "C:\\Users\\user\\Downloads\\file.rar|https:/example.com/download?id=12345|browser_broker.exe"
    )
    assert record.result_count == 2
    assert sorted(record.threats) == sorted(["Worm:VBS/Jenxcus.DN", "HackTool:MSIL/Mimikatz!MSR"])
    assert sorted(record.resources) == sorted(
        [
            "C:\\ProgramData\\App\\Scans\\FilesStash\\9F8E7D6C-5A4B-3C2D-1E0F-A1B2C3D4E5F6_1d23456789abcdef|C:\\Users\\user\\Downloads\\file.rar",
            "C:\\Users\\user\\Downloads\\file.rar->file.WsF",
            "C:\\ProgramData\\App\\Scans\\FilesStash\\9F8E7D6C-5A4B-3C2D-1E0F-A1B2C3D4E5F6_1d23456789abcdef",
            "C:\\Users\\user\\Downloads\\file.rar|https:/example.com/download?id=67890|browser_broker.exe",
            "C:\\ProgramData\\App\\Scans\\FilesStash\\9F8E7D6C-5A4B-3C2D-1E0F-A1B2C3D4E5F6_1d23456789abcdef|https:/example.com/download?id=12345|browser_broker.exe",
            "C:\\Users\\user\\Downloads\\file.rar",
            "C:\\Users\\user\\Videos\\binary.exe",
        ]
    )


def test_defender_mplogs_threat_actions(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    record = _mplog_records(target_win, fs_win, tmp_path, "threatactions").pop()
    assert record.source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert record.ts == dt("2017-12-25 16:30:45+00:00")
    assert record.threats == ["Worm:Win32/RandomName.X"]
    for item in [
        "\\\\?\\C:\\OS\\Tasks\\RandomTask1.job",
        "\\\\?\\C:\\OS\\system32\\randomfile.tmp->(UPX)",
        "\\\\?\\C:\\OS\\Tasks\\RandomTask1.job",
        "\\\\?\\C:\\OS\\system32\\randomfile.tmp",
        "C:\\OS\\Tasks\\RandomTask1.job",
        "\\\\?\\C:\\OS\\Tasks\\RandomTask1.job",
        "C:\\OS\\system32\\randomfile.tmp->(UPX)",
        "\\\\?\\C:\\OS\\system32\\randomfile.tmp->(UPX)",
        "\\\\?\\C:\\OS\\Tasks\\RandomTask1.job",
    ]:
        assert item in list(record.resources)

    assert record.actions == ["quarantine"]


def test_defender_mplogs_bmtelemetry(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    record = _mplog_records(target_win, fs_win, tmp_path, "bmtelemetry").pop()
    assert record.source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert record.ts == dt("2024-07-15 11:45:22+00:00")
    assert record.guid == "{1D3E4F07-89AB-45C2-923D-E5F6789A1B2C}"
    assert record.signature_id == 123456789012345
    assert record.sigsha == "abcd1234ef567890abcd1234ef567890abcd1234"
    assert record.threat_level == 0
    assert record.process_id == 8453
    assert record.process_creation_time == 153846236598765432
    assert record.image_path == "C:\\OS\\System32\\servicehost.exe"
    assert record.taint_info == "Friendly: Y; Reason: ; Modules: ; Parents: "
    assert record.operations == "None"


def test_defender_mplogs_lines(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    records = _mplog_records(target_win, fs_win, tmp_path, "lines")
    assert len(records) == 10

    # Process Image
    assert records[0].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[0].ts == dt("2024-07-13 14:42:19.659000+00:00")
    assert records[0].process_image_name == "randomapp.exe"
    assert records[0].pid == 5832
    assert records[0].total_time == 1398
    assert records[0].count == 22
    assert records[0].max_time == 398
    assert records[0].max_time_file == "\\Device\\HarddiskVolume2\\Users\\user123\\AppData\\Local\\Temp\\TEMP001.tmp"
    assert records[0].estimated_impact == 4

    # Lowfi
    assert records[1].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[1].ts == dt("2023-01-20 08:45:40.321000+00:00")
    assert records[1].lowfi == command(
        "C:\\OS\\System32\\cfg.exe(reg add HKLM\\SYSTEM\\OtherControlSet\\Control\\SecurityOptions\\SecurityModule /v RandomFlag /t REG_DWORD /d 0 /f)",  # noqa: E501
    )

    # Detection Add
    assert records[2].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[2].ts == dt("2023-01-27 15:33:07.698000+00:00")
    assert (
        records[2].detection
        == "HackTool:MSIL/RndGen!MD5 file:C:\\Users\\user987\\Documents\\executable.exe PropBag [length: 0, data: (null)]"  # noqa: E501
    )

    # Threat
    assert records[3].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[3].ts == dt("2023-01-27 15:33:07.698000+00:00")
    assert records[3].threat == command("C:\\Users\\user987\\Documents\\executable.exe")

    # Detection event
    assert records[4].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[4].ts == dt("2023-01-27 15:33:07.698000+00:00")
    assert records[4].threat_type == "MSIL/RndGen!MD5"
    assert records[4].command == command("C:\\Users\\user987\\Documents\\executable.exe")

    # Exclusion
    assert records[5].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[5].ts == dt("2024-08-17 17:35:22.614000+00:00")
    assert records[5].full_path_with_drive_letter == "C:\\example.txt"
    assert records[5].full_path_with_device_path == "example.txt"

    # Mini-filter unsuccesful scan
    assert records[6].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert (
        records[6].path
        == "\\Device\\HarddiskVolume2\\Users\\userdefault\\AppData\\Local\\Packages\\MicrosoftBrowser.Default_cw5n8h2txyuma\\LocalState\\ANWebView\\Default\\Popular URLs."  # noqa: E501
    )
    assert records[6].ts == dt("2024-07-13 14:38:15.272000+00:00")
    assert records[6].process == "(unknown)"
    assert records[6].status == "0xc000004a"
    assert records[6].state == "0"
    assert records[6].scan_request == "#16891"
    assert records[6].file_id == "0x200000002c4b5"
    assert records[6].reason == "OnAccess"
    assert records[6].io_status_block_for_new_file == "0x3"
    assert records[6].desired_access == "0x0"
    assert records[6].file_attributes == "0x20"
    assert records[6].scan_attributes == "0x10"
    assert records[6].access_state_flags == "0x802"
    assert records[6].backing_file_info == "0x0, 0x0, 0x0:0\\0x0:0"

    # Mini-filter blocked file
    assert records[7].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[7].ts == dt("2024-07-13 14:38:15.272000+00:00")
    assert (
        records[7].blocked_file
        == "\\Device\\HarddiskVolume2\\Users\\userdefault\\AppData\\Local\\Packages\\MicrosoftBrowser.Default_cw5n8h2txyuma\\LocalState\\ANWebView\\Default\\Popular URLs."  # noqa: E501
    )
    assert records[7].process == "(unknown)"
    assert records[7].status == "0xc000004a"
    assert records[7].state == "0"
    assert records[7].scan_request == "#16891"
    assert records[7].file_id == "0x200000002c4b5"
    assert records[7].reason == "OnAccess"
    assert records[7].io_status_block_for_new_file == "0x3"
    assert records[7].desired_access == "0x0"
    assert records[7].file_attributes == "0x20"
    assert records[7].scan_attributes == "0x10"
    assert records[7].access_state_flags == "0x802"
    assert records[7].backing_file_info == "0x0, 0x0, 0x0:0\\0x0:0"

    # EMS
    assert records[8].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[8].ts == dt("2024-09-05 10:21:39.417000+00:00")
    assert records[8].process == "sysproc"
    assert records[8].pid == 2820
    assert records[8].sigseq == "0x1"
    assert records[8].send_memory_scan_report == 1
    assert records[8].source == 4

    # Original Filename
    assert records[9].source_log == "sysvol/programdata/microsoft/windows defender/support/MPLog-20240101-094808.log"
    assert records[9].ts == dt("2024-09-03 18:12:05.364000+00:00")
    assert records[9].original_file_name == "RandomData0123_static.dll"
    assert (
        records[9].full_path
        == "c:\\os\\winsxs\\x64_default-app-service_31bf3856ad364e35_10.0.29999.9999_none_fakef123456789a\\randomdata0123.dll"  # noqa: E501
    )

    assert records[9].hr == "0x1"


@pytest.mark.parametrize(
    ("stream_id", "extension"),
    [
        (
            STREAM_ID.EA_DATA,
            "ea_data",
        ),
        (
            STREAM_ID.SECURITY_DATA,
            "security_descriptor",
        ),
        (
            STREAM_ID.LINK,
            "link",
        ),
        (
            STREAM_ID.PROPERTY_DATA,
            "property_data",
        ),
        (
            STREAM_ID.OBJECT_ID,
            "object_id",
        ),
        (
            STREAM_ID.REPARSE_DATA,
            "reparse_data",
        ),
        (
            STREAM_ID.SPARSE_BLOCK,
            "sparse_block",
        ),
        (
            STREAM_ID.TXFS_DATA,
            "txfs_data",
        ),
        (
            STREAM_ID.GHOSTED_FILE_EXTENTS,
            "ghosted_file_extents",
        ),
    ],
)
def test_recover_quarantined_file_streams_valid_param(stream_id: int, extension: str) -> None:
    quarantine_buf = b"\x69" * 32
    quarantine_stream = rc4_crypt(
        c_defender.WIN32_STREAM_ID(
            stream_id, c_defender.STREAM_ATTRIBUTES.STREAM_NORMAL_ATTRIBUTE, len(quarantine_buf), 0
        ).dumps()
        + quarantine_buf
    )

    filename, filebuf = next(recover_quarantined_file_streams(io.BytesIO(quarantine_stream), "valid_stream"))

    assert filename.endswith(extension)
    assert filebuf == quarantine_buf


def test_recover_quarantined_file_streams_invalid() -> None:
    quarantine_buf = b"\x69" * 32
    valid_quarantine_stream = c_defender.WIN32_STREAM_ID(
        STREAM_ID.EA_DATA, c_defender.STREAM_ATTRIBUTES.STREAM_NORMAL_ATTRIBUTE, len(quarantine_buf), 0
    ).dumps()

    # Make stream ID invalid.
    invalid_quarantine_stream = b"\x69" + valid_quarantine_stream[1:]

    quarantine_stream = rc4_crypt(invalid_quarantine_stream + quarantine_buf)

    with pytest.raises(ValueError, match="Unexpected Stream ID "):
        next(recover_quarantined_file_streams(io.BytesIO(quarantine_stream), "invalid_stream"))


def test_recover_quarantined_file_streams(target_win: Target, fs_win: VirtualFilesystem, tmp_path: Path) -> None:
    quarantine_file = absolute_path(
        "_data/plugins/os/windows/defender/quarantine/ResourceData/A6/A6C8322B8A19AEED96EFBD045206966DA4C9619D"
    )

    with quarantine_file.open("rb") as fh:
        assert list(recover_quarantined_file_streams(fh, quarantine_file.name)) == [
            (
                "A6C8322B8A19AEED96EFBD045206966DA4C9619D.security_descriptor",
                b"\x01\x00\x14\x88\x14\x00\x00\x000\x00\x00\x00\xa4\x00\x00\x00L\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa4\x14\xd2\x9b\x1a\x02\xa7O\x07\xf67\xb4\xe8\x03\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa4\x14\xd2\x9b\x1a\x02\xa7O\x07\xf67\xb4\x01\x02\x00\x00\x02\x00X\x00\x03\x00\x00\x00\x00\x00\x14\x00\xff\x01\x1f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x00\x18\x00\xff\x01\x1f\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 \x02\x00\x00\x00\x00$\x00\xff\x01\x1f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xa4\x14\xd2\x9b\x1a\x02\xa7O\x07\xf67\xb4\xe8\x03\x00\x00\x02\x00L\x00\x01\x00\x00\x00\x12\x10D\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00(\x00\x00\x00I\x00M\x00A\x00G\x00E\x00L\x00O\x00A\x00D\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",  # noqa: E501
            ),
            ("A6C8322B8A19AEED96EFBD045206966DA4C9619D", b"DUMMY_PAYLOAD"),
            (
                "A6C8322B8A19AEED96EFBD045206966DA4C9619D.ZoneIdentifierDATA",
                b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\user\\Downloads\\mimikatz_trunk.zip\r\n",
            ),
        ]
