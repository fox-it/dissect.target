from __future__ import annotations

import datetime
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.wer import WindowsErrorReportingPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_wer_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    wer_dir = absolute_path("_data/plugins/os/windows/wer")
    fs_win.map_dir("ProgramData/Microsoft/Windows/WER/ReportQueue/test", wer_dir)
    target_win.add_plugin(WindowsErrorReportingPlugin)
    tests = [
        "os_version_information_lcid",
        "response_type",
        "sig",
        "dynamic_sig",
        "dynamic_signatures_parameter1",
        "ui_x5b_1_x5d",
        "sp_xc3a9_cial_charact_xc3a9_r",
        "xd0bd_xd0b5_xd0b2_xd0b8_xd0b4_xd0b8_xd0bc_xd18b_xd0b9",
        "x5f_start_with_an_",
        "x33__start_with_a_3",
    ]

    records = list(target_win.wer())
    assert len(records) == 2

    wer_record_map = {r.wer_file_path.name: r for r in records}
    assert "wer_test.wer" in wer_record_map
    assert "wer_test_no_bom.wer" in wer_record_map

    record = wer_record_map["wer_test.wer"]
    for test in tests:
        record_field = getattr(record, test, None)
        assert record_field == f"test_{test}"

    assert record.ts == datetime.datetime(2022, 10, 4, 11, 0, 0, 0, tzinfo=datetime.timezone.utc)

    record = wer_record_map["wer_test_no_bom.wer"]
    assert record.ts == datetime.datetime(2021, 11, 22, 15, 39, 49, 20733, tzinfo=datetime.timezone.utc)
    assert record.os_version == "6.1.7601.2.1.0.256.48"
    assert record.app_name == "Microsoft Malware Protection Command Line Utility"


def test_wer_plugin_key_in_report_and_metadata(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """A key that is in both the report and its metadata is a single field, with the value of the report."""
    report_dir = "ProgramData/Microsoft/Windows/WER/ReportQueue/test"
    fs_win.map_file_fh(
        f"{report_dir}/report.wer",
        BytesIO("EventType=test_event_type\r\nOSVersionInformationLCID=from_report\r\n".encode("utf-16")),
    )
    fs_win.map_file_fh(
        f"{report_dir}/report.tmp.WERInternalMetadata.xml",
        BytesIO(
            (
                '<?xml version="1.0" encoding="UTF-16"?>\n'
                "<WERReportMetadata><OSVersionInformation><LCID>from_metadata</LCID></OSVersionInformation>"
                "</WERReportMetadata>"
            ).encode("utf-16")
        ),
    )
    target_win.add_plugin(WindowsErrorReportingPlugin)

    records = list(target_win.wer())
    assert len(records) == 1

    record = records[0]
    field_names = [name for _, name in record._desc.get_field_tuples()]
    assert field_names.count("os_version_information_lcid") == 1
    assert record.os_version_information_lcid == "from_report"
    assert record.event_type == "test_event_type"
