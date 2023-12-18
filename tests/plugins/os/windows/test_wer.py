import datetime

from dissect.target.plugins.os.windows.wer import WindowsErrorReportingPlugin
from tests._utils import absolute_path


def test_wer_plugin(target_win, fs_win):
    wer_dir = absolute_path("_data/plugins/os/windows/wer")
    fs_win.map_dir("ProgramData/Microsoft/Windows/WER/ReportQueue/test", wer_dir)
    target_win.add_plugin(WindowsErrorReportingPlugin)
    tests = ["os_version_information_lcid", "response_type", "sig", "dynamic_sig", "dynamic_signatures_parameter1"]

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
