import datetime

from dissect.target.plugins.os.windows.wer import WindowsErrorReportingPlugin

from ._utils import absolute_path


def test_wer_plugin(target_win, fs_win):
    wer_dir = absolute_path("data/wer/")
    fs_win.map_dir("ProgramData/Microsoft/Windows/WER/ReportQueue/test", wer_dir)
    target_win.add_plugin(WindowsErrorReportingPlugin)
    tests = ["os_version_information_lcid", "response_type", "sig", "dynamic_sig", "dynamic_signatures_parameter1"]

    records = list(target_win.wer())
    assert len(records) == 1

    record = records[0]
    for test in tests:
        record_field = getattr(record, test, None)
        assert record_field == f"test_{test}"

    assert record.ts == datetime.datetime(2022, 10, 4, 11, 0, 0, 0, tzinfo=datetime.timezone.utc)
