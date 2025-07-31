from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.search import SearchIndexPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_search_esedb(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test Windows Search EseDB parsing.

    Resources:
        - https://github.com/strozfriedberg/sidr/tree/main/tests/testdata
    """

    fs_win.map_file(
        "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
        str(absolute_path("_data/plugins/os/windows/search/Windows.edb")),
    )

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.search())
    len_records = len(records)
    assert len_records == 1183 - 2  # Database contains two empty records.

    # SearchIndexActivityRecord
    assert records[-1].ts_start == datetime(2023, 2, 16, 17, 30, 35, tzinfo=timezone.utc)
    assert records[-1].ts_end == datetime(2023, 2, 16, 17, 30, 37, tzinfo=timezone.utc)
    assert records[-1].duration == 20_000_000  # equals two seconds
    assert records[-1].application_name == "PowerPoint 2016"
    assert (
        records[-1].application_id == "{6D809377-6AF0-444B-8957-A3773F02200E}\\Microsoft Office\\Office16\\POWERPNT.EXE"
    )
    assert (
        records[-1].activity_id == "ECB32AF3-1440-4086-94E3-5311F97F89C4\\{ThisPCDesktopFolder}\\This is test PPT.pptx"
    )
    assert records[-1].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"

    # SearchIndexRecord (file)
    assert records[1175].ts == datetime(2023, 2, 16, 14, 36, 23, 877518, tzinfo=timezone.utc)
    assert records[1175].ts_mtime == datetime(2023, 2, 16, 14, 36, 14, 922361, tzinfo=timezone.utc)
    assert records[1175].ts_btime == datetime(2023, 2, 16, 14, 35, 23, 656454, tzinfo=timezone.utc)
    assert records[1175].ts_atime == datetime(2023, 2, 16, 14, 36, 22, 893101, tzinfo=timezone.utc)
    assert records[1175].path == "C:\\Users\\testuser\\Desktop\\StrozFriedberg-Example.txt"
    assert records[1175].type == "text/plain"
    assert records[1175].size == 50
    assert records[1175].data == "Example File from Stroz Friedberg.\r\nHappy Testing!"
    assert records[1175].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"

    # SearchIndexRecord (file)
    assert records[1120].ts == datetime(2023, 2, 14, 15, 14, 40, 984222, tzinfo=timezone.utc)
    assert records[1120].ts_mtime == datetime(2023, 2, 14, 15, 3, 59, 352678, tzinfo=timezone.utc)
    assert records[1120].ts_btime == datetime(2023, 2, 14, 13, 56, 55, 827263, tzinfo=timezone.utc)
    assert records[1120].ts_atime == datetime(2023, 2, 14, 15, 12, 4, 400179, tzinfo=timezone.utc)
    assert records[1120].path == "C:\\Users\\testuser\\Desktop\\Content-Check\\Malicious.js"
    assert records[1120].type == "JavaScript File"  # no mimetype available?
    assert records[1120].size == 511
    assert (
        records[1120].data
        == "Line 1\r\nLine 2\r\nLine 3\r\nLine 4\r\nLine 5\r\nLine 6\r\nLine 7\r\nLine 8\r\nLine 9\r\nLine 10\r\nLine 11\r\nLine 12\r\nLine 13\r\nLine 14\r\nLine 15\r\nLine 16\r\nLine 17\r\nLine 18\r\nLine 19\r\nLine 20\r\nLine 21\r\nLine 22\r\nLine 23\r\nLine 24\r\nLine 25\r\nLine 26\r\nLine 27\r\nLine 28\r\nLine 29\r\nLine 30\r\nLine 31\r\nLine 32\r\nLine 33\r\nLine 34\r\nLine 35\r\nLine 36\r\nLine 37\r\nLine 38\r\nLine 39\r\nLine 40\r\nLine 41\r\nLine 42\r\nLine 43\r\nLine 44\r\nLine 45\r\nLine 46\r\nLine 47\r\nLine 48\r\nLine 49\r\nLine 50\r\nLine 51\r\nLine 52\r\nLine 53\r\nLine 54\r\nLine 55\r\nLine 56\r\nLine 57\r\nLine \r\n"  # noqa: E501
    )
    assert records[1120].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"

    # SearchIndexRecord (folder)
    assert records[1116].ts == datetime(2023, 2, 14, 13, 59, 31, 356632, tzinfo=timezone.utc)
    assert records[1116].ts_mtime == datetime(2023, 2, 14, 13, 57, 29, 517132, tzinfo=timezone.utc)
    assert records[1116].ts_btime == datetime(2023, 2, 14, 13, 57, 8, 689777, tzinfo=timezone.utc)
    assert records[1116].ts_atime == datetime(2023, 2, 14, 13, 59, 31, 340546, tzinfo=timezone.utc)
    assert records[1116].path == "C:\\Users\\testuser\\Desktop\\Content-Check"
    assert records[1116].type == "File folder"  # no mimetype available?
    assert not records[1116].size
    assert not records[1116].data
    assert records[1116].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"

    # BrowserHistoryRecord (iehistory)
    assert records[995].ts == datetime(2023, 2, 13, 14, 17, 22, 448000, tzinfo=timezone.utc)
    assert records[995].browser == "iehistory"
    assert (
        records[995].url
        == "https://support.microsoft.com/en-us/microsoft-edge/this-website-doesn-t-work-in-internet-explorer-8f5fc675-cd47-414c-9535-12821ddfc554?ui=en-us&rs=en-us&ad=us"
    )
    assert records[995].title == "This website doesn't work in Internet Explorer - Microsoft Support"
    assert records[995].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"
    # assert records[995].user_id == ""


def test_windows_search_sqlite(target_win: Target, fs_win: VirtualFilesystem) -> None:
    """Test Windows 11 Search SQLite3 parsing.

    Resources:
        - https://github.com/strozfriedberg/sidr/tree/main/tests/testdata
    """

    fs_win.map_file(
        "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db",
        str(absolute_path("_data/plugins/os/windows/search/Windows.db")),
    )

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.search())
    len_records = len(records)
    assert len_records == 839 - 1  # Database contains one empty record.

    # SearchIndexActivityRecord
    assert records[698].ts_start == datetime(2023, 1, 30, 22, 14, 18, tzinfo=timezone.utc)
    assert records[698].ts_end == datetime(2023, 1, 30, 22, 14, 20, tzinfo=timezone.utc)
    assert records[698].duration == 20_000_000
    assert records[698].application_name == "notepad++.exe"
    assert records[698].application_id == "{6D809377-6AF0-444B-8957-A3773F02200E}\\Notepad++\\notepad++.exe"
    assert records[698].activity_id == "ECB32AF3-1440-4086-94E3-5311F97F89C4\\{Public}\\Threat\\becon.xml"
    assert records[698].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db"

    # SearchIndexRecord (file)
    assert records[837].ts == datetime(2023, 1, 31, 2, 45, 2, 871614, tzinfo=timezone.utc)
    assert records[837].ts_mtime == datetime(2023, 1, 31, 2, 45, 2, 56444, tzinfo=timezone.utc)
    assert records[837].ts_btime == datetime(2023, 1, 31, 2, 26, 28, 898306, tzinfo=timezone.utc)
    assert records[837].ts_atime == datetime(2023, 1, 31, 2, 45, 2, 56444, tzinfo=timezone.utc)
    assert records[837].path == "C:\\Users\\Public\\malware\\New-beacon.xml"
    assert records[837].type == "text/xml"
    assert int(records[837].size) == 174
    assert not records[837].data
    assert records[837].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db"

    # BrowserHistoryRecord (edge)
    assert records[711].ts == datetime(2023, 1, 31, 0, 9, 47, 972897, tzinfo=timezone.utc)
    assert records[711].browser == "winrt"
    assert (
        records[711].url
        == "https://www.bing.com/search?q=install+chrome&cvid=2ce0f71581824fda82398075bb250924&aqs=edge.0.0j69i57j0l7.2774j0j7&FORM=ANNTA0&PC=U531"
    )
    assert records[711].source == "\\sysvol\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db"
    # assert records[711].user_sid == ""
