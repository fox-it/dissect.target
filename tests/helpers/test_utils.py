from __future__ import annotations

import datetime
import io
import stat
import textwrap
from unittest.mock import mock_open, patch

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import fsutil, utils


def test_to_list_single_value() -> None:
    assert utils.to_list(1) == [1]
    assert utils.to_list("a") == ["a"]
    assert utils.to_list(None) == []


def test_to_list_list_value() -> None:
    assert utils.to_list([1, 2, 3]) == [1, 2, 3]
    assert utils.to_list(["a", "b", "c"]) == ["a", "b", "c"]
    assert utils.to_list([]) == []


def test_slugify() -> None:
    assert utils.slugify("foo/bar\\baz bla") == "foo_bar_baz_bla"


def test_filesystem_readinto() -> None:
    data = b"hello_world"
    mocked_file = mock_open(read_data=b"hello_world")

    buffer = bytearray([0] * 512)
    assert utils.readinto(buffer, mocked_file.return_value) == len(data)
    assert buffer[: len(data)] == data
    assert len(buffer) == 512


def test_helpers_fsutil_year_rollover_helper() -> None:
    vfs = VirtualFilesystem()

    content = """
    Dec 31 03:14:15 Line 1
    Jan  1 13:21:34 Line 2
    Dec 31 03:14:15 Line 3
    Jan  1 13:21:34 Line 4
    Dec 31 03:14:15 Line 5
    Jan  1 13:21:34 Line 6
    Jan  2 13:21:34 Line 7
    Feb  3 13:21:34 Line 8
    Dec 31 03:14:15 Line 9
    Jan  1 13:21:34 Line 10
    """
    re_ts = r"(\w+\s{1,2}\d+\s\d{2}:\d{2}:\d{2})"
    ts_fmt = "%b %d %H:%M:%S"

    vfs.map_file_fh("file", io.BytesIO(textwrap.dedent(content).encode()))
    path = vfs.path("file")

    mocked_stat = fsutil.stat_result([stat.S_IFREG, 1337, id(vfs), 0, 0, 0, len(content), 0, 3384460800, 0])
    with patch.object(path, "stat", return_value=mocked_stat):
        result = list(utils.year_rollover_helper(path, re_ts, ts_fmt))
        assert len(result) == 10

        year_line = [(ts.year, line) for ts, line in result]

        assert result[0][0].tzinfo == datetime.timezone.utc

        assert year_line[0] == (2077, "Jan  1 13:21:34 Line 10")
        assert year_line[-1] == (2073, "Dec 31 03:14:15 Line 1")

    # This mtime is in 2023 in UTC, but 2022 in -8
    # Test that the year detection correctly starts at 2022 local time if we parse with a timezone of -8
    mtime = datetime.datetime(2023, 1, 1, 3, tzinfo=datetime.timezone.utc)
    tzinfo = datetime.timezone(datetime.timedelta(hours=-8))
    mocked_stat = fsutil.stat_result([stat.S_IFREG, 1337, id(vfs), 0, 0, 0, len(content), 0, mtime.timestamp(), 0])
    with patch.object(path, "stat", return_value=mocked_stat):
        result = list(utils.year_rollover_helper(path, re_ts, ts_fmt, tzinfo))
        year_line = [(ts.year, line) for ts, line in result]

        assert result[0][0].tzinfo == tzinfo

        assert year_line[0] == (2022, "Jan  1 13:21:34 Line 10")
        assert year_line[-1] == (2018, "Dec 31 03:14:15 Line 1")


def test_helpers_fsutil_year_rollover_helper_leap_day() -> None:
    """Test if we correctly handle leap days such as 2024-02-29."""

    content = """
    Feb 28 11:00:00 Line 1
    Feb 29 12:00:00 Line 2
    Mar  1 13:00:00 Line 3
    """
    fs = VirtualFilesystem()
    fs.map_file_fh("file", io.BytesIO(textwrap.dedent(content).encode()))
    path = fs.path("file")

    re_ts = r"(\w+\s{1,2}\d+\s\d{2}:\d{2}:\d{2})"
    ts_fmt = "%b %d %H:%M:%S"
    mocked_stat = fsutil.stat_result(
        [stat.S_IFREG, 1337, id(fs), 0, 0, 0, len(content), 0, 1709294400, 0]
    )  # mtime is set to 2024-03-01.

    with patch.object(path, "stat", return_value=mocked_stat):
        result = list(utils.year_rollover_helper(path, re_ts, ts_fmt))
        assert len(result) == 3
