from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest
from flow.record.fieldtypes import datetime as dt

import dissect.target.plugins.os.windows.prefetch as prefetch
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cstruct import cstruct

    from dissect.target import Target
    from dissect.target.filesystem import VirtualFilesystem


@pytest.fixture
def mocked_cstruct(version: int) -> Iterator[cstruct]:
    with patch.object(prefetch, "c_prefetch") as mocked_cstruct:
        mocked_cstruct.PREFETCH_HEADER.return_value.version = version
        yield mocked_cstruct


@pytest.fixture
def mocked_prefetch() -> prefetch.Prefetch:
    with patch.object(prefetch, "c_prefetch"), patch.multiple(prefetch.Prefetch, identify=Mock(), parse=Mock()):
        return prefetch.Prefetch(Mock())


@pytest.fixture
def target_win_prefetch(target_win: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_file(
        "Windows\\prefetch\\MPCMDRUN.EXE-962E6200.pf",
        absolute_path("_data/plugins/os/windows/prefetch/MPCMDRUN.EXE-962E6200.pf"),
    )

    target_win.add_plugin(prefetch.PrefetchPlugin)
    return target_win


@pytest.mark.parametrize(
    ("version", "dict_output"),
    [
        (17, ("FILE_INFORMATION_17", "FILE_METRICS_ARRAY_ENTRY_17")),
        (23, ("FILE_INFORMATION_23", "FILE_METRICS_ARRAY_ENTRY_23")),
        (30, ("FILE_INFORMATION_26", "FILE_METRICS_ARRAY_ENTRY_23")),
        (31, ("FILE_INFORMATION_26", "FILE_METRICS_ARRAY_ENTRY_23")),
    ],
)
def test_prefetch_valid_versions(mocked_cstruct: cstruct, version: int, dict_output: tuple[str, str]) -> None:
    file_info = getattr(mocked_cstruct, dict_output[0])
    metric_array = getattr(mocked_cstruct, dict_output[1])
    with (
        patch.dict(prefetch.prefetch_version_structs, {version: (file_info, metric_array)}),
        patch.object(prefetch.Prefetch, "parse_metrics") as mocked_metric,
    ):
        prefetch_obj = prefetch.Prefetch(Mock())
        assert prefetch_obj.fn == file_info.return_value
        mocked_metric.assert_called_with(metric_array_struct=metric_array)


@pytest.mark.parametrize("version", [0xDEADBEEF])
def test_prefetch_invalid_version(mocked_cstruct: cstruct) -> None:
    with pytest.raises(NotImplementedError):
        prefetch.Prefetch(Mock())


def test_prefetch_datetime(mocked_prefetch: prefetch.Prefetch) -> None:
    mocked_prefetch.fn = Mock()
    mocked_prefetch.fn.last_run_time = 0xDEADBEEF

    with patch("dissect.target.plugins.os.windows.prefetch.wintimestamp") as wintimestamp:
        assert mocked_prefetch.latest_timestamp == wintimestamp.return_value


def test_prefetch_unknown_attribute(mocked_prefetch: prefetch.Prefetch) -> None:
    mocked_prefetch.fn = Mock(spec=[])
    assert len(mocked_prefetch.previous_timestamps) == 0


@pytest.mark.parametrize(
    ("dates", "expected_length"),
    [
        ([0x0] * 12, 0),
        ([0x1] * 8, 8),
        ([0x1, 0x2, 0x0, 0x1], 3),
        ([0x1, 0x0, 0x0, 0x20, 0x0], 2),
    ],
)
def test_prefetch_last_run_dates(mocked_prefetch: prefetch.Prefetch, dates: list[int], expected_length: int) -> None:
    mocked_prefetch.fn = Mock()
    mocked_prefetch.fn.last_run_remains = dates

    assert len(mocked_prefetch.previous_timestamps) == expected_length


def test_prefetch_parse_metrics(mocked_prefetch: prefetch.Prefetch) -> None:
    mocked_prefetch.fh = Mock()
    mocked_prefetch.fn = Mock()
    mocked_prefetch.fn.number_of_file_metrics_entries = 10
    with patch.object(prefetch.Prefetch, "read_filename") as filename:
        filename.return_value.decode.return_value = ""
        metric_struct = Mock()
        mocked_prefetch.fn.filename_strings_offset = ""
        metric_struct.return_value.filename_string_offset = ""
        test = mocked_prefetch.parse_metrics(metric_array_struct=metric_struct)
        assert len(test) == 10


def test_prefetch_read_filename(mocked_prefetch: prefetch.Prefetch) -> None:
    mocked_fileheader = Mock()
    mocked_fileheader.read.return_value = b""

    mocked_prefetch.fh = mocked_fileheader
    filename = mocked_prefetch.read_filename(0x10, 0x10)

    mocked_fileheader.read.assert_called_with(0x10 * 2)
    assert isinstance(filename, bytes)
    assert mocked_fileheader.seek.call_count == 2


def test_prefetch_compact(target_win_prefetch: Target) -> None:
    records = list(target_win_prefetch.prefetch(compact=True))

    assert len(records) == 1
    mpcrun = records[0]
    assert mpcrun.filename == "MPCMDRUN.exe"
    assert mpcrun.source == "c:\\Windows\\prefetch\\MPCMDRUN.EXE-962E6200.pf"
    # assert mpcrun.runcount == 21 : Todo : fix bug
    assert sorted(mpcrun.previousruns, reverse=True) == [
        dt("2024-04-29 08:11:44.680344+00:00"),
        dt("2024-04-29 07:52:38.569597+00:00"),
        dt("2024-04-29 07:52:38.319941+00:00"),
        dt("2024-04-26 12:11:44.301853+00:00"),
        dt("2024-04-26 12:11:44.161709+00:00"),
        dt("2024-04-26 09:13:19.898300+00:00"),
        dt("2024-04-26 09:13:19.757269+00:00"),
    ]
    assert mpcrun.ts == dt("2024-04-29 08:11:44.851896+00:00")
    assert len(mpcrun.linkedfiles) == 41


def test_prefetch(target_win_prefetch: Target) -> None:
    records = list(target_win_prefetch.prefetch())

    assert len(records) == 328
    assert Counter(str(r.source) for r in records) == {"c:\\Windows\\prefetch\\MPCMDRUN.EXE-962E6200.pf": 328}
    assert Counter(str(r.filename) for r in records) == {"MPCMDRUN.EXE": 328}
    assert Counter(r.ts for r in records) == {
        dt("2024-04-29 08:11:44.680344+00:00"): 41,
        dt("2024-04-29 07:52:38.569597+00:00"): 41,
        dt("2024-04-29 07:52:38.319941+00:00"): 41,
        dt("2024-04-26 12:11:44.301853+00:00"): 41,
        dt("2024-04-26 12:11:44.161709+00:00"): 41,
        dt("2024-04-26 09:13:19.898300+00:00"): 41,
        dt("2024-04-26 09:13:19.757269+00:00"): 41,
        dt("2024-04-29 08:11:44.851896+00:00"): 41
    }
