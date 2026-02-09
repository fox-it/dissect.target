from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

import dissect.target.plugins.os.windows.prefetch as prefetch

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cstruct import cstruct


@pytest.fixture
def mocked_cstruct(version: int) -> Iterator[cstruct]:
    with patch.object(prefetch, "c_prefetch") as mocked_cstruct:
        mocked_cstruct.PREFETCH_HEADER.return_value.version = version
        yield mocked_cstruct


@pytest.fixture
def mocked_prefetch() -> prefetch.Prefetch:
    with patch.object(prefetch, "c_prefetch"), patch.multiple(prefetch.Prefetch, identify=Mock(), parse=Mock()):
        return prefetch.Prefetch(Mock())


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
