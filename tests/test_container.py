from __future__ import annotations

import struct
from io import BytesIO
from pathlib import Path
from typing import Iterator
from unittest.mock import Mock, patch

import pytest

from dissect.target import container
from dissect.target.containers import raw, vhd
from dissect.target.exceptions import ContainerError


@pytest.fixture
def mocked_ewf_detect() -> Iterator[Mock]:
    mocked_ewf = Mock()
    mocked_ewf.EwfContainer.detect.return_value = True
    mocked_ewf.EwfContainer.detect
    with patch.object(container, "CONTAINERS", [mocked_ewf.EwfContainer]):
        yield mocked_ewf.EwfContainer


@pytest.mark.parametrize(
    "path, expected_output",
    [
        ("hello", Path("hello")),
        (["hello"], [Path("hello")]),
        ([Path("hello")], [Path("hello")]),
    ],
)
def test_open_inputs(mocked_ewf_detect: Mock, path: str | list[str] | Path, expected_output: Path | list[Path]) -> None:
    container.open(path)
    mocked_ewf_detect.assert_called_with(expected_output)


def test_open_fallback_fh(tmp_path: Path) -> None:
    # Create a valid VHD file
    fake_vhd = (
        (bytes(range(256)) * 2)
        + b"conectix"
        + (b"\x00" * 8)
        + (b"\xff" * 8)
        + (b"\x00" * 24)
        + struct.pack(">Q", 512)
        + (b"\x00" * 455)
    )

    tmp_with_ext = tmp_path.joinpath("testfile.vhd")
    tmp_without_ext = tmp_path.joinpath("testfile")
    tmp_with_wrong_ext = tmp_path.joinpath("testfile.qcow2")

    for path in [tmp_with_ext, tmp_without_ext, tmp_with_wrong_ext]:
        path.write_bytes(fake_vhd)

        assert isinstance(container.open(path), vhd.VhdContainer)
        assert vhd.VhdContainer.detect(path)

        with path.open("rb") as fh:
            assert isinstance(container.open(fh), vhd.VhdContainer)

        with path.open("rb") as fh:
            assert vhd.VhdContainer.detect(fh)

    tmp_nonexistent = tmp_path.joinpath("doesntexist")
    with pytest.raises(ContainerError):
        container.open(tmp_nonexistent)

    assert not vhd.VhdContainer.detect(tmp_nonexistent)

    tmp_dummy = tmp_path.joinpath("testdummy")
    tmp_dummy.write_bytes(b"\x00" * 1024)
    assert isinstance(container.open(tmp_dummy), raw.RawContainer)
    assert not vhd.VhdContainer.detect(tmp_dummy)


def test_reset_file_position() -> None:
    fh = BytesIO(b"\x00" * 8192)
    fh.seek(512)

    class MockContainer(container.Container):
        def __init__(self, fh):
            assert fh.tell() == 0
            fh.seek(1024)
            self.success = True

        @staticmethod
        def _detect_fh(fh, *args, **kwargs):
            assert fh.tell() == 0
            fh.seek(256)
            return True

    mock_container = Mock()
    mock_container.MockContainer = MockContainer
    with patch.object(container, "CONTAINERS", [mock_container.MockContainer]):
        opened_container = container.open(fh)
        assert isinstance(opened_container, mock_container.MockContainer)
        assert opened_container.success
        assert fh.tell() == 512
