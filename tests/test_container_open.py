import struct
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dissect.target import container
from dissect.target.containers import raw, vhd
from dissect.target.exceptions import ContainerError


@pytest.fixture
def mocked_ewf_detect():
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
def test_open_inputs(mocked_ewf_detect: Mock, path, expected_output):
    container.open(path)
    mocked_ewf_detect.assert_called_with(expected_output)


def test_open_fallback_fh(tmpdir_name):
    # Create a valid VHD file
    fake_vhd = (
        (bytes(range(256)) * 2)
        + b"conectix"
        + (b"\x00" * 8)
        + (b"\xFF" * 8)
        + (b"\x00" * 24)
        + struct.pack(">Q", 512)
        + (b"\x00" * 455)
    )

    tmp_root = Path(tmpdir_name)
    tmp_with_ext = tmp_root.joinpath("testfile.vhd")
    tmp_without_ext = tmp_root.joinpath("testfile")
    tmp_with_wrong_ext = tmp_root.joinpath("testfile.qcow2")

    for path in [tmp_with_ext, tmp_without_ext, tmp_with_wrong_ext]:
        path.write_bytes(fake_vhd)

        assert isinstance(container.open(path), vhd.VhdContainer)
        assert vhd.VhdContainer.detect(path)

        with path.open("rb") as fh:
            assert isinstance(container.open(fh), vhd.VhdContainer)

        with path.open("rb") as fh:
            assert vhd.VhdContainer.detect(fh)

    tmp_nonexistent = tmp_root.joinpath("doesntexist")
    with pytest.raises(ContainerError):
        container.open(tmp_nonexistent)

    assert not vhd.VhdContainer.detect(tmp_nonexistent)

    tmp_dummy = tmp_root.joinpath("testdummy")
    tmp_dummy.write_bytes(b"\x00" * 1024)
    assert isinstance(container.open(tmp_dummy), raw.RawContainer)
    assert not vhd.VhdContainer.detect(tmp_dummy)
