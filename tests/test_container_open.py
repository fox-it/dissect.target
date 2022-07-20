from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dissect.target import container


@pytest.fixture
def mocked_ewf_detect():
    with patch("dissect.target.container.ewf") as mocked_containers:
        mocked_containers.EwfContainer.detect.return_value = True
        yield mocked_containers.EwfContainer.detect


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
