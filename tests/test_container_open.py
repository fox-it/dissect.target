from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dissect.target import container


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
