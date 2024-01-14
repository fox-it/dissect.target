from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from dissect.target.plugin import arg
from dissect.target.tools.utils import args_to_uri, persist_execution_report


def test_persist_execution_report():
    output_path = Path("/tmp/test/path")
    report_data = {
        "item1": {
            "subitem1": "foo",
        },
        "item2": "bar",
    }
    timestamp = datetime(2000, 1, 1)

    test_output = "TEST OUTPUT"

    with patch("pathlib.Path.write_text") as mocked_write_text:
        with patch("json.dumps", return_value=test_output) as mocked_json_dumps:
            full_path = persist_execution_report(output_path, report_data, timestamp)

            assert full_path.parent == output_path
            assert full_path.suffix == ".json"
            assert "2000-01-01-000000" in full_path.name

            mocked_json_dumps.assert_called_once_with(report_data, sort_keys=True, indent=4)

            mocked_write_text.assert_called_once_with(test_output)


@pytest.mark.parametrize(
    "targets, loader_name, rest, uris",
    [
        (["/path/to/somewhere"], "loader", ["--loader-option", "1"], ["loader:///path/to/somewhere?option=1"]),
        (["/path/to/somewhere"], "loader", ["--loader-option", "2"], ["loader:///path/to/somewhere?option=2"]),
        (["/path/to/somewhere"], "unknown", ["--unknown-option", "3"], ["unknown:///path/to/somewhere"]),
        (["/path/to/somewhere"], "loader", ["--ignored-option", "4"], ["loader:///path/to/somewhere"]),
        (["/path/to/somewhere"], "loader", [], ["loader:///path/to/somewhere"]),
        (["/path/to/somewhere"], "invalid", [], ["invalid:///path/to/somewhere"]),
    ],
)
def test_args_to_uri(targets: list[str], loader_name: str, rest: list[str], uris: list[str]) -> None:
    @arg("--loader-option", dest="option")
    class FakeLoader:
        pass

    with patch("dissect.target.tools.utils.LOADERS_BY_SCHEME", {"loader": FakeLoader}):
        assert args_to_uri(targets, loader_name, rest) == uris
