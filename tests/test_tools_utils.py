import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from dissect.target.tools.utils import (
    load_module_paths,
    environment_variable_paths,
    persist_execution_report,
)


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

            mocked_json_dumps.called_once_with(report_data)

            mocked_write_text.assert_called_once_with(test_output)


@pytest.mark.parametrize(
    "env_value, expected_output",
    [
        (None, []),
        ("", []),
        (",", [Path(""), Path("")]),
    ],
)
def test_load_environment_variable(env_value, expected_output):
    if env_value:
        os.environ.update({"DISSECT_PLUGINS": env_value})

    assert environment_variable_paths() == expected_output


def test_load_module_paths():
    assert load_module_paths([Path(""), Path("")]) == [Path("")]
    os.environ.update({"DISSECT_PLUGINS": ","})
    assert load_module_paths([Path(""), Path("")]) == [Path("")]
