from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import arg, find_functions
from dissect.target.tools.utils import (
    args_to_uri,
    generate_argparse_for_unbound_method,
    persist_execution_report,
)

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_persist_execution_report() -> None:
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


@pytest.mark.parametrize(
    "pattern, expected_function",
    [
        ("passwords", "dissect.target.plugins.os.unix.shadow"),
        ("firefox.passwords", "Unsupported function `firefox.passwords`"),
    ],
)
def test_plugin_name_confusion_regression(target_unix_users: Target, pattern: str, expected_function: str) -> None:
    plugins, _ = find_functions(pattern, target_unix_users)
    assert len(plugins) == 1

    # We don't expect these functions to work since our target_unix_users fixture
    # does not include the neccesary artifacts for them to work. However we are
    # only interested in the plugin or namespace that was called so we check
    # the exception stack trace.
    with pytest.raises(UnsupportedPluginError) as exc_info:
        target_unix_users.get_function(plugins[0])

    assert expected_function in str(exc_info.value)


def test_plugin_mutual_exclusive_arguments():
    fargs = [
        (("--aa",), {"group": "aa"}),
        (("--bb",), {"group": "aa"}),
        (("--cc",), {"group": "bb"}),
        (("--dd",), {"group": "bb"}),
    ]
    method = test_plugin_mutual_exclusive_arguments
    setattr(method, "__args__", fargs)
    with patch("inspect.isfunction", return_value=True):
        parser = generate_argparse_for_unbound_method(method)
    assert len(parser._mutually_exclusive_groups) == 2
