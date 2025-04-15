from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, arg, find_functions
from dissect.target.tools.utils import (
    args_to_uri,
    configure_generic_arguments,
    execute_function_on_target,
    generate_argparse_for_unbound_method,
    persist_execution_report,
    process_generic_arguments,
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
    timestamp = datetime(2000, 1, 1, tzinfo=timezone.utc)

    test_output = "TEST OUTPUT"

    with (
        patch("pathlib.Path.write_text") as mocked_write_text,
        patch("json.dumps", return_value=test_output) as mocked_json_dumps,
    ):
        full_path = persist_execution_report(output_path, report_data, timestamp)

        assert full_path.parent == output_path
        assert full_path.suffix == ".json"
        assert "2000-01-01-000000" in full_path.name

        mocked_json_dumps.assert_called_once_with(report_data, sort_keys=True, indent=4)

        mocked_write_text.assert_called_once_with(test_output)


@pytest.mark.parametrize(
    ("targets", "loader_name", "rest", "uris"),
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


def test_process_generic_arguments() -> None:
    parser = argparse.ArgumentParser()
    configure_generic_arguments(parser)

    args = parser.parse_args(
        [
            "--keychain-file",
            "/path/to/keychain.csv",
            "--keychain-value",
            "some_value",
            "--loader",
            "loader_name",
            "--version",
            "--plugin-path",
            "/path/to/plugins",
        ]
    )
    args.targets = ["target1", "target2"]
    rest = ["--some-other-arg", "value"]

    with (
        patch("dissect.target.tools.utils.configure_logging") as mocked_configure_logging,
        patch("dissect.target.tools.utils.version", return_value="1.0.0") as mocked_version,
        patch("dissect.target.tools.utils.sys.exit") as mocked_exit,
        patch(
            "dissect.target.tools.utils.args_to_uri", return_value=["loader_name://target1", "loader_name://target2"]
        ) as mocked_args_to_uri,
        patch("dissect.target.tools.utils.keychain.register_keychain_file") as mocked_register_keychain_file,
        patch("dissect.target.tools.utils.keychain.register_wildcard_value") as mocked_register_wildcard_value,
        patch(
            "dissect.target.tools.utils.get_external_module_paths", return_value=["/path/to/plugins"]
        ) as mocked_get_external_module_paths,
        patch("dissect.target.tools.utils.load_modules_from_paths") as mocked_load_modules_from_paths,
    ):
        process_generic_arguments(args, rest)

        mocked_configure_logging.assert_called_once_with(0, False, as_plain_text=True)
        mocked_version.assert_called_once_with("dissect.target")
        mocked_exit.assert_called_once_with(0)
        mocked_args_to_uri.assert_called_once_with(["target1", "target2"], "loader_name", rest)
        mocked_register_keychain_file.assert_called_once_with(Path("/path/to/keychain.csv"))
        mocked_register_wildcard_value.assert_called_once_with("some_value")
        mocked_get_external_module_paths.assert_called_once_with([Path("/path/to/plugins")])
        mocked_load_modules_from_paths.assert_called_once_with(["/path/to/plugins"])

        assert args.targets == ["loader_name://target1", "loader_name://target2"]

        del args.targets
        args.target = "target1"
        process_generic_arguments(args, rest)

        assert args.target == "loader_name://target1"


@pytest.mark.parametrize(
    ("pattern", "expected_function"),
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


def test_plugin_mutual_exclusive_arguments() -> None:
    fargs = [
        (("--aa",), {"group": "aa"}),
        (("--bb",), {"group": "aa"}),
        (("--cc",), {"group": "bb"}),
        (("--dd",), {"group": "bb"}),
    ]
    method = test_plugin_mutual_exclusive_arguments
    method.__args__ = fargs
    with patch("inspect.isfunction", return_value=True):
        parser = generate_argparse_for_unbound_method(method)
    assert len(parser._mutually_exclusive_groups) == 2


def test_namespace_plugin_args() -> None:
    class Fake(Plugin):
        __namespace__ = "fake"
        __register__ = False

        @arg("--a")
        def __call__(self, a: str | None = None) -> None:
            return a

    mock_target = Mock()
    obj = Fake(mock_target)

    mock_target.get_function.return_value = Fake, obj

    _, result, rest = execute_function_on_target(mock_target, Mock(), ["--a", "asdf", "--b", "123"])

    assert result == "asdf"
    assert rest == ["--b", "123"]
