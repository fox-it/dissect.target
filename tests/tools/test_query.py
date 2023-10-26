import os
import re
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.plugin import PluginFunction
from dissect.target.target import Target
from dissect.target.tools.query import main as target_query


def test_target_query_list(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "--list"])

        with pytest.raises((SystemExit, IndexError, ImportError)):
            target_query()
        out, _ = capsys.readouterr()

        assert out.startswith("Available plugins:")
        assert "Failed to load:\n    None\nAvailable loaders:\n" in out


@pytest.mark.parametrize(
    "given_funcs, expected_invalid_funcs",
    [
        (
            ["foo"],
            ["foo"],
        ),
        (
            ["bar", "version"],
            ["bar"],
        ),
        (
            ["version", "foo", "wireguard.config", "bar", "apps.webserver.iis*"],
            ["bar", "foo"],
        ),
        (
            ["apps.browser.*.downloads", "bar", "version", "foo"],
            ["bar", "foo"],
        ),
        (
            ["apps.webserver.iis.doesnt.exist", "apps.webserver.apache.access"],
            ["apps.webserver.iis.doesnt.exist*"],
        ),
    ],
)
def test_target_query_invalid_functions(
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    given_funcs: list[str],
    expected_invalid_funcs: list[str],
) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", ",".join(given_funcs), "tests/_data/loaders/tar/test-archive-dot-folder.tgz"],
        )

        with pytest.raises((SystemExit)):
            target_query()
        _, err = capsys.readouterr()

        assert "target-query: error: argument -f/--function contains invalid plugin(s):" in err

        # Workaround for https://github.com/fox-it/dissect.target/issues/266
        RE_ERR = re.compile(r"contains invalid plugin\(s\)\: (?P<funcs>.*?)\n$")
        match = RE_ERR.search(err).groupdict()

        invalid_funcs = [i.strip() for i in match["funcs"].split(",")]
        invalid_funcs.sort()

        assert invalid_funcs == expected_invalid_funcs


@pytest.mark.parametrize(
    "given_funcs, expected_invalid_funcs",
    [
        (
            ["foo"],
            ["foo"],
        ),
        (
            ["bar", "version"],
            ["bar"],
        ),
        (
            ["version", "foo", "wireguard.config", "bar", "apps.webserver.iis*"],
            ["bar", "foo"],
        ),
        (
            ["apps.browser.*.downloads", "bar", "version", "foo"],
            ["bar", "foo"],
        ),
        (
            ["apps.webserver.iis.doesnt.exist", "apps.webserver.apache.access"],
            ["apps.webserver.iis.doesnt.exist*"],
        ),
    ],
)
def test_target_query_invalid_excluded_functions(
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    given_funcs: list[str],
    expected_invalid_funcs: list[str],
) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-query",
                "-f",
                "hostname",
                "-xf",
                ",".join(given_funcs),
                "tests/_data/loaders/tar/test-archive-dot-folder.tgz",
            ],
        )

        with pytest.raises((SystemExit)):
            target_query()
        _, err = capsys.readouterr()

        assert "target-query: error: argument -xf/--excluded-functions contains invalid plugin(s):" in err

        # Workaround for https://github.com/fox-it/dissect.target/issues/266
        RE_ERR = re.compile(r"contains invalid plugin\(s\)\: (?P<funcs>.*?)\n$")
        match = RE_ERR.search(err).groupdict()

        invalid_funcs = [i.strip() for i in match["funcs"].split(",")]
        invalid_funcs.sort()

        assert invalid_funcs == expected_invalid_funcs


def test_target_query_unsupported_plugin_log(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", "regf", "tests/_data/loaders/tar/test-archive-dot-folder.tgz"],
        )

        target_query()
        _, err = capsys.readouterr()

        assert "Unsupported plugin for regf: Registry plugin not loaded" in err


def mock_find_plugin_function(
    target: Target,
    patterns: str,
    compatibility: bool = False,
    **kwargs,
) -> tuple[list[PluginFunction], set[str]]:
    plugins = []
    for pattern in patterns.split(","):
        plugins.append(
            PluginFunction(
                name=pattern,
                output_type="record",
                path="",
                class_object=MagicMock(),
                method_name=pattern,
                plugin_desc={},
            ),
        )

    return (plugins, set())


def mock_execute_function(
    target: Target,
    func: PluginFunction,
    cli_params: Optional[list[str]] = None,
) -> tuple[str, Any, list[str]]:
    return (func.output_type, func.name, "")


def test_target_query_filtered_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-query",
                "-f",
                "foo,bar,bla,foo",
                "-xf",
                "bla",
                "tests/_data/loaders/tar/test-archive-dot-folder.tgz",
            ],
        )

        with (
            patch(
                "dissect.target.tools.query.find_plugin_functions",
                autospec=True,
                side_effect=mock_find_plugin_function,
            ),
            patch(
                "dissect.target.tools.query.execute_function_on_target",
                autospec=True,
                side_effect=mock_execute_function,
            ) as mock_execute,
            patch(
                "dissect.target.tools.query.record_output",
                autospec=True,
            ),
        ):
            target_query()

            assert len(mock_execute.mock_calls) == 2

            executed_func_names = set()
            for call in mock_execute.mock_calls:
                executed_func_names.add(call.args[1].name)
            assert executed_func_names == {"foo", "bar"}


def test_target_query_dry_run(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.sep == "\\":
        target_file = "tests\\_data\\loaders\\tar\\test-archive-dot-folder.tgz"
    else:
        target_file = "tests/_data/loaders/tar/test-archive-dot-folder.tgz"

    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", "general.*", "--dry-run", target_file],
        )

        target_query()
        out, _ = capsys.readouterr()

        assert out == f"Dry run on: <Target {target_file}>\n  execute: osinfo (general.osinfo.osinfo)\n"
