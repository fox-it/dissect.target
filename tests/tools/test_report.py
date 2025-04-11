from __future__ import annotations

import argparse
from unittest.mock import MagicMock, call, patch

import pytest

from dissect.target.plugin import FailureDescriptor, FunctionDescriptor, PluginRegistry
from dissect.target.target import Event, Target
from dissect.target.tools.report import (
    ExecutionReport,
    TargetExecutionReport,
    format_target_report,
    make_cli_args_overview,
    make_plugin_import_errors_overview,
)


@pytest.fixture
def test_target() -> Target:
    return Target("test_target")


@pytest.fixture
def func_execs() -> set[str]:
    return {"exec2", "exec1"}


@pytest.fixture
def target_execution_report(test_target: Target, func_execs: set[str]) -> TargetExecutionReport:
    return TargetExecutionReport(
        target=test_target,
        func_execs=func_execs,
    )


@pytest.fixture
def incompatible_plugins() -> set[str]:
    return {"incomp_plugin2", "incomp_plugin1"}


@pytest.fixture
def add_incompatible_plugins(target_execution_report: TargetExecutionReport, incompatible_plugins: set[str]) -> None:
    for plugin in incompatible_plugins:
        target_execution_report.add_incompatible_plugin(plugin)


@pytest.fixture
def registered_plugins() -> set[str]:
    return {"regist_plugin2", "regist_plugin1"}


@pytest.fixture
def add_registered_plugins(target_execution_report: TargetExecutionReport, registered_plugins: set[str]) -> None:
    for plugin in registered_plugins:
        target_execution_report.add_registered_plugin(plugin)


@pytest.fixture
def func_errors() -> dict[str, str]:
    return {
        "func1": "trace1",
        "func2": "trace2",
    }


@pytest.fixture
def add_func_errors(target_execution_report: TargetExecutionReport, func_errors: dict[str, str]) -> None:
    for func, trace in func_errors.items():
        target_execution_report.add_func_error(func, trace)


def test_target_execution_report_add_incompatible_plugin(
    target_execution_report: TargetExecutionReport,
    add_incompatible_plugins: None,
    incompatible_plugins: set[str],
) -> None:
    for plugin in target_execution_report.incompatible_plugins:
        assert plugin in incompatible_plugins


def test_target_execution_report_add_registered_plugin(
    target_execution_report: TargetExecutionReport,
    add_registered_plugins: None,
    registered_plugins: set[str],
) -> None:
    for plugin in target_execution_report.registered_plugins:
        assert plugin in registered_plugins


def test_target_execution_report_add_func_error(
    target_execution_report: TargetExecutionReport,
    add_func_errors: None,
    func_errors: dict[str, str],
) -> None:
    for func, trace in target_execution_report.func_errors.items():
        assert func_errors.get(func) == trace


def test_target_execution_report_as_dict(
    test_target: Target,
    target_execution_report: TargetExecutionReport,
    add_incompatible_plugins: None,
    add_registered_plugins: None,
    add_func_errors: None,
    incompatible_plugins: set[str],
    registered_plugins: set[str],
    func_errors: dict[str, str],
    func_execs: set[str],
) -> None:
    report_dict = target_execution_report.as_dict()
    assert report_dict.get("target") == str(test_target)
    assert report_dict.get("incompatible_plugins") == sorted(incompatible_plugins)
    assert report_dict.get("registered_plugins") == sorted(registered_plugins)
    assert report_dict.get("func_errors") == func_errors
    assert report_dict.get("func_execs") == sorted(func_execs)


@pytest.fixture
def execution_report() -> ExecutionReport:
    return ExecutionReport()


@pytest.fixture
def cli_args() -> argparse.Namespace:
    return argparse.Namespace(foo="bar", baz="bla")


@pytest.fixture
def set_cli_args(execution_report: ExecutionReport, cli_args: argparse.Namespace) -> None:
    execution_report.set_cli_args(cli_args)


@pytest.fixture
def plugin_stats() -> PluginRegistry:
    return PluginRegistry(
        __failed__=[
            FailureDescriptor(
                module="plugin1",
                stacktrace="trace1",
            ),
            FailureDescriptor(
                module="plugin2",
                stacktrace="trace2",
            ),
        ]
    )


@pytest.fixture
def set_plugin_stats(execution_report: ExecutionReport, plugin_stats: PluginRegistry) -> None:
    execution_report.set_plugin_stats(plugin_stats)


@pytest.fixture
def target1() -> Target:
    return Target("test1")


@pytest.fixture
def target2() -> Target:
    return Target("test2")


@pytest.fixture
def target_report1(execution_report: ExecutionReport, target1: Target) -> TargetExecutionReport:
    return execution_report.add_target_report(target1)


@pytest.fixture
def target_report2(execution_report: ExecutionReport, target2: Target) -> TargetExecutionReport:
    return execution_report.add_target_report(target2)


@pytest.fixture
def plugin1() -> MagicMock:
    plugin1 = MagicMock()
    plugin1.__module__ = "test_module"
    plugin1.__qualname__ = "plugin1"
    return plugin1


def test_execution_report_set_cli_args(
    execution_report: ExecutionReport,
    set_cli_args: None,
    cli_args: argparse.Namespace,
) -> None:
    assert execution_report.cli_args == vars(cli_args)


def test_execution_report_set_plugin_stats(
    execution_report: ExecutionReport,
    set_plugin_stats: None,
    plugin_stats: PluginRegistry,
) -> None:
    failed_plugins = plugin_stats.__failed__
    assert len(execution_report.plugin_import_errors) == len(failed_plugins)

    for failed_plugin in failed_plugins:
        module = failed_plugin.module
        stacktrace = failed_plugin.stacktrace
        assert execution_report.plugin_import_errors.get(module) == stacktrace


def test_execution_report_get_formatted_report(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target_report2: TargetExecutionReport,
) -> None:
    with (
        patch("dissect.target.tools.report.make_cli_args_overview", return_value="line_1"),
        patch("dissect.target.tools.report.make_plugin_import_errors_overview", return_value="line_2"),
        patch("dissect.target.tools.report.format_target_report", return_value="line_x"),
    ):
        assert execution_report.get_formatted_report() == "line_1\nline_2\nline_x\nline_x"


def test_execution_report_add_target_report(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target_report2: TargetExecutionReport,
) -> None:
    assert len(execution_report.target_reports) == 2
    assert target_report1 in execution_report.target_reports
    assert target_report2 in execution_report.target_reports


def test_execution_report_get_target_report(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target_report2: TargetExecutionReport,
    target1: Target,
    target2: Target,
) -> None:
    assert target_report1 == execution_report.get_target_report(target1)
    assert target_report2 == execution_report.get_target_report(target2)
    target3 = Target("nope")
    assert execution_report.get_target_report(target3) is None
    target_report3 = execution_report.get_target_report(target3, create=True)
    assert target_report3.target == target3


def test_execution_report__get_plugin_name(execution_report: ExecutionReport, plugin1: MagicMock) -> None:
    assert execution_report._get_plugin_name(plugin1) == "test_module.plugin1"


def test_execution_report_log_incompatible_plugin_plugin_cls(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target1: Target,
    plugin1: MagicMock,
) -> None:
    execution_report.log_incompatible_plugin(target1, None, plugin_cls=plugin1)
    assert "test_module.plugin1" in target_report1.incompatible_plugins


def test_execution_report_log_incompatible_plugin_plugin_desc(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target1: Target,
) -> None:
    plugin_desc = FunctionDescriptor(
        name="plugin1",
        namespace=None,
        path="",
        exported=True,
        internal=False,
        findable=True,
        alias=False,
        output=None,
        method_name="plugin1",
        module="test_module",
        qualname="plugin1",
    )
    execution_report.log_incompatible_plugin(target1, None, plugin_desc=plugin_desc)
    assert "test_module.plugin1" in target_report1.incompatible_plugins


def test_execution_report_log_registered_plugin(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target1: Target,
) -> None:
    execution_report.log_registered_plugin(target1, None, plugin_inst=MagicMock())
    assert "unittest.mock.MagicMock" in target_report1.registered_plugins


def test_execution_report_log_func_error(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target1: Target,
    func_errors: dict[str, str],
) -> None:
    func, trace = next(iter(func_errors.items()))
    execution_report.log_func_error(target1, None, func, trace)
    assert target_report1.func_errors.get(func) == trace


def test_execution_report_log_func_execution(
    execution_report: ExecutionReport,
    target_report1: TargetExecutionReport,
    target1: Target,
    func_execs: set[str],
) -> None:
    func = next(iter(func_execs))
    execution_report.log_func_execution(target1, None, func)
    assert func in target_report1.func_execs


def test_execution_report_set_event_callbacks(execution_report: ExecutionReport) -> None:
    mock_target = MagicMock()
    event_callbacks = (
        (Event.INCOMPATIBLE_PLUGIN, execution_report.log_incompatible_plugin),
        (Event.REGISTERED_PLUGIN, execution_report.log_registered_plugin),
        (Event.FUNC_EXEC, execution_report.log_func_execution),
        (Event.FUNC_EXEC_ERROR, execution_report.log_func_error),
    )

    execution_report.set_event_callbacks(mock_target)

    assert len(mock_target.mock_calls) == len(event_callbacks)
    for event_type, event_callback in event_callbacks:
        mock_call = call.set_event_callback(event_type=event_type, event_callback=event_callback)
        assert mock_call in mock_target.mock_calls


def test_execution_report_as_dict(
    execution_report: ExecutionReport,
    set_plugin_stats: None,
    plugin_stats: PluginRegistry,
    target_report1: TargetExecutionReport,
    target_report2: TargetExecutionReport,
    set_cli_args: None,
    cli_args: argparse.Namespace,
) -> None:
    expected_dict = {
        "plugin_import_errors": {
            "plugin1": "trace1",
            "plugin2": "trace2",
        },
        "target_reports": ["report1", "report2"],
        "cli_args": {
            "foo": "bar",
            "baz": "bla",
        },
    }

    with (
        patch.object(target_report1, "as_dict", return_value="report1"),
        patch.object(target_report2, "as_dict", return_value="report2"),
    ):
        execution_report_dict = execution_report.as_dict()
        assert execution_report_dict == expected_dict


def test_report_make_cli_args_overview(
    execution_report: ExecutionReport,
    set_cli_args: None,
    cli_args: argparse.Namespace,
) -> None:
    cli_args_overview = make_cli_args_overview(execution_report)
    assert "foo: bar" in cli_args_overview
    assert "baz: bla" in cli_args_overview


def test_report_make_plugin_import_errors_overview(
    execution_report: ExecutionReport,
    set_plugin_stats: None,
    plugin_stats: PluginRegistry,
) -> None:
    plugin_import_errors_overview = make_plugin_import_errors_overview(execution_report)
    assert "plugin1:\n        trace1" in plugin_import_errors_overview
    assert "plugin2:\n        trace2" in plugin_import_errors_overview


def test_report_format_target_report(
    test_target: Target,
    target_execution_report: TargetExecutionReport,
    add_incompatible_plugins: None,
    add_registered_plugins: None,
    add_func_errors: None,
    incompatible_plugins: set[str],
    registered_plugins: set[str],
    func_errors: dict[str, str],
    func_execs: set[str],
) -> None:
    target_report = format_target_report(target_execution_report)
    assert str(test_target) in target_report

    for registered_plugin in registered_plugins:
        assert registered_plugin in target_report

    for incompatible_plugin in incompatible_plugins:
        assert incompatible_plugin in target_report

    for func, trace in func_errors.items():
        assert func in target_report
        assert trace in target_report

    for func_exec in func_execs:
        assert func_exec in target_report
