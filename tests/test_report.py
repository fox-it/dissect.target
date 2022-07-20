import argparse
import pytest
from unittest.mock import MagicMock, call, patch

from dissect.target import Target
from dissect.target.report import (
    ExecutionReport,
    TargetExecutionReport,
    format_target_report,
    make_cli_args_overview,
    make_plugin_import_errors_overview,
)
from dissect.target.target import Event


@pytest.fixture
def test_target():
    return Target("test_target")


@pytest.fixture
def func_execs():
    return {"exec2", "exec1"}


@pytest.fixture
def target_execution_report(test_target, func_execs):
    return TargetExecutionReport(
        target=test_target,
        func_execs=func_execs,
    )


@pytest.fixture
def incompatible_plugins():
    return {"incomp_plugin2", "incomp_plugin1"}


@pytest.fixture
def add_incompatible_plugins(target_execution_report, incompatible_plugins):
    for plugin in incompatible_plugins:
        target_execution_report.add_incompatible_plugin(plugin)


@pytest.fixture
def registered_plugins():
    return {"regist_plugin2", "regist_plugin1"}


@pytest.fixture
def add_registered_plugins(target_execution_report, registered_plugins):
    for plugin in registered_plugins:
        target_execution_report.add_registered_plugin(plugin)


@pytest.fixture
def func_errors():
    return {
        "func1": "trace1",
        "func2": "trace2",
    }


@pytest.fixture
def add_func_errors(target_execution_report, func_errors):
    for func, trace in func_errors.items():
        target_execution_report.add_func_error(func, trace)


def test_target_execution_report_add_incompatible_plugin(
    target_execution_report,
    add_incompatible_plugins,
    incompatible_plugins,
):
    for plugin in target_execution_report.incompatible_plugins:
        assert plugin in incompatible_plugins


def test_target_execution_report_add_registered_plugin(
    target_execution_report,
    add_registered_plugins,
    registered_plugins,
):
    for plugin in target_execution_report.registered_plugins:
        assert plugin in registered_plugins


def test_target_execution_report_add_func_error(
    target_execution_report,
    add_func_errors,
    func_errors,
):
    for func, trace in target_execution_report.func_errors.items():
        assert func_errors.get(func) == trace


def test_target_execution_report_as_dict(
    test_target,
    target_execution_report,
    add_incompatible_plugins,
    add_registered_plugins,
    add_func_errors,
    incompatible_plugins,
    registered_plugins,
    func_errors,
    func_execs,
):
    report_dict = target_execution_report.as_dict()
    assert report_dict.get("target") == str(test_target)
    assert report_dict.get("incompatible_plugins") == sorted(incompatible_plugins)
    assert report_dict.get("registered_plugins") == sorted(registered_plugins)
    assert report_dict.get("func_errors") == func_errors
    assert report_dict.get("func_execs") == sorted(func_execs)


@pytest.fixture
def execution_report():
    return ExecutionReport()


@pytest.fixture
def cli_args():
    return argparse.Namespace(foo="bar", baz="bla")


@pytest.fixture
def set_cli_args(execution_report, cli_args):
    execution_report.set_cli_args(cli_args)


@pytest.fixture
def plugin_stats():
    return {
        "_failed": [
            {
                "module": "plugin1",
                "stacktrace": "trace1",
            },
            {
                "module": "plugin2",
                "stacktrace": "trace2",
            },
        ]
    }


@pytest.fixture
def set_plugin_stats(execution_report, plugin_stats):
    execution_report.set_plugin_stats(plugin_stats)


@pytest.fixture
def target1():
    return Target("test1")


@pytest.fixture
def target2():
    return Target("test2")


@pytest.fixture
def target_report1(execution_report, target1):
    return execution_report.add_target_report(target1)


@pytest.fixture
def target_report2(execution_report, target2):
    return execution_report.add_target_report(target2)


@pytest.fixture
def plugin1():
    plugin1 = MagicMock()
    plugin1.__module__ = "test_module"
    plugin1.__qualname__ = "plugin1"
    return plugin1


def test_execution_report_set_cli_args(
    execution_report,
    set_cli_args,
    cli_args,
):
    assert execution_report.cli_args == vars(cli_args)


def test_execution_report_set_plugin_stats(
    execution_report,
    set_plugin_stats,
    plugin_stats,
):
    failed_plugins = plugin_stats["_failed"]
    assert len(execution_report.plugin_import_errors) == len(failed_plugins)

    for failed_plugin in failed_plugins:
        module = failed_plugin["module"]
        stacktrace = failed_plugin["stacktrace"]
        assert execution_report.plugin_import_errors.get(module) == stacktrace


def test_execution_report_get_formatted_report(
    execution_report,
    target_report1,
    target_report2,
):
    with patch("dissect.target.report.make_cli_args_overview", return_value="line_1"):
        with patch("dissect.target.report.make_plugin_import_errors_overview", return_value="line_2"):
            with patch("dissect.target.report.format_target_report", return_value="line_x"):
                assert execution_report.get_formatted_report() == "line_1\nline_2\nline_x\nline_x"


def test_execution_report_add_target_report(
    execution_report,
    target_report1,
    target_report2,
):
    assert len(execution_report.target_reports) == 2
    assert target_report1 in execution_report.target_reports
    assert target_report2 in execution_report.target_reports


def test_execution_report_get_target_report(
    execution_report,
    target_report1,
    target_report2,
    target1,
    target2,
):
    assert target_report1 == execution_report.get_target_report(target1)
    assert target_report2 == execution_report.get_target_report(target2)
    target3 = Target("nope")
    assert execution_report.get_target_report(target3) is None
    target_report3 = execution_report.get_target_report(target3, create=True)
    assert target_report3.target == target3


def test_execution_report__get_plugin_name(execution_report, plugin1):
    assert execution_report._get_plugin_name(plugin1) == "test_module.plugin1"


def test_execution_report_log_incompatible_plugin_plugin_cls(
    execution_report,
    target_report1,
    target1,
    plugin1,
):
    execution_report.log_incompatible_plugin(target1, None, plugin_cls=plugin1)
    assert "test_module.plugin1" in target_report1.incompatible_plugins


def test_execution_report_log_incompatible_plugin_plugin_desc(
    execution_report,
    target_report1,
    target1,
):
    plugin_desc = {"fullname": "test_module.plugin1"}
    execution_report.log_incompatible_plugin(target1, None, plugin_desc=plugin_desc)
    assert "test_module.plugin1" in target_report1.incompatible_plugins


def test_execution_report_log_registered_plugin(
    execution_report,
    target_report1,
    target1,
):
    execution_report.log_registered_plugin(target1, None, plugin_inst=MagicMock())
    assert "unittest.mock.MagicMock" in target_report1.registered_plugins


def test_execution_report_log_func_error(
    execution_report,
    target_report1,
    target1,
    func_errors,
):
    func, trace = next(iter(func_errors.items()))
    execution_report.log_func_error(target1, None, func, trace)
    assert target_report1.func_errors.get(func) == trace


def test_execution_report_log_func_execution(
    execution_report,
    target_report1,
    target1,
    func_execs,
):
    func = next(iter(func_execs))
    execution_report.log_func_execution(target1, None, func)
    assert func in target_report1.func_execs


def test_execution_report_set_event_callbacks(execution_report):
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
    execution_report,
    set_plugin_stats,
    plugin_stats,
    target_report1,
    target_report2,
    set_cli_args,
    cli_args,
):
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

    with patch.object(target_report1, "as_dict", return_value="report1"):
        with patch.object(target_report2, "as_dict", return_value="report2"):
            execution_report_dict = execution_report.as_dict()
            assert execution_report_dict == expected_dict


def test_report_make_cli_args_overview(
    execution_report,
    set_cli_args,
    cli_args,
):
    cli_args_overview = make_cli_args_overview(execution_report)
    assert "foo: bar" in cli_args_overview
    assert "baz: bla" in cli_args_overview


def test_report_make_plugin_import_errors_overview(
    execution_report,
    set_plugin_stats,
    plugin_stats,
):
    plugin_import_errors_overview = make_plugin_import_errors_overview(execution_report)
    assert "plugin1:\n        trace1" in plugin_import_errors_overview
    assert "plugin2:\n        trace2" in plugin_import_errors_overview


def test_report_format_target_report(
    test_target,
    target_execution_report,
    add_incompatible_plugins,
    add_registered_plugins,
    add_func_errors,
    incompatible_plugins,
    registered_plugins,
    func_errors,
    func_execs,
):
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
