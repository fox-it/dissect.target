import textwrap
import argparse

import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Type

from dissect.target import Target
from dissect.target.plugin import Plugin
from dissect.target.target import Event


BLOCK_INDENT = 4 * " "


@dataclass
class TargetExecutionReport:
    target: Target

    incompatible_plugins: Set[str] = dataclasses.field(default_factory=set)
    registered_plugins: Set[str] = dataclasses.field(default_factory=set)

    func_errors: Dict[str, str] = dataclasses.field(default_factory=dict)
    func_execs: Set[str] = dataclasses.field(default_factory=set)

    def add_incompatible_plugin(self, plugin_name: str) -> None:
        self.incompatible_plugins.add(plugin_name)

    def add_registered_plugin(self, plugin_name: str) -> None:
        self.registered_plugins.add(plugin_name)

    def add_func_error(self, func, stacktrace: str) -> None:
        self.func_errors[func] = stacktrace

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target": str(self.target),
            "incompatible_plugins": sorted(self.incompatible_plugins),
            "registered_plugins": sorted(self.registered_plugins),
            "func_errors": self.func_errors,
            "func_execs": sorted(self.func_execs),
        }


@dataclass
class ExecutionReport:
    plugin_import_errors: Dict[str, str] = dataclasses.field(default_factory=dict)

    target_reports: List[TargetExecutionReport] = dataclasses.field(default_factory=list)

    cli_args: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def set_cli_args(self, args: argparse.Namespace) -> None:
        args = ((key, str(value)) for (key, value) in vars(args).items())
        self.cli_args.update(args)

    def set_plugin_stats(self, plugins: Dict[str, Any]) -> None:
        for details in plugins.get("_failed", []):
            self.plugin_import_errors[details["module"]] = "".join(details["stacktrace"])

    def get_formatted_report(self) -> str:
        blocks = [
            make_cli_args_overview(self),
            make_plugin_import_errors_overview(self),
            *[format_target_report(report) for report in self.target_reports],
        ]
        return "\n".join(blocks)

    def add_target_report(self, target: Target) -> TargetExecutionReport:
        target_report = TargetExecutionReport(target=target)
        self.target_reports.append(target_report)
        return target_report

    def get_target_report(self, target: Target, create: bool = False) -> TargetExecutionReport:
        target_report = next(filter(lambda r: r.target == target, self.target_reports), None)
        if target_report is None and create:
            target_report = self.add_target_report(target)
        return target_report

    @staticmethod
    def _get_plugin_name(plugin_cls):
        return f"{plugin_cls.__module__}.{plugin_cls.__qualname__}"

    def log_incompatible_plugin(
        self,
        target: Target,
        _,
        plugin_cls: Optional[Type[Plugin]] = None,
        plugin_desc: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not plugin_cls and not plugin_desc:
            raise ValueError("Either `plugin_cls` or `plugin_desc` must be set")

        target_report = self.get_target_report(target, create=True)

        if plugin_cls:
            plugin_name = self._get_plugin_name(plugin_cls)
        elif plugin_desc:
            plugin_name = plugin_desc["fullname"]

        target_report.add_incompatible_plugin(plugin_name)

    def log_registered_plugin(self, target: Target, _, plugin_inst: Plugin) -> None:
        target_report = self.get_target_report(target, create=True)
        plugin_cls = type(plugin_inst)
        plugin_name = self._get_plugin_name(plugin_cls)
        target_report.add_registered_plugin(plugin_name)

    def log_func_error(self, target: Target, _, func: str, stacktrace: str) -> None:
        target_report = self.get_target_report(target, create=True)
        target_report.add_func_error(func, stacktrace)

    def log_func_execution(self, target: Target, _, func: str) -> None:
        target_report = self.get_target_report(target, create=True)
        target_report.func_execs.add(func)

    def set_event_callbacks(self, target_cls: Type[Target]) -> None:
        target_cls.set_event_callback(
            event_type=Event.INCOMPATIBLE_PLUGIN,
            event_callback=self.log_incompatible_plugin,
        )
        target_cls.set_event_callback(
            event_type=Event.REGISTERED_PLUGIN,
            event_callback=self.log_registered_plugin,
        )
        target_cls.set_event_callback(
            event_type=Event.FUNC_EXEC,
            event_callback=self.log_func_execution,
        )
        target_cls.set_event_callback(
            event_type=Event.FUNC_EXEC_ERROR,
            event_callback=self.log_func_error,
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "plugin_import_errors": self.plugin_import_errors,
            "target_reports": [report.as_dict() for report in self.target_reports],
            "cli_args": self.cli_args,
        }


def make_cli_args_overview(report: ExecutionReport) -> str:
    header = "CLI arguments:"

    rows = []
    for key, value in sorted(report.cli_args.items()):
        rows.append(f"{key}: {value}")

    block = "\n".join(rows)
    block = textwrap.indent(block, prefix=BLOCK_INDENT)
    return "\n".join([header, block])


def make_plugin_import_errors_overview(report: ExecutionReport, short=True) -> str:
    header = "Plugin import errors:"

    rows = []
    for module, trace in sorted(report.plugin_import_errors.items()):
        trace = trace.rstrip()
        trace = textwrap.indent(trace, prefix=BLOCK_INDENT)
        rows.append(f"{module}:\n{trace}")

    block = "\n".join(rows)
    block = textwrap.indent(block, prefix=BLOCK_INDENT)
    return "\n".join([header, block])


def format_target_report(target_report: TargetExecutionReport) -> str:
    blocks = [f"Target: {target_report.target}"]

    registered_plugins_header = "Registered plugins:"
    registered_plugins_rows = sorted(target_report.registered_plugins)
    registered_plugins_rows_block = textwrap.indent(
        "\n".join(registered_plugins_rows),
        prefix=BLOCK_INDENT,
    )
    registered_plugins_block = textwrap.indent(
        "\n".join([registered_plugins_header, registered_plugins_rows_block]),
        prefix=BLOCK_INDENT,
    )
    blocks.append(registered_plugins_block)

    incompatible_plugins_header = "Incompatible plugins:"
    incompatible_plugins_rows = sorted(target_report.incompatible_plugins)
    incompatible_plugins_rows_block = textwrap.indent(
        "\n".join(incompatible_plugins_rows),
        prefix=BLOCK_INDENT,
    )
    incompatible_plugins_block = textwrap.indent(
        "\n".join([incompatible_plugins_header, incompatible_plugins_rows_block]),
        prefix=BLOCK_INDENT,
    )
    blocks.append(incompatible_plugins_block)

    func_errors_header = "Function errors:"
    func_errors_rows = []
    for func, stacktrace in sorted(target_report.func_errors.items()):
        stacktrace = textwrap.indent(stacktrace, prefix=BLOCK_INDENT)
        func_errors_rows.append(f"{func}:\n{stacktrace}")

    func_errors_rows_block = textwrap.indent("\n".join(func_errors_rows), prefix=BLOCK_INDENT)
    func_errors_block = textwrap.indent(
        "\n".join([func_errors_header, func_errors_rows_block]),
        prefix=BLOCK_INDENT,
    )
    blocks.append(func_errors_block)

    func_execs_header = "Function executions:"
    func_execs_rows = sorted(target_report.func_execs)
    func_execs_rows_block = textwrap.indent("\n".join(func_execs_rows), prefix=BLOCK_INDENT)
    func_execs_block = textwrap.indent(
        "\n".join([func_execs_header, func_execs_rows_block]),
        prefix=BLOCK_INDENT,
    )
    blocks.append(func_execs_block)

    return "\n".join(blocks)
