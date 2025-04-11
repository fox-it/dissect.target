from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

EnvironmentVariableRecord = TargetRecordDescriptor(
    "linux/proc/environ",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("varint", "pid"),
        ("string", "variable"),
        ("string", "content"),
    ],
)


class EnvironPlugin(Plugin):
    """Linux volatile proc environment plugin."""

    def check_compatible(self) -> None:
        if not self.target.has_function("proc"):
            raise UnsupportedPluginError("proc filesystem not available")

    @export(record=EnvironmentVariableRecord)
    def environ(self) -> Iterator[EnvironmentVariableRecord]:
        """Return the initial environment for all processes when they were started via execve(2).

        If the process modified its environment (e.g., by calling functions such as putenv(3) or modifying
        the environ(7) variable directly), this plugin will not reflect those changes.

        Yields EnvironmentVariableRecord with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The modification timestamp of the processes' environ file.
            name (string): The name associated to the pid.
            pid (varint): The process id (pid) of the process.
            variable (string): The name of the environment variable.
            content (string): The contents of the environment variable.
        """
        for process in self.target.proc.processes():
            for environ in process.environ():
                yield EnvironmentVariableRecord(
                    ts=process.get("environ").stat().st_mtime,
                    name=process.name,
                    pid=process.pid,
                    variable=environ.variable,
                    content=environ.contents,
                    _target=self.target,
                )
