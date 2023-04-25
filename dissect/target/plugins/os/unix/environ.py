from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

EnvironmentVariableRecord = TargetRecordDescriptor(
    "unix/proc/environ",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("varint", "pid"),
        ("string", "variable"),
        ("string", "content"),
    ],
)


class EnvironPlugin(Plugin):
    def check_compatible(self) -> None:
        if not self.target.proc:
            raise UnsupportedPluginError("No /proc directory found")

    @export(record=EnvironmentVariableRecord)
    def environ(self) -> Iterator[TargetRecordDescriptor]:
        """This plugins yields the initial environment that was set when the currently executing program was started via
        execve(2).

        If the process modified its environment (e.g., by calling functions such as putenv(3) or modifying
        the environ(7) variable directly), this plugin will not reflect those changes.

        Yields EnvironmentVariableRecord with the following fields:
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
                )
