from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.plugin import export
from dissect.target.plugins.os.unix.history import (
    CommandHistoryPlugin,
    CommandHistoryRecord,
)
from dissect.target.plugins.os.windows.defender._plugin import parse_iso_datetime

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath

RE_ESXI_BASH_HISTORY_LINE = re.compile(
    r"^(?P<date>\S+)\s+"
    r"(?P<process>[^\[:]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s+"
    r"(?:\[(?P<user>[^\]]+)\]:\s*)?"
    r"(?P<command>.+)$"
)


class ESXICommandHistoryPlugin(CommandHistoryPlugin):
    """ESXI command history plugin."""

    COMMAND_HISTORY_ABSOLUTE_PATHS = (("esxi-shell", "/var/run/log/shell.log*"),)
    COMMAND_HISTORY_RELATIVE_PATHS = ()

    @export(record=CommandHistoryRecord)
    def commandhistory(self) -> Iterator[CommandHistoryRecord]:
        """Return shell history."""
        for shell, history_path, user in self._history_files:
            if shell == "esxi-shell":
                yield from self.parse_esxi_shell_history(history_path)
            else:
                yield from self.parse_generic_history(history_path, user, shell)

    def parse_esxi_shell_history(self, path: TargetPath) -> Iterator[CommandHistoryRecord]:
        """Parse shell.log* contents."""
        i = 0
        for line in path.open("rt", errors="replace"):
            line_match = RE_ESXI_BASH_HISTORY_LINE.match(line)

            if not line_match:
                self.target.log.warning("Failed to parse line %s", line)
                continue

            record = CommandHistoryRecord(
                ts=parse_iso_datetime(line_match.group("date")),
                command=line_match.group("command"),
                order=i,  # year_rollover_helper returns entries in reverse order.
                shell="esxi-shell",
                source=path,
                _target=self.target,
            )

            record.username = line_match.group("user")
            yield record
