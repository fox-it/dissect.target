from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.history import (
    CommandHistoryPlugin,
    CommandHistoryRecord,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.helpers.record import UnixUserRecord

RE_CITRIX_NETSCALER_BASH_HISTORY_DATE = re.compile(r"(?P<date>[^<]+)\s")

CITRIX_NETSCALER_BASH_HISTORY_RE = re.compile(
    r"""
        (?P<date>[^<]+)
        \s
        <
            (?P<syslog_facility>[^\.]+)
            \.
            (?P<syslog_loglevel>[^>]+)
        >
        \s
        (?P<hostname>[^\s]+)
        \s
        (?P<process_name>[^\[]+)
            \[
                (?P<process_id>\d+)
            \]
        :
        \s
        (?P<username>.*)\s
        on\s
            (?P<destination>[^\s]+)\s
        shell_command=
        \"
            (?P<command>.*)
        \"
    $
    """,
    re.VERBOSE,
)


class CitrixCommandHistoryPlugin(CommandHistoryPlugin):
    """Citrix command history plugin."""

    COMMAND_HISTORY_ABSOLUTE_PATHS = (("citrix-netscaler-bash", "/var/log/bash.log*"),)
    COMMAND_HISTORY_RELATIVE_PATHS = (
        *CommandHistoryPlugin.COMMAND_HISTORY_RELATIVE_PATHS,
        ("citrix-netscaler-cli", ".nscli_history"),
    )

    def _find_history_files(self) -> list[tuple[str, TargetPath, UnixUserRecord | None]]:
        """Find history files on the target that this plugin can parse."""
        history_files = []
        for shell, history_absolute_path_glob in self.COMMAND_HISTORY_ABSOLUTE_PATHS:
            history_files.extend(
                (shell, path, None) for path in self.target.fs.path("/").glob(history_absolute_path_glob.lstrip("/"))
            )

        # Also utilize the _find_history_files function of the parent class
        history_files.extend(super()._find_history_files())
        return history_files

    def _find_user_by_name(self, username: str) -> UnixUserRecord | None:
        """Cached function to return the matching UnixUserRecord for a given username."""
        if username is None:
            return None

        user_details = self.target.user_details.find(username=username)
        return user_details.user if user_details else None

    @export(record=CommandHistoryRecord)
    def commandhistory(self) -> Iterator[CommandHistoryRecord]:
        """Return shell history for all Citrix users.

        Some entries are returned in reverse chronological order and can contain negative command order integers due
        to the way Citrix stores bash history commands.
        """

        for shell, history_path, user in self._history_files:
            if shell == "citrix-netscaler-cli":
                yield from self.parse_netscaler_cli_history(history_path, user)
            elif shell == "citrix-netscaler-bash":
                yield from self.parse_netscaler_bash_history(history_path)

    def parse_netscaler_bash_history(self, path: TargetPath) -> Iterator[CommandHistoryRecord]:
        """Parse bash.log* contents."""

        i = 0
        for ts, line in year_rollover_helper(path, RE_CITRIX_NETSCALER_BASH_HISTORY_DATE, "%b %d %H:%M:%S "):
            line = line.strip()
            if not line:
                continue

            match = CITRIX_NETSCALER_BASH_HISTORY_RE.match(line)
            if not match:
                continue

            group = match.groupdict()
            command = group.get("command")
            user = self._find_user_by_name(group.get("username"))

            yield CommandHistoryRecord(
                ts=ts,
                command=command,
                order=-i,  # year_rollover_helper returns entries in reverse order.
                shell="citrix-netscaler-bash",
                source=path,
                _target=self.target,
                _user=user,
            )

            i += 1

    def parse_netscaler_cli_history(
        self, history_file: TargetPath, user: UnixUserRecord
    ) -> Iterator[CommandHistoryRecord]:
        """Parses the history file of the Citrix Netscaler CLI.

        The only difference compared to generic bash history files is that the first line will start with
        ``_HiStOrY_V2_``, which we will skip.
        """
        i = 0
        for line in history_file.open("rt"):
            if not (line := line.strip()):
                continue

            if i == 0 and line == "_HiStOrY_V2_":
                continue

            yield CommandHistoryRecord(
                ts=None,
                command=line,
                order=i,
                shell="citrix-netscaler-cli",
                source=history_file,
                _target=self.target,
                _user=user,
            )

            i += 1
