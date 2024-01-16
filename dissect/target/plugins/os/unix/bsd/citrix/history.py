import re
from typing import Iterator, Optional

from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.history import (
    CommandHistoryPlugin,
    CommandHistoryRecord,
)

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
    COMMAND_HISTORY_ABSOLUTE_PATHS = (("citrix-netscaler-bash", "/var/log/bash.log*"),)
    COMMAND_HISTORY_RELATIVE_PATHS = CommandHistoryPlugin.COMMAND_HISTORY_RELATIVE_PATHS + (
        ("citrix-netscaler-cli", ".nscli_history"),
    )

    def _find_history_files(self) -> list[tuple[str, TargetPath, Optional[UnixUserRecord]]]:
        """Find history files on the target that this plugin can parse."""
        history_files = []
        for shell, history_absolute_path_glob in self.COMMAND_HISTORY_ABSOLUTE_PATHS:
            for path in self.target.fs.path("/").glob(history_absolute_path_glob.lstrip("/")):
                history_files.append((shell, path, None))

        # Also utilize the _find_history_files function of the parent class
        history_files.extend(super()._find_history_files())
        return history_files

    def _find_user_by_name(self, username: str) -> Optional[UnixUserRecord]:
        """Cached function to return the matching UnixUserRecord for a given username."""
        if username is None:
            return None

        user_details = self.target.user_details.find(username=username)
        return user_details.user if user_details else None

    @export(record=CommandHistoryRecord)
    def commandhistory(self) -> Iterator[CommandHistoryRecord]:
        """Return shell history for all users.

        When using a shell, history of the used commands is kept on the system.
        """

        for shell, history_path, user in self._history_files:
            if shell == "citrix-netscaler-cli":
                yield from self.parse_netscaler_cli_history(history_path, user)
            elif shell == "citrix-netscaler-bash":
                yield from self.parse_netscaler_bash_history(history_path)

    def parse_netscaler_bash_history(self, path: TargetPath) -> Iterator[CommandHistoryRecord]:
        """Parse bash.log* contents."""
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
                shell="citrix-netscaler-bash",
                source=path,
                _target=self.target,
                _user=user,
            )

    def parse_netscaler_cli_history(
        self, history_file: TargetPath, user: UnixUserRecord
    ) -> Iterator[CommandHistoryRecord]:
        """Parses the history file of the Citrix Netscaler CLI.

        The only difference compared to generic bash history files is that the first line will start with
        ``_HiStOrY_V2_``, which we will skip.
        """
        for idx, line in enumerate(history_file.open("rt")):
            if not (line := line.strip()):
                continue

            if idx == 0 and line == "_HiStOrY_V2_":
                continue

            yield CommandHistoryRecord(
                ts=None,
                command=line,
                shell="citrix-netscaler-cli",
                source=history_file,
                _target=self.target,
                _user=user,
            )
