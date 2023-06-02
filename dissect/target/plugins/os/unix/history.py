import re
from typing import Iterator

from dissect.util.ts import from_unix

from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export, internal

CommandHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "linux/history",
    [
        ("datetime", "ts"),
        ("wstring", "command"),
        ("path", "source"),
    ],
)

COMMAND_HISTORY_FILES = [".bash_history", ".zsh_history", ".python_history"]
# TODO: Add support for fish_history YAML-based files.
IGNORED_HOMES = ["/bin", "/usr/sbin", "/sbin"]

RE_EXTENDED_BASH = re.compile(r"^#(?P<ts>\d{10})$")
RE_EXTENDED_ZSH = re.compile(r"^: (?P<ts>\d{10}):\d+;(?P<command>.*)$")


class CommandHistoryPlugin(Plugin):
    def check_compatible(self):
        for user_details in self.target.user_details.all_with_home():
            for file_ in user_details.home_path.iterdir():
                if file_.name in COMMAND_HISTORY_FILES:
                    return True
        return False

    @export(record=CommandHistoryRecord)
    def bashhistory(self):
        """
        Deprecated, use commandhistory function.
        """
        self.target.log.warn("Function 'bashhistory' is deprecated, use the 'commandhistory' function instead.")
        return self.commandhistory()

    @export(record=CommandHistoryRecord)
    def commandhistory(self):
        """Return shell history for all users.

        When using a shell, history of the used commands is kept on the system. It is kept in a hidden file
        named ".$SHELL_history" and may expose commands that were used by an adversary.
        """

        for user_details in self.target.user_details.all_with_home():
            for ih in IGNORED_HOMES:
                if ih in user_details.user.home:
                    continue

            for file in user_details.home_path.iterdir():
                if file.name not in COMMAND_HISTORY_FILES:
                    continue

                # NOTE: Starting with Python 3.10 we can use pattern matching (PEP 634)
                if file.name == ".zsh_history":
                    yield from self.parse_zsh_history(file, user_details.user)
                else:
                    yield from self.parse_bash_history(file, user_details.user)

    @internal
    def parse_bash_history(self, file, user: str) -> Iterator[CommandHistoryRecord]:
        """Parse bash_history contents.

        Regular .bash_history files contain one plain command per line.
        An extended .bash_history file may look like this:
        ```
        #1648598339
        echo "this is a test"
        ```
        """
        next_cmd_ts = None

        for line in file.open("rt", errors="replace"):
            ts = None
            line = line.strip()

            if not line:
                continue

            if line.startswith("#") and (extended_bash_match := RE_EXTENDED_BASH.match(line)):
                next_cmd_ts = from_unix(int(extended_bash_match["ts"]))
                continue

            if next_cmd_ts:
                ts = next_cmd_ts
                next_cmd_ts = None

            yield CommandHistoryRecord(
                ts=ts,
                command=line,
                source=file,
                _target=self.target,
                _user=user,
            )

    @internal
    def parse_zsh_history(self, file, user: str) -> Iterator[CommandHistoryRecord]:
        """Parse zsh_history contents.

        Regular .zsh_history lines are just the plain commands.
        Extended .zsh_history files may look like this:
        ```
        : 1673860722:0;sudo apt install sl
        : :;
        ```
        """
        for line in file.open("rt", errors="replace"):
            line = line.strip()

            if not line or line == ": :;":
                continue

            if line.startswith(":") and (extended_zsh_match := RE_EXTENDED_ZSH.match(line)):
                ts = from_unix(int(extended_zsh_match["ts"]))
                command = extended_zsh_match["command"]
            else:
                ts = None
                command = line

            yield CommandHistoryRecord(
                ts=ts,
                command=command,
                source=file,
                _target=self.target,
                _user=user,
            )
