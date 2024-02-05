import re
from typing import Iterator, List, Tuple

from dissect.util.ts import from_unix

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixUserRecord, create_extended_descriptor
from dissect.target.plugin import Plugin, export, internal

CommandHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "unix/history",
    [
        ("datetime", "ts"),
        ("string", "command"),
        ("string", "shell"),
        ("path", "source"),
    ],
)

RE_EXTENDED_BASH = re.compile(r"^#(?P<ts>\d{10})$")
RE_EXTENDED_ZSH = re.compile(r"^: (?P<ts>\d{10}):\d+;(?P<command>.*)$")
RE_FISH = re.compile(r"- cmd: (?P<command>.+?)\s+when: (?P<ts>\d+)")


class CommandHistoryPlugin(Plugin):
    COMMAND_HISTORY_RELATIVE_PATHS = (
        ("bash", ".bash_history"),
        ("fish", ".local/share/fish/fish_history"),
        ("mongodb", ".dbshell"),
        ("mysql", ".mysql_history"),
        ("postgresql", ".psql_history"),
        ("python", ".python_history"),
        ("sqlite", ".sqlite_history"),
        ("zsh", ".zsh_history"),
        ("ash", ".ash_history"),
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self._history_files = list(self._find_history_files())

    def check_compatible(self) -> None:
        if not len(self._history_files):
            raise UnsupportedPluginError("No command history found")

    def _find_history_files(self) -> List[Tuple[str, TargetPath, UnixUserRecord]]:
        """Find existing history files."""
        history_files = []
        for user_details in self.target.user_details.all_with_home():
            for shell, history_relative_path in self.COMMAND_HISTORY_RELATIVE_PATHS:
                history_path = user_details.home_path.joinpath(history_relative_path)
                if history_path.exists():
                    history_files.append((shell, history_path, user_details.user))
        return history_files

    @export(record=CommandHistoryRecord)
    def bashhistory(self):
        """Deprecated, use commandhistory function."""
        self.target.log.warn("Function 'bashhistory' is deprecated, use the 'commandhistory' function instead.")
        return self.commandhistory()

    @export(record=CommandHistoryRecord)
    def commandhistory(self):
        """Return shell history for all users.

        When using a shell, history of the used commands is kept on the system.
        It is kept in a hidden file named ".$SHELL_history" and may expose
        commands that were used by an adversary.
        """

        for shell, history_path, user in self._history_files:
            if shell == "zsh":
                yield from self.parse_zsh_history(history_path, user)

            elif shell == "fish":
                yield from self.parse_fish_history(history_path, user)

            else:
                yield from self.parse_generic_history(history_path, user, shell)

    @internal
    def parse_generic_history(self, file, user: UnixUserRecord, shell: str) -> Iterator[CommandHistoryRecord]:
        """Parse bash_history contents.

        Regular .bash_history files contain one plain command per line.
        An extended .bash_history file may look like this:
        ```
        #1648598339
        echo "this is a test"
        ```

        Resources:
            - http://git.savannah.gnu.org/cgit/bash.git/tree/bashhist.c
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
                shell=shell,
                source=file,
                _target=self.target,
                _user=user,
            )

    @internal
    def parse_zsh_history(self, file, user: UnixUserRecord) -> Iterator[CommandHistoryRecord]:
        """Parse zsh_history contents.

        Regular .zsh_history lines are just the plain commands.
        Extended .zsh_history files may look like this:
        ```
        : 1673860722:0;sudo apt install sl
        : :;
        ```

        Resources:
            - https://sourceforge.net/p/zsh/code/ci/master/tree/Src/hist.c
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
                shell="zsh",
                source=file,
                _target=self.target,
                _user=user,
            )

    @internal
    def parse_fish_history(self, history_file: TargetPath, user: UnixUserRecord) -> Iterator[CommandHistoryRecord]:
        """Parses the history file of the fish shell.

        The fish history file is formatted as pseudo-YAML.
        An example of such a file:
        ```
        - cmd: ls
          when: 1688642435
        - cmd: cd home/
          when: 1688642441
          paths:
            - home/
        - cmd: echo "test: test"
          when: 1688986629
        ```

        Note that the last `- cmd: echo "test: test"` is not valid YAML,
        which is why we cannot safely use the Python yaml module.

        Resources:
            - https://github.com/fish-shell/fish-shell/blob/master/src/history.cpp
        """

        with history_file.open("r") as h_file:
            history_data = h_file.read()

        for command, ts in RE_FISH.findall(history_data):
            yield CommandHistoryRecord(
                ts=from_unix(int(ts)),
                command=command,
                shell="fish",
                source=history_file,
                _target=self.target,
                _user=user,
            )
