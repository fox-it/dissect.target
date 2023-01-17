import datetime
import re

from dissect.target.helpers.descriptor_extensions import (
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

CommandHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "linux/history",
    [
        ("datetime", "ts"),
        ("wstring", "command"),
        ("uri", "source"),
    ],
)

COMMAND_HISTORY_FILES = [".bash_history", ".zsh_history", ".fish_history", "fish_history", ".python_history"]
IGNORED_HOMES = ["/bin", "/usr/sbin", "/sbin"]


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

            for file_ in user_details.home_path.iterdir():
                if file_.name not in COMMAND_HISTORY_FILES:
                    continue

                try:
                    next_cmd_ts = None

                    for line in file_.open("rt", errors="replace"):  # Ignore Non-UTF-8 characters in bash_history
                        cmd_ts = None
                        line = line.strip()

                        # Skip empty lines
                        if not line:
                            continue

                        if line.startswith("#"):  # Parse timestamp if possible
                            matches = re.search(r"^#([0-9]{10})$", line)
                            if matches:
                                ts = matches.group(1)
                                try:
                                    next_cmd_ts = datetime.datetime.utcfromtimestamp(float(ts))
                                except (ValueError, TypeError):
                                    continue
                            continue

                        if next_cmd_ts:
                            cmd_ts = next_cmd_ts
                            next_cmd_ts = None

                        yield CommandHistoryRecord(
                            ts=cmd_ts,
                            command=line,
                            source=str(file_),
                            _target=self.target,
                            _user=user_details.user,
                        )
                except Exception:
                    self.target.log.exception("Failed to parse command history: %s", file_)
