import datetime
import re

from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension

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
                    for line in file_.open("rt", errors="ignore"):  # Ignore Non-ASCII characters in bash_history
                        cmd_ts = None
                        if line.startswith("#") or len(line.strip()) == 0:
                            matches = re.search(r"^#([0-9]{10})$", line.strip())
                            if matches:
                                ts = matches.group(1)
                                try:
                                    cmd_ts = datetime.datetime.utcfromtimestamp(float(ts))
                                except (ValueError, TypeError):
                                    continue
                            continue

                        matches = re.search(
                            r"^.*\s\d+\s+(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s(.*)$",
                            line.strip(),
                        )
                        if matches:
                            cmd_ts = datetime.datetime(
                                int(matches.group(1)),
                                int(matches.group(2)),
                                int(matches.group(3)),
                                int(matches.group(4)),
                                int(matches.group(5)),
                                int(matches.group(6)),
                            )
                            command = matches.group(7)
                        else:
                            command = line.strip()

                        yield CommandHistoryRecord(
                            ts=cmd_ts,
                            command=command,
                            source=str(file_),
                            _target=self.target,
                            _user=user_details.user,
                        )
                except Exception:
                    self.target.log.exception("Failed to parse command history: %s", file_)
