from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension

ConsoleHostHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "filesystem/windows/powershell/history",
    [
        ("datetime", "last_modified"),
        ("string", "command"),
        ("uri", "path"),
    ],
)


class PowerShellHistoryPlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self._history = []
        for user_details in target.user_details.all_with_home():
            history_path = user_details.home_path.joinpath(
                "AppData/Roaming/Microsoft/Windows/PowerShell/psreadline/consolehost_history.txt"
            )
            if history_path.exists():
                self._history.append((user_details.user, history_path))

    def check_compatible(self):
        if not self._history:
            raise UnsupportedPluginError("No ConsoleHost_history.txt files found")

    @export(record=ConsoleHostHistoryRecord)
    def powershell_history(self):
        """Return PowerShell command history for all users.

        The PowerShell ConsoleHost_history.txt file contains information about the commands executed with PowerShell in
        a terminal. No data is recorded from terminal-less PowerShell sessions.

        Sources:
            - https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html
        """
        for user, path in self._history:
            for line in path.open("r"):
                line = line.strip()
                if not line:
                    continue

                yield ConsoleHostHistoryRecord(
                    last_modified=path.stat().st_mtime,
                    command=line,
                    path=uri.from_windows(str(path)),
                    _target=self.target,
                    _user=user,
                )
