from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

ConsoleHostHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "powershell/history",
    [
        ("datetime", "mtime"),
        ("string", "command"),
        ("path", "source"),
    ],
)


class PowerShellHistoryPlugin(Plugin):
    PATHS = [
        "AppData/Roaming/Microsoft/Windows/PowerShell/psreadline",
        ".local/share/powershell/PSReadLine",
    ]

    def __init__(self, target):
        super().__init__(target)

        self._history = []

        for user_details in target.user_details.all_with_home():
            for ps_path in self.PATHS:
                history_path = user_details.home_path.joinpath(ps_path)
                for history_file in history_path.glob("*_history.txt"):
                    self._history.append((user_details.user, history_file))

    def check_compatible(self) -> None:
        if not self._history:
            raise UnsupportedPluginError("No ConsoleHost_history.txt files found")

    @export(record=ConsoleHostHistoryRecord)
    def powershell_history(self):
        """Return PowerShell command history for all users.

        The PowerShell ConsoleHost_history.txt file contains information about the commands executed with PowerShell in
        a terminal. No data is recorded from terminal-less PowerShell sessions. Commands are saved to disk after the process has completed.
        PSReadLine does not save commands containing 'password', 'asplaintext', 'token', 'apikey' or 'secret'.

        References:
            - https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html
            - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_history?view=powershell-7.3#order-of-commands-in-the-history
            - https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline?view=powershell-7.3#command-history
        """  # noqa E501

        for user, _path in self._history:
            file_mtime = _path.stat().st_mtime

            for line in _path.open("r"):
                line = line.strip()
                if not line:
                    continue

                yield ConsoleHostHistoryRecord(
                    mtime=file_mtime,
                    command=line,
                    source=_path,
                    _target=self.target,
                    _user=user,
                )
