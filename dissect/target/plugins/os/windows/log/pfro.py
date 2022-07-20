import datetime
import re

from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

PfroRecord = TargetRecordDescriptor(
    "filesystem/windows/pfro",
    [
        ("datetime", "ts"),
        ("uri", "path"),
        ("string", "operation"),
    ],
)


class PfroPlugin(Plugin):
    """
    PFRO plugin.
    """

    def __init__(self, target):
        super().__init__(target)
        self.logfile = self.target.fs.path("sysvol/windows/PFRO.log")

    def check_compatible(self):
        if not self.logfile.exists():
            raise UnsupportedPluginError("No PFRO log found")

    @export(record=PfroRecord)
    def pfro(self):
        """Return the content of sysvol/Windows/PFRO.log

        A Pending File Rename Operation log file (PFRO.log) holds information about the process of deleting or renaming
        files that are locked or being used and that will be renamed on reboot. This is related to the filerenameop
        plugin.

        Sources:
            - https://social.technet.microsoft.com/Forums/en-US/9b66a7b0-16d5-4d22-be4e-51df12db9f80/issue-understanding-pfro-log
            - https://community.ccleaner.com/topic/49106-pending-file-rename-operations-log/

        Yields PfroRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The parsed timestamp.
            path (uri): The parsed path.
            operation (string): The parsed operation.
        """  # noqa: E501
        try:
            for line in self.logfile.open("rt", encoding="utf-16-le"):
                if len(line) <= 1:
                    continue

                idx = line.split(" - ")
                date = idx[0]
                if "Error" in date:
                    # prfo log can log its own error. This results in an entry
                    # which gets grouped with the datetime of the logged
                    # action.
                    date = re.split(".+[A-Za-z]", date)[1]
                path = idx[1].split("|")[0][16:-2]
                operation = idx[1].split("|")
                if len(operation) >= 2:
                    operation = operation[1].split(" ")[0]
                else:
                    operation = None

                yield PfroRecord(
                    ts=datetime.datetime.strptime(date, "%m/%d/%Y %H:%M:%S"),
                    path=uri.from_windows(path),
                    operation=operation,
                    _target=self.target,
                )
        except UnicodeDecodeError:
            pass
