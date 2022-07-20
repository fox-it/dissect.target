import datetime
import re

from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension

BashHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "linux/bashhistory",
    [
        ("datetime", "ts"),
        ("wstring", "command"),
        ("uri", "source"),
    ],
)


class BashHistoryPlugin(Plugin):
    def check_compatible(self):
        pass

    @export(record=BashHistoryRecord)
    def bashhistory(self):
        """Return bash history for all users.

        When using the BASH shell, history of the used commands is kept on the system. It is kept in a hidden file
        named ".bash_history" and may expose commands that were used by an adversary.
        """
        for user_details in self.target.user_details.all_with_home():
            for file_ in user_details.home_path.iterdir():
                if not file_.name.startswith(".bash_history"):
                    continue

                try:
                    for line in file_.open("rt"):
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

                        yield BashHistoryRecord(
                            ts=cmd_ts,
                            command=command,
                            source=str(file_),
                            _target=self.target,
                            _user=user_details.user,
                        )
                except Exception:
                    self.target.log.exception("Failed to parse bash history: %s", file_)
