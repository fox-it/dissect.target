import re

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

CronjobRecord = TargetRecordDescriptor(
    "unix/cronjob",
    [
        ("string", "minute"),
        ("string", "hour"),
        ("string", "day"),
        ("string", "month"),
        ("string", "weekday"),
        ("string", "user"),
        ("string", "command"),
        ("path", "source"),
    ],
)

EnvironmentVariableRecord = TargetRecordDescriptor(
    "unix/environmentvariable",
    [
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class CronjobPlugin(Plugin):
    def check_compatible(self) -> None:
        pass

    def parse_crontab(self, file_path):
        for line in file_path.open("rt"):
            line = line.strip()
            if line.startswith("#") or not len(line):
                continue

            match = re.search(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", line)
            if match:
                usr = match.group(6)
                cmd = match.group(7)
                if not str(file_path).startswith("/etc/crontab") or not str(file_path).startswith("/etc/cron.d"):
                    cmd = usr + " " + cmd
                    usr = ""

                yield CronjobRecord(
                    minute=match.group(1),
                    hour=match.group(2),
                    day=match.group(3),
                    month=match.group(4),
                    weekday=match.group(5),
                    user=usr,
                    command=cmd,
                    source=file_path,
                    _target=self.target,
                )

            s = re.search(r"^([a-zA-Z_]+[a-zA-Z[0-9_])=(.*)", line)
            if s:
                yield EnvironmentVariableRecord(
                    key=s.group(1),
                    value=s.group(2),
                    source=file_path,
                    _target=self.target,
                )

    @export(record=[CronjobRecord, EnvironmentVariableRecord])
    def cronjobs(self):
        """
        Return all cronjobs.

        A cronjob is a scheduled task/command on a Unix based system. Adversaries may use cronjobs to gain
        persistence on the system.
        """
        tabs = []
        crontab_dirs = [
            "/var/cron/tabs",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
            "/etc/cron.d",
            "/usr/local/etc/cron.d",  # FreeBSD
        ]
        for path in crontab_dirs:
            fspath = self.target.fs.path(path)
            if not fspath.exists():
                continue

            for f in fspath.iterdir():
                if not f.exists():
                    continue
                if f.is_file():
                    tabs.append(f)

        crontab_file = self.target.fs.path("/etc/crontab")
        if crontab_file.exists():
            tabs.append(crontab_file)

        crontab_file = self.target.fs.path("/etc/anacrontab")
        if crontab_file.exists():
            tabs.append(crontab_file)

        for f in tabs:
            for record in self.parse_crontab(f):
                yield record
