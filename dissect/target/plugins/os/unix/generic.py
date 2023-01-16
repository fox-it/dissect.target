from datetime import datetime
from statistics import median
from typing import Union

from dissect.target.plugin import Plugin, export


class GenericPlugin(Plugin):
    def check_compatible(self):
        pass

    @export(property=True)
    def activity(self) -> Union[datetime, str]:
        """Return last seen activity based on filesystem timestamps."""
        var_log = self.target.fs.path("/var/log")
        if not var_log.exists():
            return

        last_seen = 0
        for f in var_log.iterdir():
            if f.stat().st_mtime > last_seen:
                last_seen = f.stat().st_mtime

        if last_seen != 0:
            return datetime.fromtimestamp(last_seen)

        return "unknown"

    @export(property=True)
    def installdate(self) -> Union[datetime, str]:
        """Return the likely install date of the filesystem."""

        files = [
            # Debian
            "/var/log/installer/install-journal.txt",
            "/var/log/installer/syslog",
            # RedHat
            "/root/anaconda-ks.cfg",
            # Generic
            "/etc/hostname",
            "/etc/machine-id",
            "/var/lib/dpkg/arch",
        ]
        dates = []

        for f in files:
            p = self.target.fs.path(f)
            if p.exists():
                dates.append(p.stat().st_mtime)

        if dates:
            return datetime.utcfromtimestamp(median(dates))

        # As a fallback if none of the above files are found, we attempt
        # to discover the birth date of the root filesystem.
        #
        # If the change time and modify time of the root dir are equal,
        # this is likely the creation timestamp of the root fs.
        if self.target.fs.stat("/").st_ctime == self.target.fs.stat("/").st_mtime:
            return datetime.utcfromtimestamp(self.target.fs.stat("/").st_ctime)

        return "unknown"
