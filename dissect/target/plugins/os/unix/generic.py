from datetime import datetime
from statistics import median
from typing import Optional

from dissect.util import ts

from dissect.target.plugin import Plugin, export


class GenericPlugin(Plugin):
    def check_compatible(self) -> None:
        pass

    @export(property=True)
    def activity(self) -> Optional[datetime]:
        """Return last seen activity based on filesystem timestamps."""
        var_log = self.target.fs.path("/var/log")
        if not var_log.exists():
            return

        last_seen = 0
        for f in var_log.iterdir():
            if f.stat().st_mtime > last_seen:
                last_seen = f.stat().st_mtime

        if last_seen != 0:
            return ts.from_unix(last_seen)

    @export(property=True)
    def install_date(self) -> Optional[datetime]:
        """Return the likely install date of the operating system."""

        # Although this purports to be a generic function for Unix targets,
        # these paths are Linux specific.
        files = [
            # Debian
            "/var/log/installer/install-journal.txt",
            "/var/log/installer/syslog",
            "/var/lib/dpkg/arch",
            # RedHat
            "/root/anaconda-ks.cfg",
            # Generic
            "/etc/hostname",
            "/etc/machine-id",
        ]
        dates = []

        for f in files:
            p = self.target.fs.path(f)
            if p.exists():
                dates.append(p.stat().st_mtime)

        if dates:
            return ts.from_unix(median(dates))

        # As a fallback if none of the above files are found, we attempt
        # to discover the birth date of the root filesystem.
        #
        # If the change time and modify time of the root dir are equal,
        # this is likely the creation timestamp of the root fs.
        root_stat = self.target.fs.stat("/")
        if root_stat.st_ctime == root_stat.st_mtime:
            return ts.from_unix(root_stat.st_ctime)
