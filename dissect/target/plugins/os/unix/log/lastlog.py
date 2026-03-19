from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.database.sqlite3 import SQLite3
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from pathlib import Path

    from dissect.target.target import Target

LastLogRecord = TargetRecordDescriptor(
    "linux/log/lastlog",
    [
        ("datetime", "ts"),
        ("uint32", "uid"),
        ("string", "ut_user"),  # name
        ("string", "ut_host"),  # source
        ("string", "ut_tty"),  # port
        ("string", "ut_service"),
        ("path", "source"),
    ],
)

lastlog_def = """
#define UT_NAMESIZE 32
#define UT_HOSTSIZE 256
#define size        292


struct {
    uint32 tv_sec;
} time_t;


struct entry {
    struct time_t ll_time;
    char    ut_user[UT_NAMESIZE];
    char    ut_host[UT_HOSTSIZE];
};
"""

c_lastlog = cstruct().load(lastlog_def)


@dataclass
class LastLogEntry:
    ts: datetime
    uid: int
    ut_user: str | None
    ut_tty: str | None
    ut_host: str | None
    ut_service: str | None  # lastlog2 specific


class LastLogFile:
    """Lastlog sparse file iterator.

    References:
        - https://github.com/linux-pam/linux-pam/tree/master/modules/pam_lastlog
    """

    def __init__(self, path: Path, users: dict | None):
        self.path = path
        self.fh = path.open()
        self.users = users

    def __iter__(self) -> Iterator[LastLogEntry]:
        idx = -1
        while True:
            try:
                idx += 1
                entry = c_lastlog.entry(self.fh)
                user = self.users.get(idx)

                if entry.ll_time.tv_sec == 0:
                    continue

                yield LastLogEntry(
                    ts=from_unix(entry.ll_time.tv_sec),
                    uid=idx,
                    ut_user=user,
                    ut_tty=entry.ut_user.decode().strip("\x00") or None,
                    ut_host=entry.ut_host.decode(errors="ignore").strip("\x00") or None,
                    ut_service=None,
                )

            except EOFError:
                break


class LastLogDb:
    """Lastlog2 database file iterator.

    References:
        - https://github.com/util-linux/util-linux/tree/master/liblastlog2
        - https://github.com/util-linux/util-linux/tree/master/pam_lastlog2
    """

    def __init__(self, path: Path, users: dict | None):
        self.path = path
        self.db = SQLite3(path)
        self.users: dict[str, int] = {v: k for k, v in users.items()}

    def __iter__(self) -> Iterator[LastLogEntry]:
        if not (table := self.db.table("Lastlog2")):
            return None

        for row in table.rows():
            yield LastLogEntry(
                ts=from_unix(row.Time),
                uid=self.users.get(row.Name),
                ut_user=row.Name,
                ut_tty=row.TTY,
                ut_host=row.RemoteHost or None,
                ut_service=row.Service,
            )


class LastLogPlugin(Plugin):
    """UNIX lastlog plugin."""

    def __init__(self, target: Target):
        super().__init__(target)

        self.paths = list(self.target.fs.path("/").glob("var/log/lastlog*")) + list(
            self.target.fs.path("/").glob("var/lib/lastlog/lastlog2*")
        )

    def check_compatible(self) -> None:
        if not self.paths:
            raise UnsupportedPluginError("No lastlog file(s) found on target")

    @export(record=LastLogRecord)
    def lastlog(self) -> Iterator[LastLogRecord]:
        """Return login information from ``/var/log/lastlog`` and ``/var/lib/lastlog/lastlog2.db`` files.

        Lastlog files contain the most recent logins of all users on a UNIX based operating system.

        Newer UNIX distributions use ``lastlog2`` and ``liblastlog2`` which use SQLite3 database files.

        References:
            - https://www.tutorialspoint.com/unix_commands/lastlog.htm
        """
        seen = set()
        users: dict[int, str] = (
            {user.uid: user.name for user in self.target.users()} if self.target.has_function("users") else {}
        )

        for path in self.paths:
            if any(seen_path.samefile(path) for seen_path in seen):
                continue

            iterator = LastLogDb if path.suffix == ".db" else LastLogFile
            for entry in iterator(path, users):
                yield LastLogRecord(
                    **asdict(entry),
                    source=path,
                    _target=self.target,
                )
