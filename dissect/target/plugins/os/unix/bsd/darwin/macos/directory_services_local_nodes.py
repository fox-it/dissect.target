from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

DirectoryServicesLocalNodesRecord = TargetRecordDescriptor(
    "macos/directory_services_local_nodes",
    [
        ("string[]", "tables"),
        ("datetime", "filetime"),
        ("string", "filename"),
        ("string", "recordtype"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class DirectoryServicesLocalNodesPlugin(Plugin):
    """macOS directory services local nodes plugin."""

    PATH = "/var/db/dslocal/nodes/Default/sqlindex"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = None
        self._resolve_file()

    def _resolve_file(self) -> None:
        path = self.target.fs.path(self.PATH)
        if path.exists():
            self.file = path

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No sqlindex file found")

    @export(record=DirectoryServicesLocalNodesRecord)
    def directory_services_local_nodes(
        self,
    ) -> Iterator[DirectoryServicesLocalNodesRecord]:
        """Yield directory services local nodes information."""
        with SQLite3(self.file) as database:
            NAME_TABLES = {
                "name",
                "realname",
                "generateduid",
                "uid",
                "gid",
                "ip_address",
                "ipv6_address",
                "smb_sid",
                "smb_rid",
                "groupmembers",
                "users",
                "nestedgroups",
            }

            r_rows: list[tuple[str, object]] = []
            n_tables = set()

            for table in database.tables():
                if table.name.startswith("rec:"):
                    r_rows.extend((table.name, r_row) for r_row in table.rows())
                elif table.name in NAME_TABLES:
                    n_tables.add(table)

            for table in n_tables:
                rec_rows = list(r_rows)

                for n_row in table.rows():
                    matched = False

                    for idx, (table_name, r_row) in enumerate(rec_rows):
                        if r_row.filename == n_row.filename:
                            yield DirectoryServicesLocalNodesRecord(
                                tables=[table.name, table_name],
                                filetime=r_row.filetime,
                                filename=n_row.filename,
                                recordtype=n_row.recordtype,
                                value=n_row.value,
                                source=self.file,
                                _target=self.target,
                            )

                            del rec_rows[idx]
                            matched = True
                            break

                    if not matched:
                        yield DirectoryServicesLocalNodesRecord(
                            tables=[table.name],
                            filetime=None,
                            filename=n_row.filename,
                            recordtype=n_row.recordtype,
                            value=n_row.value,
                            source=self.file,
                            _target=self.target,
                        )

        # Still missing altsecurityidentities, hardwareuuid, en_address, mail, member tables
