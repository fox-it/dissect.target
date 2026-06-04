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
    """macOS Directory Services local nodes plugin.

    The /var/db/dslocal/sqlindex database tracks metadata for plist files in the directory structure

    References:
        - https://web.archive.org/web/20221206190314/https://samsclass.info/121/lec16/ch13.pdf
    """

    PATH = "/var/db/dslocal/nodes/Default/sqlindex"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No sqlindex file found")

    @export(record=DirectoryServicesLocalNodesRecord)
    def directory_services_local_nodes(
        self,
    ) -> Iterator[DirectoryServicesLocalNodesRecord]:
        """Return macOS Directory Services local node entries.

        Yields DirectoryServicesLocalNodesRecord with the following fields:

        .. code-block:: text

            tables (string[]): Names of tables contributing to the record.
            filetime (datetime): Timestamp associated with the row.
            filename (string): Name of the backing plist file.
            recordtype (string): Type of directory record (e.g. users, groups).
            value (string): Attribute value associated with the record.
            source (path): Path to the sqlindex file.

        Data is derived from the sqlindex database, where:
            - Tables prefixed with "rec:" contain rows with plist filenames and associated filetimes.
            - Attribute tables (e.g. name, uid, gid) contain rows with filenames, recordtypes, and values.

        Records are created by correlating rows between "rec:" and attribute tables.
        """
        with SQLite3(self.file) as database:
            ATTRIBUTE_TABLES = {
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
                elif table.name in ATTRIBUTE_TABLES:
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

        # TODO: Add altsecurityidentities, hardwareuuid, en_address, mail, member tables
