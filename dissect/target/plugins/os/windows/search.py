from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dissect.esedb import EseDB
from dissect.sql import SQLite3
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import hashutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

SearchIndexRecord = TargetRecordDescriptor(
    "windows/search_index/entry",
    [
        ("datetime", "ts"),
        ("datetime", "ts_mtime"),
        ("datetime", "ts_btime"),
        ("datetime", "ts_atime"),
        ("path", "path"),
        ("string", "type"),
        ("filesize", "size"),
        ("bytes", "data"),
        ("path", "source"),
    ],
)


class SearchIndexPlugin(Plugin):
    """Windows Search Index plugin.

    Parses ``Windows.edb`` EseDB and ``Windows.db`` SQlite3 databases. Currently does not parse
    ``GatherLogs/SystemIndex/SystemIndex.*.(Crwl|gthr)`` files or ``Windows-gather.db`` and ``Windows-usn.db`` files.

    Resources:
        - https://github.com/strozfriedberg/sidr
        - https://github.com/libyal/esedb-kb/blob/main/documentation/Windows%20Search.asciidoc
        - https://www.aon.com/en/insights/cyber-labs/windows-search-index-the-forensic-artifact-youve-been-searching-for
    """

    SYSTEM_PATHS = (
        # Windows 11 22H2 (SQLite3)
        "sysvol/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db",
        # Windows Vista and Windows 10 (EseDB)
        "sysvol/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
        # Windows XP (EseDB)
        "sysvol/Documents and Settings/All Users/Application Data/Microsoft/Search/Data/Applications/Windows/Windows.edb",  # noqa: E501
    )

    USER_PATHS = (
        # Windows 10 Server Roaming (EseDB / SQLite)
        "AppData/Roaming/Microsoft/Search/Data/Applications/S-1-*/*.*db",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.databases = set(self.find_databases())

    def find_databases(self) -> Iterator[tuple[Path, UserDetails | None]]:
        seen = set()

        for system_path in self.SYSTEM_PATHS:
            if (path := self.target.fs.path(system_path)).is_file() and (
                digest := hashutil.common(path.open())
            ) not in seen:
                seen.add(digest)
                yield path.resolve(), None

        for user_details in self.target.user_details.all_with_home():
            for user_path in self.USER_PATHS:
                for path in user_details.home_path.glob(user_path):
                    if (digest := hashutil.common(path.open())) not in seen:
                        seen.add(digest)
                        yield path.resolve(), user_details

    def check_compatible(self) -> None:
        if not self.databases:
            raise UnsupportedPluginError("No Windows Search Index database files found on target")

    @export(record=SearchIndexRecord)
    def search(self) -> Iterator[SearchIndexRecord]:
        """Yield Windows Index Search records."""

        # TODO: Split record types in IE/Edge browsing activity, user activity and file activity

        for db_path, user_details in self.databases:
            if db_path.suffix == ".edb":
                yield from self.parse_esedb(db_path, user_details)

            elif db_path.suffix == ".db":
                yield from self.parse_sqlite(db_path, user_details)

    def parse_esedb(self, db_path: Path, user_details: UserDetails) -> Iterator[SearchIndexRecord]:
        """Parse the EseDB ``SystemIndex_PropertyStore`` table."""

        with db_path.open("rb") as fh:
            db = EseDB(fh)
            table = db.table("SystemIndex_PropertyStore")

            # Translates e.g. "System_DateModified" to "15F-System_DateModified"
            COLS = {col.split("-", maxsplit=1)[-1]: col for col in table.column_names}

            for record in table.records():

                # BUG: System_Search_AutoSummary is LongText but actually stores bytes?
                data = record.get(COLS["System_Search_AutoSummary"])
                data = data.encode() if isinstance(data, str) else data

                # TODO: What is the difference between System_Date* and System_Document_Date*?
                # TODO: Check if InvertedOnlyMD5 field matches filesystem file content

                yield SearchIndexRecord(
                    ts=None,
                    ts_mtime=wintimestamp(int.from_bytes(b_mtime, "little"))
                    if (b_mtime := record.get(COLS["System_DateModified"]))
                    else None,
                    ts_btime=wintimestamp(int.from_bytes(b_btime, "little"))
                    if (b_btime := record.get(COLS["System_DateCreated"]))
                    else None,
                    ts_atime=wintimestamp(int.from_bytes(b_atime, "little"))
                    if (b_atime := record.get(COLS["System_DateAccessed"]))
                    else None,
                    path=record.get(COLS["System_ItemPathDisplay"]),
                    type=record.get(COLS["System_MIMEType"]),  # or System_ItemTypeText
                    size=int.from_bytes(b_size, "little") if (b_size := record.get(COLS["System_Size"])) else None,
                    data=data,
                    source=db_path,
                    _target=self.target,
                )

    def parse_sqlite(self, db_path: Path, user_details: UserDetails) -> Iterator[SearchIndexRecord]:
        """Parse the SQLite3 ``SystemIndex_1_PropertyStore`` table."""

        def build_record(values: dict[str, Any], db_path: Path, target: Target) -> Iterator[SearchIndexRecord]:

            # TODO: Add System_FileOwner
            # TODO: Add System_Search_AutoSummary
            # TODO: Parse System_FileAttributes (https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)

            yield SearchIndexRecord(
                ts=wintimestamp(int.from_bytes(b_gtime, "little"))
                if (b_gtime := current_values.get("System_Search_GatherTime"))
                else None,
                ts_mtime=wintimestamp(int.from_bytes(b_mtime, "little"))
                if (b_mtime := current_values.get("System_DateModified"))
                else None,
                ts_btime=wintimestamp(int.from_bytes(b_btime, "little"))
                if (b_btime := current_values.get("System_DateCreated"))
                else None,
                ts_atime=wintimestamp(int.from_bytes(b_atime, "little"))
                if (b_atime := current_values.get("System_DateAccessed"))
                else None,
                path=current_values.get("System_ItemPathDisplay"),
                type=current_values.get("System_MIMEType"),  # or System_ContentType or System_ItemTypeText
                size=int.from_bytes(b_size, "little")
                if (b_size := current_values.get("System_Size"))
                else None,
                data=bytes(current_values.get("System_Search_AutoSummary", ""),encoding="utf-8") or None,
                source=db_path,
                _target=target,
            )

        with db_path.open("rb") as fh:
            db = SQLite3(fh)

            # Contains WorkId, ColumnId and Value
            table = db.table("SystemIndex_1_PropertyStore")

            # ColumnId is translated using the ``SystemIndex_1_PropertyStore_Metadata`` table
            COLS = {
                row.get("Id"): row.get("UniqueKey", "").split("-", maxsplit=1)[-1]
                for row in db.table("SystemIndex_1_PropertyStore_Metadata").rows()
            }

            current_work_id = None
            current_values = {}

            for row in table.rows():
                if current_work_id is None:
                    current_work_id = row.get("WorkId")

                if row.get("WorkId") != current_work_id:
                    yield from build_record(current_values, db_path, self.target)
                    current_work_id = row.get("WorkId")
                    current_values = {}

                column_id = row.get("ColumnId")
                column_name = COLS[column_id]
                current_values[column_name] = row.get("Value")

            yield from build_record(current_values, db_path, self.target)
