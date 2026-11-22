from __future__ import annotations

import sqlite3
import tempfile
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ExecPolicyRecord = TargetRecordDescriptor(
    "macos/execpolicy/entries",
    [
        ("string", "file_identifier"),
        ("string", "bundle_id"),
        ("string", "bundle_version"),
        ("string", "team_id"),
        ("string", "signing_id"),
        ("string", "cdhash"),
        ("string", "responsible_path"),
        ("path", "source"),
    ],
)


class ExecPolicyPlugin(Plugin):
    """Plugin to parse macOS ExecPolicy database.

    Tracks executed binaries and their code signing information.

    Location: /private/var/db/SystemPolicyConfiguration/ExecPolicy
    """

    __namespace__ = "execpolicy"

    DB_GLOB = "private/var/db/SystemPolicyConfiguration/ExecPolicy"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No ExecPolicy database found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM if they exist
        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=ExecPolicyRecord)
    def entries(self) -> Iterator[ExecPolicyRecord]:
        """Parse executed binary measurements from the ExecPolicy database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_entries(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing ExecPolicy at %s: %s", db_path, e)

    def _parse_entries(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()

            # Discover columns dynamically since they vary by macOS version
            cursor.execute("PRAGMA table_info(executable_measurements_v2)")
            columns = [col["name"] for col in cursor.fetchall()]

            if not columns:
                return

            cursor.execute("SELECT * FROM executable_measurements_v2")
            for row in cursor:
                try:
                    file_identifier = str(row["file_identifier"]) if "file_identifier" in columns else ""
                except (IndexError, KeyError):
                    file_identifier = ""

                try:
                    bundle_id = str(row["bundle_id"]) if "bundle_id" in columns else ""
                except (IndexError, KeyError):
                    bundle_id = ""

                try:
                    bundle_version = str(row["bundle_version"]) if "bundle_version" in columns else ""
                except (IndexError, KeyError):
                    bundle_version = ""

                try:
                    team_id = str(row["team_id"]) if "team_id" in columns else ""
                except (IndexError, KeyError):
                    team_id = ""

                try:
                    signing_id = str(row["signing_id"]) if "signing_id" in columns else ""
                except (IndexError, KeyError):
                    signing_id = ""

                try:
                    cdhash = str(row["cdhash"]) if "cdhash" in columns else ""
                except (IndexError, KeyError):
                    cdhash = ""

                try:
                    responsible_path = str(row["responsible_path"]) if "responsible_path" in columns else ""
                except (IndexError, KeyError):
                    responsible_path = ""

                yield ExecPolicyRecord(
                    file_identifier=file_identifier if file_identifier != "None" else "",
                    bundle_id=bundle_id if bundle_id != "None" else "",
                    bundle_version=bundle_version if bundle_version != "None" else "",
                    team_id=team_id if team_id != "None" else "",
                    signing_id=signing_id if signing_id != "None" else "",
                    cdhash=cdhash if cdhash != "None" else "",
                    responsible_path=responsible_path if responsible_path != "None" else "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
