from __future__ import annotations

import plistlib
import sqlite3
import tempfile
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ArdConfigRecord = TargetRecordDescriptor(
    "macos/ard/config",
    [
        ("string", "setting"),
        ("string", "value"),
        ("path", "source"),
    ],
)

ArdAccessRecord = TargetRecordDescriptor(
    "macos/ard/access",
    [
        ("string", "entry"),
        ("path", "source"),
    ],
)


class MacOSArdPlugin(Plugin):
    """Plugin to parse Apple Remote Desktop configuration and access data.

    Locations:
        /private/var/db/RemoteManagement/cliauth
        /private/var/db/RemoteManagement/RMDB/rmdb.sqlite3
        /Library/Application Support/Apple Remote Desktop/RemoteManagement.launchd
        /Library/Preferences/com.apple.RemoteDesktop.plist
        /Library/Preferences/com.apple.RemoteManagement.plist
    """

    __namespace__ = "ard"

    PLIST_PATHS = [
        "Library/Application Support/Apple Remote Desktop/RemoteManagement.launchd",
        "Library/Preferences/com.apple.RemoteDesktop.plist",
        "Library/Preferences/com.apple.RemoteManagement.plist",
    ]

    CLIAUTH_PATH = "private/var/db/RemoteManagement/cliauth"
    RMDB_PATH = "private/var/db/RemoteManagement/RMDB/rmdb.sqlite3"

    def __init__(self, target):
        super().__init__(target)
        root = self.target.fs.path("/")

        self._plist_paths = []
        for p in self.PLIST_PATHS:
            path = root.joinpath(p)
            if path.exists():
                self._plist_paths.append(path)

        self._cliauth_path = root.joinpath(self.CLIAUTH_PATH)
        if not self._cliauth_path.exists():
            self._cliauth_path = None

        self._rmdb_path = root.joinpath(self.RMDB_PATH)
        if not self._rmdb_path.exists():
            self._rmdb_path = None

    def check_compatible(self) -> None:
        if not self._plist_paths and not self._cliauth_path and not self._rmdb_path:
            raise UnsupportedPluginError("No Apple Remote Desktop artifacts found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _flatten_plist(self, data, prefix=""):
        """Flatten a plist dict into key-value pairs."""
        results = []
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    results.extend(self._flatten_plist(value, full_key))
                elif isinstance(value, list):
                    results.append((full_key, str(value)))
                else:
                    results.append((full_key, str(value)))
        return results

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=ArdConfigRecord)
    def config(self) -> Iterator[ArdConfigRecord]:
        """Parse Apple Remote Desktop configuration from plist files."""
        for path in self._plist_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue
                for setting, value in self._flatten_plist(data):
                    yield ArdConfigRecord(
                        setting=setting,
                        value=value,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ARD plist %s: %s", path, e)

    @export(record=ArdAccessRecord)
    def access(self) -> Iterator[ArdAccessRecord]:
        """Parse Apple Remote Desktop access entries from cliauth and rmdb."""
        if self._cliauth_path:
            try:
                with self._cliauth_path.open("r") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        yield ArdAccessRecord(
                            entry=line,
                            source=self._cliauth_path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing cliauth %s: %s", self._cliauth_path, e)

        if self._rmdb_path:
            try:
                conn, tmp = self._open_db(self._rmdb_path)
                try:
                    cursor = conn.cursor()
                    # Try to discover tables and read user/access data
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r["name"] for r in cursor.fetchall()]

                    for table in tables:
                        try:
                            cursor.execute(f"SELECT * FROM [{table}]")
                            for row in cursor:
                                entry_parts = []
                                for key in row:
                                    val = row[key]
                                    if val is not None:
                                        entry_parts.append(f"{key}={val}")
                                if entry_parts:
                                    yield ArdAccessRecord(
                                        entry="; ".join(entry_parts),
                                        source=self._rmdb_path,
                                        _target=self.target,
                                    )
                        except Exception:
                            continue
                finally:
                    conn.close()
                    tmp.close()
            except Exception as e:
                self.target.log.warning("Error parsing rmdb %s: %s", self._rmdb_path, e)
