from __future__ import annotations

import contextlib
import plistlib
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


BackupInfoRecord = TargetRecordDescriptor(
    "macos/idevicebackup/info",
    [
        ("datetime", "last_backup_date"),
        ("string", "device_name"),
        ("string", "display_name"),
        ("string", "product_type"),
        ("string", "product_version"),
        ("string", "serial_number"),
        ("string", "build_version"),
        ("string", "unique_identifier"),
        ("string", "iccid"),
        ("string", "imei"),
        ("string", "meid"),
        ("string", "phone_number"),
        ("boolean", "is_encrypted"),
        ("path", "source"),
    ],
)

BackupFileRecord = TargetRecordDescriptor(
    "macos/idevicebackup/files",
    [
        ("datetime", "modified"),
        ("string", "file_id"),
        ("string", "relative_path"),
        ("string", "file_domain"),
        ("varint", "file_size"),
        ("varint", "flags"),
        ("path", "source"),
    ],
)


class IDeviceBackupPlugin(Plugin):
    """Plugin to parse iOS device backup metadata from macOS.

    Parses Info.plist (device info) and Manifest.db (backed up file list)
    from iTunes/Finder iOS backup directories.

    Location: ~/Library/Application Support/MobileSync/Backup/
    """

    __namespace__ = "idevicebackup"

    BACKUP_GLOB = "Users/*/Library/Application Support/MobileSync/Backup/*"

    def __init__(self, target):
        super().__init__(target)
        self._backup_dirs = []
        for d in self.target.fs.path("/").glob(self.BACKUP_GLOB):
            # Check if this looks like a backup directory (has Info.plist or Manifest.db)
            info = d.joinpath("Info.plist")
            manifest = d.joinpath("Manifest.db")
            if info.exists() or manifest.exists():
                self._backup_dirs.append(d)

    def check_compatible(self) -> None:
        if not self._backup_dirs:
            raise UnsupportedPluginError("No iOS device backups found")

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

    @export(record=BackupInfoRecord)
    def info(self) -> Iterator[BackupInfoRecord]:
        """Parse iOS backup device information from Info.plist."""
        for backup_dir in self._backup_dirs:
            info_path = backup_dir.joinpath("Info.plist")
            if not info_path.exists():
                continue
            try:
                with info_path.open("rb") as fh:
                    data = plistlib.loads(fh.read())
                last_backup = data.get("Last Backup Date")
                if isinstance(last_backup, datetime):
                    last_backup = (
                        last_backup.replace(tzinfo=timezone.utc) if last_backup.tzinfo is None else last_backup
                    )
                yield BackupInfoRecord(
                    last_backup_date=last_backup,
                    device_name=data.get("Device Name", ""),
                    display_name=data.get("Display Name", ""),
                    product_type=data.get("Product Type", ""),
                    product_version=data.get("Product Version", ""),
                    serial_number=data.get("Serial Number", ""),
                    build_version=data.get("Build Version", ""),
                    unique_identifier=data.get("Unique Identifier", data.get("Target Identifier", "")),
                    iccid=data.get("ICCID", ""),
                    imei=data.get("IMEI", ""),
                    meid=data.get("MEID", ""),
                    phone_number=data.get("Phone Number", ""),
                    is_encrypted=bool(data.get("WasPasscodeSet", False)),
                    source=info_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing backup Info.plist at %s: %s", info_path, e)

    @export(record=BackupFileRecord)
    def files(self) -> Iterator[BackupFileRecord]:
        """Parse backed up file list from Manifest.db."""
        for backup_dir in self._backup_dirs:
            manifest_path = backup_dir.joinpath("Manifest.db")
            if not manifest_path.exists():
                continue
            try:
                yield from self._parse_manifest(manifest_path)
            except Exception as e:
                self.target.log.warning("Error parsing Manifest.db at %s: %s", manifest_path, e)

    def _parse_manifest(self, manifest_path):
        conn, tmp = self._open_db(manifest_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(Files)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return

            cursor.execute("SELECT * FROM Files")
            for row in cursor:
                # relativePath and domain are the key fields
                modified = None
                flags = 0

                # The file blob contains a plist with metadata
                file_blob = row["file"] if "file" in columns else None
                if file_blob and isinstance(file_blob, bytes):
                    try:
                        file_info = plistlib.loads(file_blob)
                        if isinstance(file_info, dict):
                            objects = file_info.get("$objects", [])
                            # Try to extract LastModified from the plist
                            for obj in objects:
                                if isinstance(obj, dict):
                                    if "LastModified" in obj:
                                        ts = obj["LastModified"]
                                        if isinstance(ts, (int, float)) and ts > 0:
                                            with contextlib.suppress(ValueError, OSError):
                                                modified = datetime.fromtimestamp(ts, tz=timezone.utc)
                                    if "Flags" in obj:
                                        flags = obj.get("Flags", 0) or 0
                                    if "Size" in obj:
                                        obj.get("Size", 0) or 0
                    except Exception:
                        pass

                file_size_val = 0
                try:
                    if file_blob and isinstance(file_blob, bytes):
                        file_info = plistlib.loads(file_blob)
                        if isinstance(file_info, dict):
                            for obj in file_info.get("$objects", []):
                                if isinstance(obj, dict) and "Size" in obj:
                                    file_size_val = obj.get("Size", 0) or 0
                                    break
                except Exception:
                    pass

                yield BackupFileRecord(
                    modified=modified,
                    file_id=row["fileID"] if "fileID" in columns else "",
                    relative_path=row["relativePath"] if "relativePath" in columns and row["relativePath"] else "",
                    file_domain=row["domain"] if "domain" in columns and row["domain"] else "",
                    file_size=file_size_val,
                    flags=flags,
                    source=manifest_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
