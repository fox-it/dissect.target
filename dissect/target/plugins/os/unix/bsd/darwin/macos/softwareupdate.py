from __future__ import annotations

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


AppStoreInstallRecord = TargetRecordDescriptor(
    "macos/softwareupdate/appstore_installs",
    [
        ("datetime", "ts"),
        ("string", "bundle_id"),
        ("string", "bundle_name"),
        ("string", "bundle_version"),
        ("string", "vendor_name"),
        ("varint", "item_id"),
        ("varint", "phase"),
        ("boolean", "redownload"),
        ("path", "source"),
    ],
)

AppStoreUpdateRecord = TargetRecordDescriptor(
    "macos/softwareupdate/appstore_updates",
    [
        ("datetime", "install_date"),
        ("datetime", "release_date"),
        ("string", "bundle_id"),
        ("varint", "update_state"),
        ("varint", "store_item_id"),
        ("path", "source"),
    ],
)

ReceiptRecord = TargetRecordDescriptor(
    "macos/softwareupdate/receipts",
    [
        ("datetime", "install_date"),
        ("string", "package_identifier"),
        ("string", "package_version"),
        ("string", "package_filename"),
        ("string", "install_prefix_path"),
        ("string", "install_process_name"),
        ("path", "source"),
    ],
)

SoftwareUpdateConfigRecord = TargetRecordDescriptor(
    "macos/softwareupdate/config",
    [
        ("datetime", "last_successful_date"),
        ("boolean", "automatic_download"),
        ("boolean", "automatic_install"),
        ("boolean", "critical_update_install"),
        ("string", "recommended_updates"),
        ("path", "source"),
    ],
)


class SoftwareUpdatePlugin(Plugin):
    """Plugin to parse macOS software installation and update artifacts.

    Locations:
    - ~/Library/Caches/com.apple.appstoreagent/storeSystem.db
    - /var/db/receipts/*.plist
    - /Library/Preferences/com.apple.SoftwareUpdate.plist
    """

    __namespace__ = "softwareupdate"

    STORE_DB_GLOB = "Users/*/Library/Caches/com.apple.appstoreagent/storeSystem.db"
    RECEIPTS_GLOB = "var/db/receipts/*.plist"
    SWUPDATE_GLOB = "Library/Preferences/com.apple.SoftwareUpdate.plist"

    def __init__(self, target):
        super().__init__(target)
        self._store_dbs = list(self.target.fs.path("/").glob(self.STORE_DB_GLOB))
        self._receipts = list(self.target.fs.path("/").glob(self.RECEIPTS_GLOB))
        self._swupdate = list(self.target.fs.path("/").glob(self.SWUPDATE_GLOB))

    def check_compatible(self) -> None:
        if not self._store_dbs and not self._receipts and not self._swupdate:
            raise UnsupportedPluginError("No software update artifacts found")

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

    def _parse_datetime_str(self, val):
        if not val:
            return None
        try:
            return datetime.fromisoformat(str(val).replace(" +0000", "+00:00").replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
        try:
            return datetime.strptime(str(val), "%Y-%m-%d %H:%M:%S %z")
        except (ValueError, TypeError):
            return None

    @export(record=AppStoreInstallRecord)
    def appstore_installs(self) -> Iterator[AppStoreInstallRecord]:
        """Parse App Store install history from storeSystem.db."""
        for db_path in self._store_dbs:
            try:
                yield from self._parse_installs(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing storeSystem.db at %s: %s", db_path, e)

    def _parse_installs(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(app_install)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return
            cursor.execute("SELECT * FROM app_install")
            for row in cursor:
                ts = (
                    self._parse_datetime_str(row["install_finished_timestamp"])
                    if "install_finished_timestamp" in columns
                    else None
                )
                if not ts:
                    ts = self._parse_datetime_str(row["timestamp"]) if "timestamp" in columns else None
                yield AppStoreInstallRecord(
                    ts=ts,
                    bundle_id=row["bundle_id"] if "bundle_id" in columns else "",
                    bundle_name=row["bundle_name"] if "bundle_name" in columns else "",
                    bundle_version=row["bundle_version"] if "bundle_version" in columns else "",
                    vendor_name=row["vendor_name"] if "vendor_name" in columns else "",
                    item_id=row["item_id"] if "item_id" in columns else 0,
                    phase=row["phase"] if "phase" in columns else 0,
                    redownload=bool(row["redownload"]) if "redownload" in columns else False,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=AppStoreUpdateRecord)
    def appstore_updates(self) -> Iterator[AppStoreUpdateRecord]:
        """Parse App Store update history from storeSystem.db."""
        for db_path in self._store_dbs:
            try:
                yield from self._parse_updates(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing storeSystem.db updates at %s: %s", db_path, e)

    def _parse_updates(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(app_updates)")
            columns = [col["name"] for col in cursor.fetchall()]
            if not columns:
                return
            cursor.execute("SELECT * FROM app_updates")
            for row in cursor:
                yield AppStoreUpdateRecord(
                    install_date=self._parse_datetime_str(row["install_date"]) if "install_date" in columns else None,
                    release_date=self._parse_datetime_str(row["release_date"]) if "release_date" in columns else None,
                    bundle_id=row["bundle_id"] if "bundle_id" in columns else "",
                    update_state=row["update_state"] if "update_state" in columns else 0,
                    store_item_id=row["store_item_id"] if "store_item_id" in columns else 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=ReceiptRecord)
    def receipts(self) -> Iterator[ReceiptRecord]:
        """Parse software installation receipts from /var/db/receipts/."""
        for plist_path in self._receipts:
            try:
                with plist_path.open("rb") as fh:
                    data = plistlib.loads(fh.read())
                install_date = data.get("InstallDate")
                if isinstance(install_date, datetime):
                    install_date = (
                        install_date.replace(tzinfo=timezone.utc) if install_date.tzinfo is None else install_date
                    )
                yield ReceiptRecord(
                    install_date=install_date,
                    package_identifier=data.get("PackageIdentifier", ""),
                    package_version=str(data.get("PackageVersion", "")),
                    package_filename=data.get("PackageFileName", ""),
                    install_prefix_path=data.get("InstallPrefixPath", ""),
                    install_process_name=data.get("InstallProcessName", ""),
                    source=plist_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing receipt at %s: %s", plist_path, e)

    @export(record=SoftwareUpdateConfigRecord)
    def config(self) -> Iterator[SoftwareUpdateConfigRecord]:
        """Parse macOS Software Update configuration."""
        for plist_path in self._swupdate:
            try:
                with plist_path.open("rb") as fh:
                    data = plistlib.loads(fh.read())
                last_date = data.get("LastSuccessfulDate")
                if isinstance(last_date, datetime):
                    last_date = last_date.replace(tzinfo=timezone.utc) if last_date.tzinfo is None else last_date
                recommended = data.get("RecommendedUpdates", [])
                rec_str = "; ".join(
                    f"{u.get('Display Name', '')} {u.get('Display Version', '')}"
                    for u in recommended
                    if isinstance(u, dict)
                )
                yield SoftwareUpdateConfigRecord(
                    last_successful_date=last_date,
                    automatic_download=bool(data.get("AutomaticDownload", False)),
                    automatic_install=bool(data.get("AutomaticallyInstallMacOSUpdates", False)),
                    critical_update_install=bool(data.get("CriticalUpdateInstall", False)),
                    recommended_updates=rec_str,
                    source=plist_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing SoftwareUpdate plist at %s: %s", plist_path, e)
