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


# ── Record Descriptors ───────────────────────────────────────────────────

KextInfoRecord = TargetRecordDescriptor(
    "macos/kext/installed",
    [
        ("string", "bundle_id"),
        ("string", "bundle_name"),
        ("string", "bundle_version"),
        ("string", "short_version"),
        ("string", "executable"),
        ("string", "kext_location"),
        ("path", "source"),
    ],
)

KextLoadHistoryRecord = TargetRecordDescriptor(
    "macos/kext/load_history",
    [
        ("string", "bundle_id"),
        ("string", "team_id"),
        ("string", "kext_path"),
        ("string", "boot_uuid"),
        ("string", "created_at"),
        ("string", "last_seen"),
        ("varint", "flags"),
        ("string", "cdhash"),
        ("path", "source"),
    ],
)

KextPolicyRecord = TargetRecordDescriptor(
    "macos/kext/policy",
    [
        ("string", "bundle_id"),
        ("string", "team_id"),
        ("string", "developer_name"),
        ("boolean", "allowed"),
        ("varint", "flags"),
        ("string", "policy_type"),
        ("path", "source"),
    ],
)

KextClassificationRecord = TargetRecordDescriptor(
    "macos/kext/classification",
    [
        ("string", "vendor"),
        ("string", "bundle_id"),
        ("string", "team_id"),
        ("path", "source"),
    ],
)

SystemExtensionRecord = TargetRecordDescriptor(
    "macos/kext/system_extensions",
    [
        ("string", "identifier"),
        ("string", "team_id"),
        ("string", "short_version"),
        ("string", "bundle_version"),
        ("string", "state"),
        ("string", "category"),
        ("string", "container_app"),
        ("string", "origin_path"),
        ("string", "unique_id"),
        ("path", "source"),
    ],
)


class KextPlugin(Plugin):
    """Plugin to parse macOS kernel extensions and system extensions.

    Comprehensive parsing of all kext/sysext-related artifacts:
    - /Library/Extensions/*.kext — third-party kexts
    - /System/Library/Extensions/*.kext — Apple kexts
    - /Library/Apple/System/Library/Extensions/*.kext — Apple-provided third-party kexts
    - /Library/StagedExtensions/*/*.kext — staged (pre-boot validated) kexts
    - /Library/SystemExtensions/db.plist — system extension database
    - /private/var/db/SystemPolicyConfiguration/KextPolicy — kext approval policy DB
    - /private/var/db/SystemPolicyConfiguration/KextClassification.plist — vendor kext classifications
    """

    __namespace__ = "kext"

    # Kext Info.plist locations
    KEXT_GLOBS = [
        "Library/Extensions/*/Contents/Info.plist",
        "System/Library/Extensions/*/Contents/Info.plist",
        "Library/Apple/System/Library/Extensions/*/Contents/Info.plist",
        "Library/StagedExtensions/Library/Extensions/*/Contents/Info.plist",
        "Library/StagedExtensions/Library/Filesystems/*/Contents/Extensions/*/Contents/Info.plist",
    ]

    KEXT_POLICY_PATHS = [
        "private/var/db/SystemPolicyConfiguration/KextPolicy",
    ]

    KEXT_CLASSIFICATION_PATHS = [
        "private/var/db/SystemPolicyConfiguration/KextClassification.plist",
    ]

    SYSEXT_DB_PATHS = [
        "Library/SystemExtensions/db.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        root = self.target.fs.path("/")

        self._kext_plists = []
        for pattern in self.KEXT_GLOBS:
            self._kext_plists.extend(root.glob(pattern))

        self._kext_policy_paths = [root.joinpath(p) for p in self.KEXT_POLICY_PATHS if root.joinpath(p).exists()]

        self._classification_paths = [
            root.joinpath(p) for p in self.KEXT_CLASSIFICATION_PATHS if root.joinpath(p).exists()
        ]

        self._sysext_paths = [root.joinpath(p) for p in self.SYSEXT_DB_PATHS if root.joinpath(p).exists()]

    def check_compatible(self) -> None:
        if not self._kext_plists and not self._kext_policy_paths and not self._sysext_paths:
            raise UnsupportedPluginError("No kernel extension data found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _open_db(self, path):
        with path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM files if they exist (data may live in WAL)
        extras = []
        for suffix in ["-wal", "-shm"]:
            src = path.parent.joinpath(path.name + suffix)
            if src.exists():
                extra_path = tmp.name + suffix
                with src.open("rb") as sf, open(extra_path, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())
                extras.append(extra_path)

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    # ── Installed Kexts ──────────────────────────────────────────────────

    @export(record=KextInfoRecord)
    def installed(self) -> Iterator[KextInfoRecord]:
        """Parse installed kernel extensions from Info.plist files across all kext locations."""
        for plist_path in sorted(self._kext_plists):
            try:
                data = self._read_plist(plist_path)
                if data is None:
                    continue

                kext_dir = str(plist_path.parent.parent)

                yield KextInfoRecord(
                    bundle_id=data.get("CFBundleIdentifier", ""),
                    bundle_name=data.get("CFBundleName", data.get("CFBundleExecutable", "")),
                    bundle_version=data.get("CFBundleVersion", ""),
                    short_version=data.get("CFBundleShortVersionString", ""),
                    executable=data.get("CFBundleExecutable", ""),
                    kext_location=kext_dir,
                    source=plist_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing kext %s: %s", plist_path, e)

    @staticmethod
    def _table_exists(conn, name):
        cur = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
        return cur.fetchone() is not None

    # ── Kext Load History ────────────────────────────────────────────────

    @export(record=KextLoadHistoryRecord)
    def load_history(self) -> Iterator[KextLoadHistoryRecord]:
        """Parse kext load history from the legacy KextPolicy database.

        On macOS 11+ user-mode kext loading was deprecated in favour of System
        Extensions, and on macOS 15 the KextPolicy SQLite file is shipped empty
        (no tables). This function returns nothing on those systems by design —
        use ``kext.system_extensions`` for the modern equivalent.
        """
        for path in self._kext_policy_paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                if not self._table_exists(conn, "kext_load_history_v3"):
                    # macOS 15 ships KextPolicy with no tables — feature retired.
                    self.target.log.debug(
                        "%s has no kext_load_history_v3 table; kext loading is deprecated on this macOS version", path
                    )
                    continue

                cursor = conn.cursor()
                cursor.execute("""
                    SELECT path, team_id, bundle_id, boot_uuid,
                           created_at, last_seen, flags, cdhash
                    FROM kext_load_history_v3
                    ORDER BY last_seen DESC
                """)
                for row in cursor:
                    yield KextLoadHistoryRecord(
                        bundle_id=row["bundle_id"] or "",
                        team_id=row["team_id"] or "",
                        kext_path=row["path"] or "",
                        boot_uuid=row["boot_uuid"] or "",
                        created_at=row["created_at"] or "",
                        last_seen=row["last_seen"] or "",
                        flags=row["flags"] or 0,
                        cdhash=row["cdhash"] or "",
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing kext load history %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Kext Policy ──────────────────────────────────────────────────────

    @export(record=KextPolicyRecord)
    def policy(self) -> Iterator[KextPolicyRecord]:
        """Parse kext approval policies from the legacy KextPolicy database.

        On macOS 15 the KextPolicy SQLite file is empty — kext approval has
        been retired alongside user-mode kext loading. Returns nothing on
        those systems by design.
        """
        for path in self._kext_policy_paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                if not self._table_exists(conn, "kext_policy"):
                    # macOS 15 ships KextPolicy with no tables — feature retired.
                    self.target.log.debug(
                        "%s has no kext_policy table; kext approval is deprecated on this macOS version", path
                    )
                    continue

                cursor = conn.cursor()
                cursor.execute("""
                    SELECT team_id, bundle_id, allowed, developer_name, flags
                    FROM kext_policy
                """)
                for row in cursor:
                    yield KextPolicyRecord(
                        bundle_id=row["bundle_id"] or "",
                        team_id=row["team_id"] or "",
                        developer_name=row["developer_name"] or "",
                        allowed=bool(row["allowed"]),
                        flags=row["flags"] or 0,
                        policy_type="user_approved",
                        source=path,
                        _target=self.target,
                    )

                if self._table_exists(conn, "kext_policy_mdm"):
                    cursor.execute("""
                        SELECT team_id, bundle_id, allowed, payload_uuid
                        FROM kext_policy_mdm
                    """)
                    for row in cursor:
                        yield KextPolicyRecord(
                            bundle_id=row["bundle_id"] or "",
                            team_id=row["team_id"] or "",
                            developer_name=row["payload_uuid"] or "",
                            allowed=bool(row["allowed"]),
                            flags=0,
                            policy_type="mdm",
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing kext policy %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Kext Classification ──────────────────────────────────────────────

    @export(record=KextClassificationRecord)
    def classification(self) -> Iterator[KextClassificationRecord]:
        """Parse kext vendor classifications from KextClassification.plist."""
        for path in self._classification_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                products = data.get("Products", {})
                for vendor, kexts in products.items():
                    if not isinstance(kexts, list):
                        continue
                    for kext in kexts:
                        yield KextClassificationRecord(
                            vendor=vendor,
                            bundle_id=kext.get("BundleID", ""),
                            team_id=kext.get("TeamID", ""),
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing kext classification %s: %s", path, e)

    # ── System Extensions ────────────────────────────────────────────────

    @export(record=SystemExtensionRecord)
    def system_extensions(self) -> Iterator[SystemExtensionRecord]:
        """Parse system extensions from /Library/SystemExtensions/db.plist."""
        for path in self._sysext_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                for ext in data.get("extensions", []):
                    version = ext.get("bundleVersion", {})
                    categories = ext.get("categories", [])
                    container = ext.get("container", {})

                    yield SystemExtensionRecord(
                        identifier=ext.get("identifier", ""),
                        team_id=ext.get("teamID", ""),
                        short_version=version.get("CFBundleShortVersionString", ""),
                        bundle_version=version.get("CFBundleVersion", ""),
                        state=ext.get("state", ""),
                        category=categories[0] if categories else "",
                        container_app=container.get("bundlePath", ""),
                        origin_path=ext.get("originPath", ""),
                        unique_id=ext.get("uniqueID", ""),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing system extensions %s: %s", path, e)
