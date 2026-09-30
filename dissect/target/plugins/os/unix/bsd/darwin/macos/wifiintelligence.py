from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

WifiContextRecord = TargetRecordDescriptor(
    "macos/wifiintelligence/wifi_events",
    [
        ("datetime", "ts"),
        ("varint", "behavior_type"),
        ("string", "behavior_identifier"),
        ("float", "time_since_previous"),
        ("path", "source"),
    ],
)

PersonInteractionRecord = TargetRecordDescriptor(
    "macos/wifiintelligence/person_interactions",
    [
        ("datetime", "ts"),
        ("string", "entity_identifier"),
        ("varint", "communication_mechanism"),
        ("string", "bundle_id"),
        ("path", "source"),
    ],
)

EntityAliasRecord = TargetRecordDescriptor(
    "macos/wifiintelligence/entity_aliases",
    [
        ("string", "alias"),
        ("string", "entity_type"),
        ("string", "signal_type"),
        ("float", "confidence"),
        ("path", "source"),
    ],
)


class WifiIntelligencePlugin(Plugin):
    """Plugin to parse Apple Intelligence Platform views.db.

    Contains wifi connect/disconnect events, person interaction mechanisms,
    and entity alias data used by Apple Intelligence features.

    Location: ~/Library/IntelligencePlatform/Artifacts/internal/views.db
    """

    __namespace__ = "wifiintelligence"

    DB_GLOB = "Users/*/Library/IntelligencePlatform/Artifacts/internal/views.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No IntelligencePlatform views.db found")

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

    def _cocoa_to_dt(self, ts):
        if ts is not None and ts > 0:
            try:
                return COCOA_EPOCH + timedelta(seconds=ts)
            except (ValueError, OverflowError):
                pass
        return None

    @export(record=WifiContextRecord)
    def wifi_events(self) -> Iterator[WifiContextRecord]:
        """Parse wifi connect/disconnect events from views.db."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_wifi(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing wifi events at %s: %s", db_path, e)

    def _parse_wifi(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM wifiContextEvents")
            except sqlite3.OperationalError:
                return
            for row in cursor:
                yield WifiContextRecord(
                    ts=self._cocoa_to_dt(row["timestamp"]),
                    behavior_type=row["behaviorType"],
                    behavior_identifier=row["behaviorIdentifier"] or "",
                    time_since_previous=row["timeSincePreviousEvent"] or 0.0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=PersonInteractionRecord)
    def person_interactions(self) -> Iterator[PersonInteractionRecord]:
        """Parse person interaction mechanisms from views.db."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_interactions(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing person interactions at %s: %s", db_path, e)

    def _parse_interactions(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM personInteractionMechanisms")
            except sqlite3.OperationalError:
                return
            for row in cursor:
                yield PersonInteractionRecord(
                    ts=self._cocoa_to_dt(row["interactionDate"]),
                    entity_identifier=row["entityIdentifier"] or "",
                    communication_mechanism=row["communicationMechanism"] or 0,
                    bundle_id=row["bundleID"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=EntityAliasRecord)
    def entity_aliases(self) -> Iterator[EntityAliasRecord]:
        """Parse entity aliases from views.db."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_aliases(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing entity aliases at %s: %s", db_path, e)

    def _parse_aliases(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM entity_alias")
            except sqlite3.OperationalError:
                return
            for row in cursor:
                yield EntityAliasRecord(
                    alias=row["alias"] or "",
                    entity_type=row["entity_type"] or "",
                    signal_type=row["signal_type"] or "",
                    confidence=row["confirmation_confidence"] or 0.0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
