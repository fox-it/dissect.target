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


# CoreDuet timestamps: Cocoa epoch (seconds since 2001-01-01)
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

MECHANISM_MAP = {
    0: "unknown",
    1: "mail",
    2: "messages",
    3: "calls",
    4: "third_party_messaging",
    5: "calendar",
    6: "spotlight",
    7: "safari",
    8: "siri",
    12: "messages",
    16: "calls",
    17: "facetime",
}

DIRECTION_MAP = {
    0: "incoming",
    1: "outgoing",
}


def _cocoa_ts(value):
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


InteractionRecord = TargetRecordDescriptor(
    "macos/interactions/entries",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "bundle_id"),
        ("string", "target_bundle_id"),
        ("string", "mechanism"),
        ("varint", "mechanism_id"),
        ("string", "direction"),
        ("boolean", "is_response"),
        ("varint", "recipient_count"),
        ("string", "sender_name"),
        ("string", "sender_identifier"),
        ("string", "group_name"),
        ("string", "account"),
        ("string", "domain_identifier"),
        ("string", "content_url"),
        ("string", "uuid"),
        ("path", "source"),
    ],
)

ContactRecord = TargetRecordDescriptor(
    "macos/interactions/contacts",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_first_incoming"),
        ("datetime", "ts_last_incoming"),
        ("datetime", "ts_first_outgoing"),
        ("datetime", "ts_last_outgoing"),
        ("string", "display_name"),
        ("string", "identifier"),
        ("string", "custom_identifier"),
        ("string", "person_id"),
        ("varint", "incoming_sender_count"),
        ("varint", "incoming_recipient_count"),
        ("varint", "outgoing_recipient_count"),
        ("varint", "contact_type"),
        ("path", "source"),
    ],
)


class InteractionsPlugin(Plugin):
    """Plugin to parse macOS CoreDuet interactionC.db.

    Parses communication interactions tracked by CoreDuet/Siri Intelligence:
    Messages, FaceTime, WhatsApp, Calendar invites, phone calls, and more.

    Locations:
    - /private/var/db/CoreDuet/People/interactionC.db (system-wide, needs root on live)
    - ~/Library/Application Support/com.apple.DuetExpertCenter/People/interactionC.db (per-user)
    """

    __namespace__ = "interactions"

    DB_GLOBS = [
        "private/var/db/CoreDuet/People/interactionC.db",
        "Users/*/Library/Application Support/com.apple.DuetExpertCenter/People/interactionC.db",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._paths = []
        root = self.target.fs.path("/")
        for pattern in self.DB_GLOBS:
            self._paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No interactionC.db found")

    def _open_db(self, path):
        with path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = path.parent.joinpath(path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=InteractionRecord)
    def entries(self) -> Iterator[InteractionRecord]:
        """Parse communication interactions from interactionC.db."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT i.ZSTARTDATE, i.ZENDDATE, i.ZCREATIONDATE,
                           i.ZBUNDLEID, i.ZTARGETBUNDLEID,
                           i.ZMECHANISM, i.ZDIRECTION, i.ZISRESPONSE,
                           i.ZRECIPIENTCOUNT, i.ZGROUPNAME,
                           i.ZACCOUNT, i.ZDOMAINIDENTIFIER,
                           i.ZCONTENTURL, i.ZUUID,
                           c.ZDISPLAYNAME AS sender_name,
                           c.ZIDENTIFIER AS sender_identifier
                    FROM ZINTERACTIONS i
                    LEFT JOIN ZCONTACTS c ON i.ZSENDER = c.Z_PK
                    ORDER BY i.ZSTARTDATE DESC
                """)
                for row in cursor:
                    mech_id = row["ZMECHANISM"] or 0
                    yield InteractionRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        bundle_id=row["ZBUNDLEID"] or "",
                        target_bundle_id=row["ZTARGETBUNDLEID"] or "",
                        mechanism=MECHANISM_MAP.get(mech_id, f"unknown_{mech_id}"),
                        mechanism_id=mech_id,
                        direction=DIRECTION_MAP.get(row["ZDIRECTION"] or 0, "unknown"),
                        is_response=bool(row["ZISRESPONSE"]),
                        recipient_count=row["ZRECIPIENTCOUNT"] or 0,
                        sender_name=row["sender_name"] or "",
                        sender_identifier=row["sender_identifier"] or "",
                        group_name=row["ZGROUPNAME"] or "",
                        account=row["ZACCOUNT"] or "",
                        domain_identifier=row["ZDOMAINIDENTIFIER"] or "",
                        content_url=row["ZCONTENTURL"] or "",
                        uuid=row["ZUUID"] or "",
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing interactions %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=ContactRecord)
    def contacts(self) -> Iterator[ContactRecord]:
        """Parse contact entries from interactionC.db."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZCREATIONDATE, ZDISPLAYNAME, ZIDENTIFIER,
                           ZCUSTOMIDENTIFIER, ZPERSONID, ZTYPE,
                           ZINCOMINGSENDERCOUNT, ZINCOMINGRECIPIENTCOUNT,
                           ZOUTGOINGRECIPIENTCOUNT,
                           ZFIRSTINCOMINGSENDERDATE, ZLASTINCOMINGSENDERDATE,
                           ZFIRSTOUTGOINGRECIPIENTDATE, ZLASTOUTGOINGRECIPIENTDATE
                    FROM ZCONTACTS
                    ORDER BY ZLASTINCOMINGSENDERDATE DESC
                """)
                for row in cursor:
                    yield ContactRecord(
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        ts_first_incoming=_cocoa_ts(row["ZFIRSTINCOMINGSENDERDATE"]),
                        ts_last_incoming=_cocoa_ts(row["ZLASTINCOMINGSENDERDATE"]),
                        ts_first_outgoing=_cocoa_ts(row["ZFIRSTOUTGOINGRECIPIENTDATE"]),
                        ts_last_outgoing=_cocoa_ts(row["ZLASTOUTGOINGRECIPIENTDATE"]),
                        display_name=row["ZDISPLAYNAME"] or "",
                        identifier=row["ZIDENTIFIER"] or "",
                        custom_identifier=row["ZCUSTOMIDENTIFIER"] or "",
                        person_id=row["ZPERSONID"] or "",
                        incoming_sender_count=row["ZINCOMINGSENDERCOUNT"] or 0,
                        incoming_recipient_count=row["ZINCOMINGRECIPIENTCOUNT"] or 0,
                        outgoing_recipient_count=row["ZOUTGOINGRECIPIENTCOUNT"] or 0,
                        contact_type=row["ZTYPE"] or 0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing contacts %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()
