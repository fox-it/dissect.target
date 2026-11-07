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


def _cocoa_ts(value):
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


ContactRecord = TargetRecordDescriptor(
    "macos/addressbook/contacts",
    [
        ("datetime", "ts_created"),
        ("datetime", "ts_modified"),
        ("string", "first_name"),
        ("string", "last_name"),
        ("string", "organization"),
        ("string", "job_title"),
        ("string", "nickname"),
        ("string", "unique_id"),
        ("path", "source"),
    ],
)

EmailRecord = TargetRecordDescriptor(
    "macos/addressbook/emails",
    [
        ("string", "address"),
        ("string", "label"),
        ("string", "contact_name"),
        ("path", "source"),
    ],
)

PhoneRecord = TargetRecordDescriptor(
    "macos/addressbook/phones",
    [
        ("string", "full_number"),
        ("string", "label"),
        ("string", "country_code"),
        ("string", "contact_name"),
        ("path", "source"),
    ],
)


class AddressBookPlugin(Plugin):
    """Plugin to parse macOS AddressBook contacts database.

    Parses contacts, email addresses, and phone numbers from:
    ~/Library/Application Support/AddressBook/AddressBook-v22.abcddb
    """

    __namespace__ = "addressbook"

    DB_GLOB = "Users/*/Library/Application Support/AddressBook/AddressBook-v22.abcddb"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No AddressBook database found")

    def _open_db(self, path):
        with path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM if they exist
        for suffix in ["-wal", "-shm"]:
            src = path.parent.joinpath(path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=ContactRecord)
    def contacts(self) -> Iterator[ContactRecord]:
        """Parse contacts from AddressBook ZABCDRECORD table."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZCREATIONDATE, ZMODIFICATIONDATE,
                           ZFIRSTNAME, ZLASTNAME, ZORGANIZATION,
                           ZJOBTITLE, ZNICKNAME, ZUNIQUEID
                    FROM ZABCDRECORD
                """)
                for row in cursor:
                    yield ContactRecord(
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        ts_modified=_cocoa_ts(row["ZMODIFICATIONDATE"]),
                        first_name=row["ZFIRSTNAME"] or "",
                        last_name=row["ZLASTNAME"] or "",
                        organization=row["ZORGANIZATION"] or "",
                        job_title=row["ZJOBTITLE"] or "",
                        nickname=row["ZNICKNAME"] or "",
                        unique_id=row["ZUNIQUEID"] or "",
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing contacts %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=EmailRecord)
    def emails(self) -> Iterator[EmailRecord]:
        """Parse email addresses joined with contact names from AddressBook."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT e.ZADDRESS, e.ZLABEL,
                           r.ZFIRSTNAME, r.ZLASTNAME
                    FROM ZABCDEMAILADDRESS e
                    LEFT JOIN ZABCDRECORD r ON e.ZOWNER = r.Z_PK
                """)
                for row in cursor:
                    first = row["ZFIRSTNAME"] or ""
                    last = row["ZLASTNAME"] or ""
                    contact_name = f"{first} {last}".strip()

                    yield EmailRecord(
                        address=row["ZADDRESS"] or "",
                        label=row["ZLABEL"] or "",
                        contact_name=contact_name,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing emails %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=PhoneRecord)
    def phones(self) -> Iterator[PhoneRecord]:
        """Parse phone numbers joined with contact names from AddressBook."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT p.ZFULLNUMBER, p.ZLABEL, p.ZCOUNTRYCODE,
                           r.ZFIRSTNAME, r.ZLASTNAME
                    FROM ZABCDPHONENUMBER p
                    LEFT JOIN ZABCDRECORD r ON p.ZOWNER = r.Z_PK
                """)
                for row in cursor:
                    first = row["ZFIRSTNAME"] or ""
                    last = row["ZLASTNAME"] or ""
                    contact_name = f"{first} {last}".strip()

                    yield PhoneRecord(
                        full_number=row["ZFULLNUMBER"] or "",
                        label=row["ZLABEL"] or "",
                        country_code=row["ZCOUNTRYCODE"] or "",
                        contact_name=contact_name,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing phones %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()
