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


AccountRecord = TargetRecordDescriptor(
    "macos/accounts/entries",
    [
        ("datetime", "ts_created"),
        ("string", "username"),
        ("string", "description"),
        ("string", "identifier"),
        ("string", "account_type"),
        ("string", "account_type_description"),
        ("string", "owning_bundle_id"),
        ("string", "authentication_type"),
        ("boolean", "active"),
        ("boolean", "authenticated"),
        ("boolean", "visible"),
        ("path", "source"),
    ],
)

AccountTypeRecord = TargetRecordDescriptor(
    "macos/accounts/types",
    [
        ("string", "identifier"),
        ("string", "description"),
        ("string", "owning_bundle_id"),
        ("string", "credential_type"),
        ("boolean", "supports_authentication"),
        ("boolean", "supports_multiple"),
        ("boolean", "obsolete"),
        ("path", "source"),
    ],
)

AccountPropertyRecord = TargetRecordDescriptor(
    "macos/accounts/properties",
    [
        ("string", "username"),
        ("string", "account_identifier"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)

CredentialRecord = TargetRecordDescriptor(
    "macos/accounts/credentials",
    [
        ("datetime", "ts_expiration"),
        ("string", "account_identifier"),
        ("string", "service_name"),
        ("boolean", "persistent"),
        ("path", "source"),
    ],
)


class MacOSAccountsPlugin(Plugin):
    """Plugin to parse macOS Internet Accounts (Accounts4.sqlite).

    Parses configured accounts (iCloud, GameCenter, iTunes, CalDAV, CardDAV,
    FindMyFriends, etc.), account types, properties, and credentials.

    Location: ~/Library/Accounts/Accounts4.sqlite
    """

    __namespace__ = "accounts"

    ACCOUNTS_GLOB = "Users/*/Library/Accounts/Accounts4.sqlite"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.ACCOUNTS_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No Accounts4.sqlite found")

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

    @export(record=AccountRecord)
    def entries(self) -> Iterator[AccountRecord]:
        """Parse configured Internet Accounts."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT a.ZUSERNAME, a.ZACCOUNTDESCRIPTION, a.ZIDENTIFIER,
                           a.ZOWNINGBUNDLEID, a.ZAUTHENTICATIONTYPE,
                           a.ZACTIVE, a.ZAUTHENTICATED, a.ZVISIBLE, a.ZDATE,
                           t.ZIDENTIFIER AS type_id,
                           t.ZACCOUNTTYPEDESCRIPTION AS type_desc
                    FROM ZACCOUNT a
                    LEFT JOIN ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK
                    ORDER BY a.ZDATE DESC
                """)
                for row in cursor:
                    yield AccountRecord(
                        ts_created=_cocoa_ts(row["ZDATE"]),
                        username=row["ZUSERNAME"] or "",
                        description=row["ZACCOUNTDESCRIPTION"] or "",
                        identifier=row["ZIDENTIFIER"] or "",
                        account_type=row["type_id"] or "",
                        account_type_description=row["type_desc"] or "",
                        owning_bundle_id=row["ZOWNINGBUNDLEID"] or "",
                        authentication_type=row["ZAUTHENTICATIONTYPE"] or "",
                        active=bool(row["ZACTIVE"]),
                        authenticated=bool(row["ZAUTHENTICATED"]),
                        visible=bool(row["ZVISIBLE"]),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing accounts %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=AccountTypeRecord)
    def types(self) -> Iterator[AccountTypeRecord]:
        """Parse registered account types."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZIDENTIFIER, ZACCOUNTTYPEDESCRIPTION, ZOWNINGBUNDLEID,
                           ZCREDENTIALTYPE, ZSUPPORTSAUTHENTICATION,
                           ZSUPPORTSMULTIPLEACCOUNTS, ZOBSOLETE
                    FROM ZACCOUNTTYPE
                    ORDER BY ZIDENTIFIER
                """)
                for row in cursor:
                    yield AccountTypeRecord(
                        identifier=row["ZIDENTIFIER"] or "",
                        description=row["ZACCOUNTTYPEDESCRIPTION"] or "",
                        owning_bundle_id=row["ZOWNINGBUNDLEID"] or "",
                        credential_type=row["ZCREDENTIALTYPE"] or "",
                        supports_authentication=bool(row["ZSUPPORTSAUTHENTICATION"]),
                        supports_multiple=bool(row["ZSUPPORTSMULTIPLEACCOUNTS"]),
                        obsolete=bool(row["ZOBSOLETE"]),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing account types %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=AccountPropertyRecord)
    def properties(self) -> Iterator[AccountPropertyRecord]:
        """Parse account properties (key-value pairs per account)."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT p.ZKEY, p.ZVALUE,
                           a.ZUSERNAME, a.ZIDENTIFIER
                    FROM ZACCOUNTPROPERTY p
                    LEFT JOIN ZACCOUNT a ON p.ZOWNER = a.Z_PK
                    ORDER BY a.ZUSERNAME, p.ZKEY
                """)
                for row in cursor:
                    val = row["ZVALUE"]
                    if isinstance(val, bytes):
                        try:
                            val = val.decode("utf-8")
                        except (UnicodeDecodeError, ValueError):
                            val = f"<binary {len(val)} bytes>"
                    else:
                        val = str(val) if val is not None else ""

                    yield AccountPropertyRecord(
                        username=row["ZUSERNAME"] or "",
                        account_identifier=row["ZIDENTIFIER"] or "",
                        key=row["ZKEY"] or "",
                        value=val,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing account properties %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=CredentialRecord)
    def credentials(self) -> Iterator[CredentialRecord]:
        """Parse credential items (service names, expiration — no secrets extracted)."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZACCOUNTIDENTIFIER, ZSERVICENAME,
                           ZPERSISTENT, ZEXPIRATIONDATE
                    FROM ZCREDENTIALITEM
                    ORDER BY ZEXPIRATIONDATE DESC
                """)
                for row in cursor:
                    yield CredentialRecord(
                        ts_expiration=_cocoa_ts(row["ZEXPIRATIONDATE"]),
                        account_identifier=row["ZACCOUNTIDENTIFIER"] or "",
                        service_name=row["ZSERVICENAME"] or "",
                        persistent=bool(row["ZPERSISTENT"]),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing credentials %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()
