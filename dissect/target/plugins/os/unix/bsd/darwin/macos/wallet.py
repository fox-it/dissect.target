from __future__ import annotations

import json
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
    if value:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


# ── Record Descriptors ───────────────────────────────────────────────────

WalletPassRecord = TargetRecordDescriptor(
    "macos/wallet/pass",
    [
        ("datetime", "ts_ingested"),
        ("datetime", "ts_modified"),
        ("string", "organization"),
        ("string", "serial_number"),
        ("string", "unique_id"),
        ("string", "pass_type"),
        ("varint", "card_type"),
        ("varint", "pass_flavor"),
        ("string", "primary_account_suffix"),
        ("path", "source"),
    ],
)

WalletPassDetailRecord = TargetRecordDescriptor(
    "macos/wallet/pass_detail",
    [
        ("string", "organization"),
        ("string", "serial_number"),
        ("string", "pass_category"),
        ("string", "field_section"),
        ("string", "field_key"),
        ("string", "field_label"),
        ("string", "field_value"),
        ("path", "source"),
    ],
)

WalletTransactionRecord = TargetRecordDescriptor(
    "macos/wallet/transaction",
    [
        ("datetime", "ts"),
        ("string", "merchant_name"),
        ("string", "currency_code"),
        ("varint", "amount"),
        ("string", "locality"),
        ("string", "administrative_area"),
        ("float", "location_latitude"),
        ("float", "location_longitude"),
        ("varint", "transaction_status"),
        ("varint", "transaction_type"),
        ("string", "peer_payment_handle"),
        ("path", "source"),
    ],
)

WalletPaymentCardRecord = TargetRecordDescriptor(
    "macos/wallet/payment_card",
    [
        ("string", "display_name"),
        ("string", "fpan_suffix"),
        ("string", "dpan_suffix"),
        ("varint", "state"),
        ("varint", "payment_type"),
        ("boolean", "supports_contactless"),
        ("boolean", "supports_in_app"),
        ("path", "source"),
    ],
)

WalletPassTypeRecord = TargetRecordDescriptor(
    "macos/wallet/pass_type",
    [
        ("string", "identifier"),
        ("string", "team_identifier"),
        ("path", "source"),
    ],
)


class AppleWalletPlugin(Plugin):
    """Plugin to parse Apple Wallet / Apple Pay data.

    Parses:
    - passes23.sqlite (passes, transactions, payment cards)
    - .pkpass directories (pass.json with detailed pass fields)

    Location: ~/Library/Passes/
    """

    __namespace__ = "wallet"

    DB_GLOB = "Users/*/Library/Passes/passes23.sqlite"
    CARDS_GLOB = "Users/*/Library/Passes/Cards/*.pkpass/pass.json"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))
        self._pass_json_paths = list(self.target.fs.path("/").glob(self.CARDS_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths and not self._pass_json_paths:
            raise UnsupportedPluginError("No Apple Wallet data found")

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

    # ── Passes (from database) ───────────────────────────────────────────

    @export(record=WalletPassRecord)
    def passes(self) -> Iterator[WalletPassRecord]:
        """Parse wallet passes (boarding passes, tickets, reservations, etc.)."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_passes(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing wallet passes at %s: %s", db_path, e)

    def _parse_passes(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT p.unique_id, p.organization_name, p.serial_number,
                       p.ingested_date, p.modified_date, p.card_type,
                       p.pass_flavor, p.primary_account_suffix,
                       pt.identifier AS pass_type_identifier
                FROM pass p
                LEFT JOIN pass_type pt ON p.pass_type_pid = pt.pid
                ORDER BY p.modified_date DESC
            """)
            for row in cursor:
                yield WalletPassRecord(
                    ts_ingested=_cocoa_ts(row["ingested_date"]),
                    ts_modified=_cocoa_ts(row["modified_date"]),
                    organization=row["organization_name"] or "",
                    serial_number=row["serial_number"] or "",
                    unique_id=row["unique_id"] or "",
                    pass_type=row["pass_type_identifier"] or "",
                    card_type=row["card_type"] or 0,
                    pass_flavor=row["pass_flavor"] or 0,
                    primary_account_suffix=row["primary_account_suffix"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Pass details (from pkpass/pass.json files) ───────────────────────

    @export(record=WalletPassDetailRecord)
    def pass_details(self) -> Iterator[WalletPassDetailRecord]:
        """Parse detailed pass fields from .pkpass directories (pass.json)."""
        for pass_json_path in self._pass_json_paths:
            try:
                yield from self._parse_pass_json(pass_json_path)
            except Exception as e:
                self.target.log.warning("Error parsing pass.json at %s: %s", pass_json_path, e)

    def _parse_pass_json(self, pass_json_path):
        with pass_json_path.open("rb") as fh:
            data = json.loads(fh.read())

        org = data.get("organizationName", "")
        serial = data.get("serialNumber", "")

        # Determine pass category
        pass_categories = ["boardingPass", "eventTicket", "coupon", "storeCard", "generic"]
        for category in pass_categories:
            if category not in data:
                continue

            fields = data[category]
            field_sections = [
                "headerFields",
                "primaryFields",
                "secondaryFields",
                "auxiliaryFields",
                "backFields",
            ]
            for section in field_sections:
                for field in fields.get(section, []):
                    yield WalletPassDetailRecord(
                        organization=org,
                        serial_number=serial,
                        pass_category=category,
                        field_section=section,
                        field_key=field.get("key", ""),
                        field_label=field.get("label", ""),
                        field_value=str(field.get("value", "")),
                        source=pass_json_path,
                        _target=self.target,
                    )

    # ── Transactions ─────────────────────────────────────────────────────

    @export(record=WalletTransactionRecord)
    def transactions(self) -> Iterator[WalletTransactionRecord]:
        """Parse Apple Pay payment transactions."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_transactions(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing transactions at %s: %s", db_path, e)

    def _parse_transactions(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT t.transaction_date, t.currency_code, t.amount,
                       t.locality, t.administrative_area,
                       t.location_latitude, t.location_longitude,
                       t.transaction_status, t.transaction_type,
                       ts.display_name AS merchant_name,
                       t.peer_payment_counterpart_handle
                FROM payment_transaction t
                LEFT JOIN transaction_source ts ON t.source_pid = ts.pid
                ORDER BY t.transaction_date DESC
            """)
            for row in cursor:
                yield WalletTransactionRecord(
                    ts=_cocoa_ts(row["transaction_date"]),
                    merchant_name=row["merchant_name"] or "",
                    currency_code=row["currency_code"] or "",
                    amount=row["amount"] or 0,
                    locality=row["locality"] or "",
                    administrative_area=row["administrative_area"] or "",
                    location_latitude=row["location_latitude"] or 0.0,
                    location_longitude=row["location_longitude"] or 0.0,
                    transaction_status=row["transaction_status"] or 0,
                    transaction_type=row["transaction_type"] or 0,
                    peer_payment_handle=row["peer_payment_counterpart_handle"] or "",
                    source=db_path,
                    _target=self.target,
                )
        except Exception:
            # Table may have different schema or not exist
            pass
        finally:
            conn.close()
            tmp.close()

    # ── Payment Cards ────────────────────────────────────────────────────

    @export(record=WalletPaymentCardRecord)
    def payment_cards(self) -> Iterator[WalletPaymentCardRecord]:
        """Parse registered Apple Pay payment cards."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_payment_cards(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing payment cards at %s: %s", db_path, e)

    def _parse_payment_cards(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT display_name, fpan_suffix, dpan_suffix, state,
                       payment_type, supports_contactless_payment,
                       supports_in_app_payment
                FROM payment_application
            """)
            for row in cursor:
                yield WalletPaymentCardRecord(
                    display_name=row["display_name"] or "",
                    fpan_suffix=row["fpan_suffix"] or "",
                    dpan_suffix=row["dpan_suffix"] or "",
                    state=row["state"] or 0,
                    payment_type=row["payment_type"] or 0,
                    supports_contactless=bool(row["supports_contactless_payment"]),
                    supports_in_app=bool(row["supports_in_app_payment"]),
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    # ── Pass Types ───────────────────────────────────────────────────────

    @export(record=WalletPassTypeRecord)
    def pass_types(self) -> Iterator[WalletPassTypeRecord]:
        """Parse registered pass type identifiers."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_pass_types(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing pass types at %s: %s", db_path, e)

    def _parse_pass_types(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT identifier, team_identifier FROM pass_type")
            for row in cursor:
                yield WalletPassTypeRecord(
                    identifier=row["identifier"] or "",
                    team_identifier=row["team_identifier"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
