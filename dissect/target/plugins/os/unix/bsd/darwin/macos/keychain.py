from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

KeychainRecord = TargetRecordDescriptor(
    "macos/keychain",
    [
        ("string", "table"),
        ("varint", "row_id"),
        ("float", "cdat"),
        ("float", "mdat"),
        ("string", "desc"),
        ("string", "icmt"),
        ("string", "crtr"),
        ("string", "type"),
        ("string", "scrp"),
        ("string", "labl"),
        ("string", "alis"),
        ("varint", "invi"),
        ("varint", "nega"),
        ("varint", "cusi"),
        ("varint", "prot"),
        ("string", "acct"),
        ("string", "svce"),
        ("string", "gena"),
        ("string", "data"),
        ("string", "agrp"),
        ("string", "pdmn"),
        ("varint", "sync"),
        ("varint", "tomb"),
        ("string", "sha1"),
        ("string", "vwht"),
        ("string", "tkid"),
        ("string", "musr"),
        ("string", "UUID"),
        ("varint", "sysb"),
        ("string", "pcss"),
        ("string", "pcsk"),
        ("string", "pcsi"),
        ("string", "persistref"),
        ("varint", "clip"),
        ("string", "ggrp"),
        ("path", "source"),
    ],
)

SqliteSequenceRecord = TargetRecordDescriptor(
    "macos/keychain/sqlite_sequence",
    [
        ("string", "table"),
        ("string", "name"),
        ("varint", "seq"),
        ("path", "source"),
    ],
)

TVersionRecord = TargetRecordDescriptor(
    "macos/keychain/t_version",
    [
        ("string", "table"),
        ("varint", "row_id"),
        ("string", "version"),
        ("varint", "minor"),
        ("path", "source"),
    ],
)

MetaDataKeysRecord = TargetRecordDescriptor(
    "macos/keychain/meta_data_keys",
    [
        ("string", "table"),
        ("string", "keyclass"),
        ("string", "actual_key_class"),
        ("string", "data"),
        ("path", "source"),
    ],
)

KeychainRecords = (
    KeychainRecord,
    SqliteSequenceRecord,
    TVersionRecord,
    MetaDataKeysRecord,
)

FIELD_MAPPINGS = {
    "actualKeyclass": "actual_key_class",
    "rowid": "row_id",
}


class KeychainPlugin(Plugin):
    """macOS keychain plugin."""

    USER_PATH = ("Library/Keychains/*/keychain-2.db",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No keychain-2.db files found")

    def _find_files(self) -> None:
        for _, path in _build_userdirs(self, self.USER_PATH):
            self.files.add(path)

    @export(record=KeychainRecords)
    def keychain(
        self,
    ) -> Iterator[KeychainRecords]:
        """Yield keychain information."""
        yield from build_sqlite_records(self, self.files, KeychainRecords, field_mappings=FIELD_MAPPINGS)

        # Still missing cert, outgoingqueue, incomingqueue, synckeys, ckmirror, currentkeys,
        # ckstate, item_backup, backup_keybag, ckmanifest, pending_manifest, ckmanifest_leaf,
        # backup_keyarchive, currentkeyarchives, archived_key_backup, pending_manifest_leaf,
        # currentitems, ckdevicestate, tlkshare, sharingIncomingQueue,
        # sharingMirror, sharingOutgoingQueue tables
