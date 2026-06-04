from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

GenpRecord = TargetRecordDescriptor(
    "macos/keychain/genp",
    [
        ("string", "table"),
        ("varint", "row_id"),
        ("datetime", "cdat"),
        ("datetime", "mdat"),
        ("bytes", "desc"),
        ("bytes", "icmt"),
        ("varint", "crtr"),
        ("varint", "keychain_type"),
        ("varint", "scrp"),
        ("bytes", "labl"),
        ("bytes", "alis"),
        ("varint", "invi"),
        ("varint", "nega"),
        ("varint", "cusi"),
        ("bytes", "prot"),
        ("bytes", "acct"),
        ("bytes", "svce"),
        ("bytes", "gena"),
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
        ("varint", "pcss"),
        ("bytes", "pcsk"),
        ("bytes", "pcsi"),
        ("bytes", "persistref"),
        ("varint", "clip"),
        ("string", "ggrp"),
        ("path", "source"),
    ],
)


InetRecord = TargetRecordDescriptor(
    "macos/keychain/inet",
    [
        ("string", "table"),
        ("varint", "row_id"),
        ("datetime", "cdat"),
        ("datetime", "mdat"),
        ("bytes", "desc"),
        ("bytes", "icmt"),
        ("varint", "crtr"),
        ("varint", "keychain_type"),
        ("varint", "scrp"),
        ("bytes", "labl"),
        ("bytes", "alis"),
        ("varint", "invi"),
        ("varint", "nega"),
        ("varint", "cusi"),
        ("bytes", "prot"),
        ("bytes", "acct"),
        ("bytes", "sdmn"),
        ("bytes", "srvr"),
        ("string", "ptcl"),
        ("bytes", "atyp"),
        ("varint", "port"),
        ("bytes", "path_binary"),
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
        ("varint", "pcss"),
        ("bytes", "pcsk"),
        ("bytes", "pcsi"),
        ("bytes", "persistref"),
        ("varint", "clip"),
        ("string", "ggrp"),
        ("path", "source"),
    ],
)

KeysRecord = TargetRecordDescriptor(
    "macos/keychain/keys",
    [
        ("string", "table"),
        ("varint", "row_id"),
        ("datetime", "cdat"),
        ("datetime", "mdat"),
        ("bytes", "kcls"),
        ("bytes", "labl"),
        ("bytes", "alis"),
        ("varint", "perm"),
        ("varint", "priv"),
        ("varint", "modi"),
        ("bytes", "klbl"),
        ("bytes", "atag"),
        ("varint", "crtr"),
        ("varint", "keychain_type"),
        ("varint", "bsiz"),
        ("varint", "esiz"),
        ("varint", "sdat"),
        ("varint", "edat"),
        ("varint", "sens"),
        ("varint", "asen"),
        ("varint", "extr"),
        ("varint", "next"),
        ("varint", "encr"),
        ("varint", "decr"),
        ("varint", "drve"),
        ("varint", "sign"),
        ("varint", "vrfy"),
        ("varint", "snrc"),
        ("varint", "vyrc"),
        ("varint", "wrap"),
        ("varint", "unwp"),
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
        ("varint", "pcss"),
        ("bytes", "pcsk"),
        ("bytes", "pcsi"),
        ("bytes", "persistref"),
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
        ("varint", "keyclass"),
        ("varint", "actual_keyclass"),
        ("string", "data"),
        ("path", "source"),
    ],
)

KeychainRecords = (
    GenpRecord,
    InetRecord,
    KeysRecord,
    SqliteSequenceRecord,
    TVersionRecord,
    MetaDataKeysRecord,
)

FIELD_MAPPINGS = {
    "actualKeyclass": "actual_keyclass",
    "rowid": "row_id",
    "path": "path_binary",
    "type": "keychain_type",
}

CONVERT_TIMESTAMPS = {
    "cdat": "2001",
    "mdat": "2001",
}


class KeychainPlugin(Plugin):
    """macOS keychain plugin.

    Parses Data Protection keychain databases (keychain-2.db).
    These are stored in ``Library/Keychains/*/``, where ``*`` is the UUID that assigned to that Mac.

    References:
        - https://eclecticlight.co/2023/08/07/an-introduction-to-keychains-and-how-theyve-changed/
    """

    USER_PATH = ("Library/Keychains/*/keychain-2.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No keychain-2.db files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=KeychainRecords)
    def keychain(
        self,
    ) -> Iterator[KeychainRecords]:
        """Return macOS Keychain database entries."""
        yield from build_sqlite_records(
            self, self.files, KeychainRecords, field_mappings=FIELD_MAPPINGS, convert_timestamps=CONVERT_TIMESTAMPS
        )

        # TODO: Add cert, outgoingqueue, incomingqueue, synckeys, ckmirror, currentkeys,
        # ckstate, item_backup, backup_keybag, ckmanifest, pending_manifest, ckmanifest_leaf,
        # backup_keyarchive, currentkeyarchives, archived_key_backup, pending_manifest_leaf,
        # currentitems, ckdevicestate, tlkshare, sharingIncomingQueue,
        # sharingMirror, sharingOutgoingQueue tables
