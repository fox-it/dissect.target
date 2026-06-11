from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.notes import NotesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "NotesV7.storedata",
            "NotesV7.storedata-wal",
        ]
    ],
)
def test_notes(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [
        user,
    ]
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/notes/{test_file}")
        fs_unix.map_file(f"Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/{test_file}", data_file)

    target_unix.add_plugin(NotesPlugin)

    results = list(target_unix.notes())

    assert len(results) == 42

    assert results[0].table == "ZACCOUNT"
    assert results[0].z_pk == 1
    assert results[0].z_ent == 4
    assert results[0].z_opt == 2
    assert not results[0].z_allow_insecure_authentication
    assert results[0].z_did_choose_to_migrate
    assert results[0].z_enabled
    assert results[0].z_root_folder == 2
    assert results[0].z6_root_folder == 6
    assert results[0].z_trash_folder == 1
    assert results[0].z_gmail_capabilities_support is None
    assert results[0].z_port is None
    assert results[0].z_security_layer_type is None
    assert not results[0].z_migration_offered
    assert results[0].z_account_description == "On My Mac"
    assert results[0].z_email_address is None
    assert results[0].z_full_name is None
    assert results[0].z_parent_account_identifier is None
    assert results[0].z_user_name is None
    assert results[0].z_folder_hierarchy_sync_state is None
    assert results[0].z_authentication is None
    assert results[0].z_host_name is None
    assert results[0].z_server_path_prefix is None
    assert results[0].z_external_url is None
    assert results[0].z_internal_url is None
    assert results[0].z_last_used_autodiscover_url is None
    assert results[0].z_tls_certificate is None
    assert results[0].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[1].table == "ZFOLDER"
    assert results[1].z_pk == 1
    assert results[1].z_ent == 9
    assert results[1].z_opt == 2
    assert results[1].z_account == 1
    assert results[1].z1_account == 4
    assert results[1].z_parent is None
    assert results[1].z6_parent is None
    assert results[1].z_is_distinguished is None
    assert results[1].z_alleged_highest_modification_sequence is None
    assert results[1].z_computed_highest_modification_sequence is None
    assert results[1].z_uid_next is None
    assert results[1].z_uid_validity is None
    assert results[1].z_trash_account == 1
    assert results[1].z1_trash_account == 4
    assert results[1].z_name == "Trash"
    assert results[1].z_change_key is None
    assert results[1].z_user_name is None
    assert results[1].z_folder_id is None
    assert results[1].z_sync_state is None
    assert results[1].z_server_name is None
    assert results[1].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[4].table == "Z_PRIMARYKEY"
    assert results[4].z_ent == 1
    assert results[4].z_name == "Account"
    assert results[4].z_super == 0
    assert results[4].z_max == 1
    assert results[4].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[29].ac_account_type_version is None
    assert results[29].ns_auto_vacuum_level == 2
    assert results[29].ns_persistence_framework_version == 1526
    assert results[29].ns_persistence_maximum_framework_version == 1526
    assert results[29].ns_store_model_version_checksum_key == "kEYcIlyOEwm45cPXDVhZk/RhZ1zBhdqNxj73uVM6ANM="
    assert (
        results[29].ns_store_model_version_hashes_digest
        == "oKU9BJZ8XlLnCDx32ddVJ7zUewwSZxitb1jZ2XSfZEqW7ZTynDfDUJKGaDF4E//G64SKKXQU253iSERK2dTzdA=="
    )
    assert results[29].ns_store_model_version_hashes_version == 3
    assert results[29].ns_store_model_version_identifiers == "['']"
    assert results[29].ns_store_type == "SQLite"
    assert results[29].plist_path == "Z_METADATA/Z_VERSION=1"
    assert results[29].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[30].account_hash is not None
    assert isinstance(results[30].account_hash, (bytes, bytearray))
    assert results[30].attachment_hash is not None
    assert isinstance(results[30].attachment_hash, (bytes, bytearray))
    assert results[30].ews_account is not None
    assert isinstance(results[30].ews_account, (bytes, bytearray))
    assert results[30].ews_folder is not None
    assert isinstance(results[30].ews_folder, (bytes, bytearray))
    assert results[30].ews_note is not None
    assert isinstance(results[30].ews_note, (bytes, bytearray))
    assert results[30].folder is not None
    assert isinstance(results[30].folder, (bytes, bytearray))
    assert results[30].folder_action is not None
    assert isinstance(results[30].folder_action, (bytes, bytearray))
    assert results[30].imap_account is not None
    assert isinstance(results[30].imap_account, (bytes, bytearray))
    assert results[30].imap_folder is not None
    assert isinstance(results[30].imap_folder, (bytes, bytearray))
    assert results[30].imap_note is not None
    assert isinstance(results[30].imap_note, (bytes, bytearray))
    assert results[30].insert_folder_action is not None
    assert isinstance(results[30].insert_folder_action, (bytes, bytearray))
    assert results[30].insert_note_action is not None
    assert isinstance(results[30].insert_note_action, (bytes, bytearray))
    assert results[30].local_account is not None
    assert isinstance(results[30].local_account, (bytes, bytearray))
    assert results[30].move_folder_action is not None
    assert isinstance(results[30].move_folder_action, (bytes, bytearray))
    assert results[30].move_note_action is not None
    assert isinstance(results[30].move_note_action, (bytes, bytearray))
    assert results[30].note is not None
    assert isinstance(results[30].note, (bytes, bytearray))
    assert results[30].note_action is not None
    assert isinstance(results[30].note_action, (bytes, bytearray))
    assert results[30].note_body is not None
    assert isinstance(results[30].note_body, (bytes, bytearray))
    assert results[30].offline_action is not None
    assert isinstance(results[30].offline_action, (bytes, bytearray))
    assert results[30].trash_folder is not None
    assert isinstance(results[30].trash_folder, (bytes, bytearray))
    assert results[30].update_folder_action is not None
    assert isinstance(results[30].update_folder_action, (bytes, bytearray))
    assert results[30].update_note_action is not None
    assert isinstance(results[30].update_note_action, (bytes, bytearray))
    assert results[30].plist_path == "Z_METADATA/Z_VERSION=1/NSStoreModelVersionHashes"
    assert results[30].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[31].table == "Z_METADATA"
    assert results[31].z_version == 1
    assert results[31].z_uuid == "FCCEFDB3-D6A9-4BC1-A57A-9BFCE8592C33"
    assert results[31].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[32].table == "Z_MODELCACHE"
    assert results[32].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[33].table == "ACHANGE"
    assert results[33].z_pk == 1
    assert results[33].z_ent == 16001
    assert results[33].z_opt is None
    assert results[33].z_change_type == 0
    assert results[33].z_entity == 6
    assert results[33].z_entity_pk == 2
    assert results[33].z_transaction_id == 1
    assert results[33].z_columns is None
    assert results[33].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[38].table == "ATRANSACTION"
    assert results[38].z_pk == 1
    assert results[38].z_ent == 16002
    assert results[38].z_opt is None
    assert results[38].z_author_ts is None
    assert results[38].z_bundle_id_ts == 1
    assert results[38].z_context_name_ts is None
    assert results[38].z_process_id_ts == 2
    assert results[38].z_timestamp == datetime(2026, 5, 4, 11, 35, 17, 303456, tzinfo=timezone.utc)
    assert results[38].z_author is None
    assert results[38].z_bundle_id is None
    assert results[38].z_context_name is None
    assert results[38].z_process_id is None
    assert results[38].z_query_gen is None
    assert results[38].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"

    assert results[40].table == "ATRANSACTIONSTRING"
    assert results[40].z_pk == 1
    assert results[40].z_ent == 16003
    assert results[40].z_opt is None
    assert results[40].z_name == "com.apple.Notes"
    assert results[40].source == "/Users/user/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata"
