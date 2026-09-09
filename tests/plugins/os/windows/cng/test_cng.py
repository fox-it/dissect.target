from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.cng.cng import CNGPlugin
from dissect.target.plugins.os.windows.cng.key import CNGKey
from dissect.target.plugins.os.windows.cng.util import derive_key_hash
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_cng_key_name_hash_derivation() -> None:
    """Test if we can derive CNG key names correctly."""
    assert derive_key_hash("Google Chromekey1") == "7096db7aeb75c0d3497ecd56d355a695"
    assert (
        derive_key_hash("Microsoft Connected Devices Platform device certificate") == "de7cf8a7901d2ad13e5c67c29e5d1662"
    )


def test_windows_cng_system_key(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can find and parse a CNG system key correctly."""
    hash = derive_key_hash("Google Chromekey1")
    machine_guid = "013611f0-5a3d-4306-a425-ea3543c1053c"
    key_name = f"{hash}_{machine_guid}"

    fs_win.map_file(
        f"ProgramData/Microsoft/Crypto/SystemKeys/{key_name}",
        absolute_path(f"_data/plugins/os/windows/cng/fixture/windows_11/SystemKeys/{key_name}"),
    )
    target_win_users.add_plugin(CNGPlugin)
    assert len(target_win_users.cng.system_keys) == 1

    record = next(target_win_users.cng.keys())
    assert record.ts
    assert record.name == "Google Chromekey1"
    assert record.source == f"sysvol\\ProgramData\\Microsoft\\Crypto\\SystemKeys\\{hash}_{machine_guid}"

    key = target_win_users.cng.find_key("Google Chromekey1")
    assert isinstance(key, CNGKey)
    assert key.version == 1
    assert key.type == 2
    assert key.name == "Google Chromekey1"
    assert key.sid == "S-1-5-18"

    assert key.get_property("Modified") == datetime(2025, 6, 18, 21, 27, 57, 755360, tzinfo=timezone.utc)

    assert key.get_property("CreatorProcessName") == (
        "C:\\Program Files\\Google\\Chrome\\Application\\137.0.7151.120\\elevation_service.exe"
    )

    # Since we do not have the DPAPI plugin set up here, there are two encrypted properties.
    assert len(key.encrypted[0].data) == 338
    assert len(key.encrypted[1].data) == 284


def test_windows_cng_user_key(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can find and parse a CNG user key correctly.

    Can be verified with::

        C:\\Windows\\system32> certutil -csp "Microsoft Software Key Storage Provider" -v -key -privatekey -user
    """
    hash = derive_key_hash("Microsoft Connected Devices Platform device certificate")
    machine_guid = "013611f0-5a3d-4306-a425-ea3543c1053c"
    key_name = f"{hash}_{machine_guid}"

    fs_win.map_file(
        f"Users/John/AppData/Roaming/Microsoft/Crypto/Keys/{key_name}",
        absolute_path(f"_data/plugins/os/windows/cng/fixture/windows_11/AnotherUser_Keys/{key_name}"),
    )
    target_win_users.add_plugin(CNGPlugin)
    assert len(target_win_users.cng.user_keys) == 1

    key = target_win_users.cng.find_key(
        "Microsoft Connected Devices Platform device certificate",
        sid="S-1-5-21-3263113198-3007035898-945866154-1002",
    )

    assert key.version == 1
    assert key.type == 4
    assert key.name == "Microsoft Connected Devices Platform device certificate"
    assert key.sid == "S-1-5-21-3263113198-3007035898-945866154-1002"

    assert key.get_property("Modified") == datetime(2025, 6, 3, 18, 26, 18, 592632, tzinfo=timezone.utc)

    assert key.get_property("CreatorProcessName") == "C:\\Windows\\System32\\svchost.exe"

    pubkey = key.get_key("Public Key", "ECC")
    assert pubkey.key.curve == "NIST P-256"

    # Since we do not have the DPAPI plugin set up here, there are two encrypted properties.
    assert len(key.encrypted[0].data) == 322
    assert len(key.encrypted[1].data) == 348
