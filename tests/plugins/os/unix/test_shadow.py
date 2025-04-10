from io import BytesIO
from pathlib import Path

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.shadow import ShadowPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_unix_shadow(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    shadow_file = absolute_path("_data/plugins/os/unix/shadow/shadow")
    fs_unix.map_file("/etc/shadow", shadow_file)
    target_unix_users.add_plugin(ShadowPlugin)

    results = list(target_unix_users.passwords())
    assert len(results) == 1
    assert results[0].name == "test"
    assert (
        results[0].crypt
        == "$6$oLHns1qc.C3DoQ8c$temOg6X.UF5Ly3gM03cGnBLib30mv8J49dUI.w9.EHTnO4R467zyKbfBnmTa5IIvDr5mRXFoJVBGKF6QuFDpo1"
    )  # noqa E501
    assert results[0].salt == "oLHns1qc.C3DoQ8c"
    assert (
        results[0].hash == "temOg6X.UF5Ly3gM03cGnBLib30mv8J49dUI.w9.EHTnO4R467zyKbfBnmTa5IIvDr5mRXFoJVBGKF6QuFDpo1"
    )  # noqa E501
    assert results[0].algorithm == "sha512"
    assert results[0].crypt_param is None
    assert results[0].last_change == "18963"
    assert results[0].min_age == 0
    assert results[0].max_age == 99999
    assert results[0].warning_period == 7
    assert results[0].inactivity_period == ""
    assert results[0].expiration_date == ""
    assert results[0].unused_field == ""


def test_unix_shadow_backup_file(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """test if both the shadow file and shadow backup file are read and returns unique hash+user combinations"""
    shadow_file = absolute_path("_data/plugins/os/unix/shadow/shadow")
    fs_unix.map_file("/etc/shadow", shadow_file)

    first_entry = Path(shadow_file).open("rb").read()
    other_entry = first_entry.replace(b"test", b"other-user")
    duplicate_entry = first_entry
    fs_unix.map_file_fh("/etc/shadow-", BytesIO(first_entry + other_entry + duplicate_entry))

    results = list(target_unix_users.passwords())
    assert len(results) == 2
    assert results[0].name == "test"
    assert results[1].name == "other-user"
    assert results[0].hash == results[1].hash
