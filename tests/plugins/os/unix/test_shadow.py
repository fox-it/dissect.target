from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from textwrap import dedent
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.shadow import ShadowPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


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
    )
    assert results[0].salt == "oLHns1qc.C3DoQ8c"
    assert results[0].hash == "temOg6X.UF5Ly3gM03cGnBLib30mv8J49dUI.w9.EHTnO4R467zyKbfBnmTa5IIvDr5mRXFoJVBGKF6QuFDpo1"
    assert results[0].algorithm == "sha512"
    assert results[0].crypt_param is None
    assert results[0].last_change == datetime(2021, 12, 2, 0, 0, 0, tzinfo=timezone.utc)  # 18963
    assert results[0].min_age is None
    assert results[0].max_age == datetime(2295, 9, 16, 0, 0, 0, tzinfo=timezone.utc)  # 99999
    assert results[0].warning_period == 7
    assert results[0].inactivity_period is None
    assert results[0].expiration_date is None
    assert results[0].unused_field == ""


def test_unix_shadow_backup_file(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if both the shadow file and shadow backup file are read and returns unique hash+user combinations."""
    shadow_file = absolute_path("_data/plugins/os/unix/shadow/shadow")
    fs_unix.map_file("/etc/shadow", shadow_file)

    first_entry = shadow_file.read_bytes()
    other_entry = first_entry.replace(b"test", b"other-user")
    duplicate_entry = first_entry
    fs_unix.map_file_fh("/etc/shadow-", BytesIO(first_entry + other_entry + duplicate_entry))

    results = list(target_unix_users.passwords())
    assert len(results) == 2
    assert results[0].name == "test"
    assert results[1].name == "other-user"
    assert results[0].hash == results[1].hash


def test_unix_shadow_invalid_shent(
    caplog: pytest.LogCaptureFixture, target_unix_users: Target, fs_unix: VirtualFilesystem
) -> None:
    """Test if we can parse invalid day values in shents."""

    shadow_invalid = """
    no_last_change:$6$salt$hash1::0:99999:7::123456:
    no_max_age:$6$salt$hash2:18963:0::7:::
    only_last_change:$6$salt$hash3:18963::::::
    no_int_fields:$6$salt$hash4:string::::::
    daemon:*:18474:0:99999:7:::
    bin:*:18474:0:99999:7:::
    nobody:*:18474:0:99999:7:::
    regular:$6$salt$hash5:1337:0:99999:7::123456:
    """
    fs_unix.map_file_fh("/etc/shadow", BytesIO(dedent(shadow_invalid).encode()))

    results = list(target_unix_users.passwords())
    assert len(results) == 5

    assert [r.name for r in results] == [
        "no_last_change",
        "no_max_age",
        "only_last_change",
        "no_int_fields",
        "regular",
    ]

    assert results[0].name == "no_last_change"
    assert results[0].last_change is None
    assert results[0].min_age is None
    assert results[0].max_age is None
    assert results[0].warning_period == 7
    assert results[0].inactivity_period is None
    assert results[0].expiration_date == datetime(2308, 1, 6, tzinfo=timezone.utc)

    assert results[1].name == "no_max_age"
    assert results[1].last_change == datetime(2021, 12, 2, tzinfo=timezone.utc)
    assert results[1].max_age is None

    assert results[2].name == "only_last_change"
    assert results[2].last_change == datetime(2021, 12, 2, tzinfo=timezone.utc)

    assert results[3].name == "no_int_fields"
    assert results[3].last_change is None
    assert (
        "Unable to parse last_change shadow value in /etc/shadow: invalid literal for int() with base 10: 'string' ('string')"  # noqa:E501
        in caplog.text
    )

    # make sure we parsed the last entry even though the other entries are 'broken'
    assert results[-1].name == "regular"
    assert results[-1].salt == "salt"
    assert results[-1].hash == "hash5"
    assert results[-1].algorithm == "sha512"
    assert results[-1].last_change == datetime(1973, 8, 30, tzinfo=timezone.utc)
    assert results[-1].min_age is None
    assert results[-1].max_age == datetime(2247, 6, 14, tzinfo=timezone.utc)
    assert results[-1].warning_period == 7
    assert results[-1].inactivity_period is None
    assert results[-1].expiration_date == datetime(2308, 1, 6, tzinfo=timezone.utc)
