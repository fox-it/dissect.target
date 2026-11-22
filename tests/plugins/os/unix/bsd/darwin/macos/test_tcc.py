from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.tcc import TCCPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "user.db",
                "system.db",
            ),
            (
                "/Users/user/Library/Application Support/com.apple.TCC/TCC.db",
                "/Library/Application Support/com.apple.TCC/TCC.db",
            ),
        ),
    ],
)
def test_tcc(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    tz = timezone.utc

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
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/tcc/{name}")
        fs_unix.map_file(path, data_file)

    target_unix.add_plugin(TCCPlugin)

    results = list(target_unix.tcc())
    results.sort(key=lambda r: r.source)

    assert len(results) == 51

    assert results[0].table == "admin"
    assert results[0].key == "version"
    assert results[0].value == "32"
    assert results[0].source == "/Library/Application Support/com.apple.TCC/TCC.db"

    assert results[1].table == "access"
    assert results[1].service == "kTCCServiceSystemPolicyAllFiles"
    assert (
        results[1].client
        == "/System/Library/PrivateFrameworks/VoiceShortcuts.framework/Versions/A/Support/siriactionsd"
    )
    assert results[1].client_type == 1
    assert results[1].auth_value == "Denied"
    assert results[1].auth_reason == "Service Policy"
    assert results[1].auth_version == 1
    assert (
        results[1].csreq
        == b"\xfa\xde\x0c\x00\x00\x00\x004\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\x16com.apple.siriactionsd\x00\x00\x00\x00\x00\x03"  # noqa E501
    )
    assert results[1].policy_id is None
    assert results[1].indirect_object_identifier == "UNUSED"
    assert results[1].indirect_object_identifier_type is None
    assert results[1].indirect_object_code_identity is None
    assert results[1].flags == 0
    assert results[1].last_modified == datetime(2026, 3, 25, 14, 13, 27, tzinfo=tz)
    assert results[1].pid is None
    assert results[1].pid_version is None
    assert results[1].boot_uuid == "UNUSED"
    assert results[1].last_reminded == datetime(1970, 1, 1, 0, 0, 0, tzinfo=tz)
    assert results[1].source == "/Library/Application Support/com.apple.TCC/TCC.db"

    assert results[-1].table == "integrity_flag"
    assert results[-1].key == "integrity_flag"
    assert results[-1].value == "0"
    assert results[-1].source == "/Users/user/Library/Application Support/com.apple.TCC/TCC.db"
