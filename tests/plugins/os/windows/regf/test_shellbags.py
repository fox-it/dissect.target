from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.regf.shellbags import (
    ShellBagsPlugin,
    parse_shell_item_list,
)

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("shellbag", "name", "modification_time", "localized_name"),
    [
        (
            (
                b"X\x001\x00\x00\x00\x00\x00WX\xc1I\x11\x00MENUST~1\x00\x00@\x00\x03\x00\x04\x00\xef\xbeWXZBWXZB\x14"
                b"\x00*\x00M\x00e\x00n\x00u\x00 \x00S\x00t\x00a\x00r\x00t\x00\x00\x00@shell32.dll,-21786\x00\x18\x00"
                b"\x00\x00"
            ),
            "Menu Start",
            datetime.datetime(2024, 2, 23, 9, 14, 2, tzinfo=datetime.timezone.utc),
            b"@shell32.dll,-21786",
        ),
        (
            (
                b"x\x001\x00\x00\x00\x00\x00\x17W\x0bk\x11\x00Users\x00d\x00\t\x00\x04\x00\xef\xbe\xa7T,*\x91X\xe6R."
                b"\x00\x00\x00\n\x08\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00\x00\x00\x00\x00A"
                b"\x06\x85\x00U\x00s\x00e\x00r\x00s\x00\x00\x00@\x00s\x00h\x00e\x00l\x00l\x003\x002\x00.\x00d\x00l"
                b"\x00l\x00,\x00-\x002\x001\x008\x001\x003\x00\x00\x00\x14\x00\x00\x00"
            ),
            "Users",
            datetime.datetime(2023, 8, 23, 13, 24, 22, tzinfo=datetime.timezone.utc),
            "@shell32.dll,-21813",
        ),
    ],
    ids=("char", "wchar"),
)
def test_shellbags_parser(
    shellbag: bytes, name: str, modification_time: datetime.datetime, localized_name: str | bytes
) -> None:
    bag = next(parse_shell_item_list(shellbag))

    assert bag.name == name
    assert bag.modification_time == modification_time

    extension = bag.extensions[0]

    assert extension.long_name == name
    assert extension.localized_name == localized_name


@pytest.mark.parametrize(
    ("bags", "expected_type", "expected_path"),
    [
        # single VOLUME with path `A:\`
        (
            [("", "1", "19002f413a5c000000000000000000000000000000000000000000")],
            ["VOLUME"],
            ["A:\\"],
        ),
        # single VOLUME with invalid unicode character
        (
            [("", "0", "19002f4d7920436f6d70757465725c52c3a9ea6d79000000000000")],
            ["VOLUME"],
            ["My Computer\\R\u00e9\udceamy"],
        ),
        # nested path leading to "My Computer\\C:\\Users\\Administrator\\Downloads"
        (
            [
                # ROOT_FOLDER
                ("", "1", "14001f50e04fd020ea3a6910a2d808002b30309d0000"),
                # VOLUME
                ("1", "0", "19002f433a5c000000000000000000000000000000000000000000"),
                # FILE_ENTRY
                (
                    "1\\0",
                    "0",
                    (
                        "7800310000000000875747ab1100557365727300640009000400efbe2f4d2e31"
                        "875747ab2e000000d00100000000010000000000000000003a00000000004899"
                        "e90055007300650072007300000040007300680065006c006c00330032002e00"
                        "64006c006c002c002d0032003100380031003300000014000000"
                    ),
                ),
                # FILE_ENTRY
                (
                    "1\\0\\0",
                    "0",
                    (
                        "6400310000000000875748ab100041444d494e497e3100004c0009000400efbe"
                        "875747ab875748ab2e000000b9f5010000000200000000000000000000000000"
                        "0000688f5a00410064006d0069006e006900730074007200610074006f007200"
                        "000018000000"
                    ),
                ),
                # FILE_ENTRY
                (
                    "1\\0\\0\\0",
                    "0",
                    (
                        "8400310000000000875748ab1100444f574e4c4f7e3100006c0009000400efbe"
                        "875747ab875748ab2e000000c1f5010000000200000000000000000042000000"
                        "0000192d580044006f0077006e006c006f006100640073000000400073006800"
                        "65006c006c00330032002e0064006c006c002c002d0032003100370039003800"
                        "000018000000"
                    ),
                ),
            ],
            ["ROOT_FOLDER", "VOLUME", "FILE_ENTRY", "FILE_ENTRY", "FILE_ENTRY"],
            [
                "My Computer",
                "My Computer\\C:",
                "My Computer\\C:\\Users",
                "My Computer\\C:\\Users\\Administrator",
                "My Computer\\C:\\Users\\Administrator\\Downloads",
            ],
        ),
    ],
    ids=(
        "single-volume",
        "single-volume-invalid-unicode",
        "nested-path",
    ),
)
def test_shellbags_plugin(
    target_win_users: Target,
    hive_hku: VirtualHive,
    bags: list[tuple[str, str, str]],
    expected_type: list[str],
    expected_path: list[str],
) -> None:
    """Test if shellbags mapped to a registry hive are found and parsed correctly."""

    key_name = "Software\\Microsoft\\Windows\\Shell\\BagMRU"

    for bag_key, bag_name, bag_value in bags:
        key = VirtualKey(hive_hku, f"{key_name}\\{bag_key}")
        key.add_value(bag_name, bytes.fromhex(bag_value))
        hive_hku.map_key(f"{key_name}\\{bag_key}", key)

    target_win_users.add_plugin(ShellBagsPlugin)
    results = list(target_win_users.shellbags())

    assert len(results) == len(bags)
    assert [r.type for r in results] == expected_type
    assert [r.path for r in results] == expected_path
