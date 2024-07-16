from __future__ import annotations

import datetime

import pytest

from dissect.target.plugins.os.windows.regf.shellbags import parse_shell_item_list


@pytest.mark.parametrize(
    "shellbag, name, modification_time, localized_name",
    [
        (
            (
                b"X\x001\x00\x00\x00\x00\x00WX\xc1I\x11\x00MENUST~1\x00\x00@\x00\x03\x00\x04\x00\xef\xbeWXZBWXZB\x14"
                b"\x00*\x00M\x00e\x00n\x00u\x00 \x00S\x00t\x00a\x00r\x00t\x00\x00\x00@shell32.dll,-21786\x00\x18\x00"
                b"\x00\x00"
            ),
            "Menu Start",
            datetime.datetime(2024, 2, 23, 9, 14, 2),
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
            datetime.datetime(2023, 8, 23, 13, 24, 22),
            "@shell32.dll,-21813",
        ),
    ],
    ids=["char", "wchar"],
)
def test_parse_shell_item_list(
    shellbag: bytes, name: str, modification_time: datetime.datetime, localized_name: str | bytes
) -> None:
    bag = next(parse_shell_item_list(shellbag))

    assert bag.name == name
    assert bag.modification_time == modification_time

    extension = bag.extensions[0]

    assert extension.long_name == name
    assert extension.localized_name == localized_name
