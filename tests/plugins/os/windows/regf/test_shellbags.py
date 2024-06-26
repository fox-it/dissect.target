import datetime

from dissect.target.plugins.os.windows.regf.shellbags import parse_shell_item_list


def test_parse_shell_item_list() -> None:
    shellbag = (
        b"X\x001\x00\x00\x00\x00\x00WX\xc1I\x11\x00MENUST~1\x00\x00@\x00\x03\x00\x04\x00\xef\xbeWXZBWXZB\x14\x00*"
        b"\x00M\x00e\x00n\x00u\x00 \x00S\x00t\x00a\x00r\x00t\x00\x00\x00@shell32.dll,-21786\x00\x18\x00\x00\x00"
    )

    bag = next(parse_shell_item_list(shellbag))

    assert bag.name == "Menu Start"
    assert bag.modification_time == datetime.datetime(2024, 2, 23, 9, 14, 2)

    extension = bag.extensions[0]

    assert extension.long_name == "Menu Start"
    assert extension.localized_name == b"@shell32.dll,-21786"
