from dissect.target.helpers.regutil import RegFlex

from ._utils import absolute_path


def test_regflex():
    regflex = RegFlex()

    with open(absolute_path("data/regflex.reg"), "rt") as fh:
        regflex.map_definition(fh)

    assert "HKEY_CURRENT_USER" in regflex.hives
    hive = regflex.hives["HKEY_CURRENT_USER"]
    assert hive.key("Test1").value("Value1").value == "a"

    assert "HKEY_CLASSES_ROOT" in regflex.hives
    hive = regflex.hives["HKEY_CLASSES_ROOT"]
    assert hive.key("Test2").value("Value2").value == "b"

    assert "HKEY_LOCAL_MACHINE" in regflex.hives
    hive = regflex.hives["HKEY_LOCAL_MACHINE"]
    key = hive.key("Test Values")
    assert len(key.values()) == 15
    assert key.value("String").value == "a"
    assert key.value("Long String").value == "a" * 1218
    assert key.value("Binary").value == b"\x00" * 8
    assert key.value("Long Binary").value == b"\x00" * 240
    assert key.value("Dword").value == 1
    assert key.value("None").value == b"\x00\x01\x02\x04"
    assert key.value("Hex String").value == "abcd"
    assert key.value("Expandable String").value == "a"
    assert key.value("Long Expandable String").value == "a" * 2584
    assert key.value("Hex Binary").value == b"\x00" * 8
    assert key.value("Hex Dword LE").value == 1
    assert key.value("Hex Dword BE").value == 1
    assert key.value("Multi String").value == ["a", "b", "c", "d"]
    assert key.value("Long Multi String").value == ["a" * 1024, "b" * 1024, "c" * 1024, "d" * 1024]
    assert key.value("Qword").value == 1
