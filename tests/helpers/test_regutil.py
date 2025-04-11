from __future__ import annotations

import pytest
from dissect.regf import c_regf

from dissect.target.helpers.regutil import (
    HiveCollection,
    KeyCollection,
    RegFlex,
    RegistryHive,
    RegistryKeyNotFoundError,
    RegistryValueType,
    VirtualHive,
    VirtualKey,
    glob_ext,
    glob_ext0,
    glob_ext1,
    glob_split,
    has_glob_magic,
)
from tests._utils import absolute_path


def test_regflex() -> None:
    regflex = RegFlex()

    with absolute_path("_data/helpers/regutil/regflex.reg").open() as fh:
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

    assert key.value("String").type == RegistryValueType.SZ
    assert key.value("Long String").value == "a" * 1218
    assert key.value("Long String").type == RegistryValueType.SZ

    assert key.value("Binary").value == b"\x00" * 8
    assert key.value("Binary").type == RegistryValueType.BINARY

    assert key.value("Long Binary").value == b"\x00" * 240
    assert key.value("Long Binary").type == RegistryValueType.BINARY

    assert key.value("Dword").value == 1
    assert key.value("Dword").type == RegistryValueType.DWORD

    assert key.value("None").value == b"\x00\x01\x02\x04"
    assert key.value("None").type == RegistryValueType.NONE

    assert key.value("Hex String").value == "abcd"
    assert key.value("Hex String").type == RegistryValueType.SZ

    assert key.value("Expandable String").value == "a"
    assert key.value("Expandable String").type == RegistryValueType.EXPAND_SZ

    assert key.value("Long Expandable String").value == "a" * 2584
    assert key.value("Long Expandable String").type == RegistryValueType.EXPAND_SZ

    assert key.value("Hex Binary").value == b"\x00" * 8
    assert key.value("Hex Binary").type == RegistryValueType.BINARY

    assert key.value("Hex Dword LE").value == 1
    assert key.value("Hex Dword LE").type == RegistryValueType.DWORD

    assert key.value("Hex Dword BE").value == 1
    assert key.value("Hex Dword BE").type == RegistryValueType.DWORD_BIG_ENDIAN

    assert key.value("Multi String").value == ["a", "b", "c", "d"]
    assert key.value("Multi String").type == RegistryValueType.MULTI_SZ

    assert key.value("Long Multi String").value == ["a" * 1024, "b" * 1024, "c" * 1024, "d" * 1024]
    assert key.value("Long Multi String").type == RegistryValueType.MULTI_SZ

    assert key.value("Qword").value == 1
    assert key.value("Qword").type == RegistryValueType.QWORD


@pytest.mark.parametrize(
    ("pattern", "has_glob"),
    [
        ("", False),
        ("foo\\bar", False),
        ("foo\\*\\", True),
        ("\\?\\foo", True),
        ("foo\\[", True),
        ("foo\\]", False),
    ],
)
def test_has_glob_magic(pattern: str, has_glob: bool) -> None:
    assert has_glob_magic(pattern) is has_glob


@pytest.mark.parametrize(
    ("pattern", "part1", "part2"),
    [
        ("", "", ""),
        ("foo\\bar", "foo\\bar", ""),
        ("\\foo\\bar", "\\foo\\bar", ""),
        ("foo\\bar\\*\\", "foo\\bar\\", "*\\"),
        ("foo\\bar\\*\\bla", "foo\\bar\\", "*\\bla"),
        ("foo\\bar\\?\\bla", "foo\\bar\\", "?\\bla"),
        ("foo\\bar\\[a-z]\\bla", "foo\\bar\\", "[a-z]\\bla"),
        ("foo\\bar\\b*z\\bla", "foo\\bar\\", "b*z\\bla"),
        ("foo\\bar\\b?z\\bla", "foo\\bar\\", "b?z\\bla"),
        ("foo\\bar\\b[a-z]z\\bla", "foo\\bar\\", "b[a-z]z\\bla"),
        ("*\\foo\\bar\\bla", "", "*\\foo\\bar\\bla"),
        ("?\\foo\\bar\\bla", "", "?\\foo\\bar\\bla"),
        ("[a-z]\\foo\\bar\\bla", "", "[a-z]\\foo\\bar\\bla"),
        ("f*r\\foo\\bar\\bla", "", "f*r\\foo\\bar\\bla"),
        ("f?r\\foo\\bar\\bla", "", "f?r\\foo\\bar\\bla"),
        ("f[a-z]r\\foo\\bar\\bla", "", "f[a-z]r\\foo\\bar\\bla"),
        ("\\*\\foo\\bar\\bla", "\\", "*\\foo\\bar\\bla"),
        ("foo\\bar\\bla\\*", "foo\\bar\\bla\\", "*"),
        ("foo\\bar\\bla\\?", "foo\\bar\\bla\\", "?"),
        ("foo\\bar\\bla\\[a-z]", "foo\\bar\\bla\\", "[a-z]"),
        ("foo\\bar\\bla\\b*z", "foo\\bar\\bla\\", "b*z"),
        ("foo\\bar\\bla\\b?z", "foo\\bar\\bla\\", "b?z"),
        ("foo\\bar\\bla\\b[a-z]z", "foo\\bar\\bla\\", "b[a-z]z"),
    ],
)
def test_glob_split(pattern: str, part1: str, part2: str) -> None:
    assert glob_split(pattern) == (part1, part2)


@pytest.fixture
def hive() -> VirtualHive:
    hive = VirtualHive()

    key_paths = [
        "\\some\\path\\to\\foo",
        "\\some\\path\\to\\bar",
        "\\some\\path\\to\\bla",
        "\\some\\path\\bla",
        "\\some\\other\\bla",
        "\\some\\very-long\\path\\to\\bla",
        "\\some\\other-long\\path\\into\\bla",
        "\\other\\path\\to\\bla",
    ]

    for key_path in key_paths:
        key = VirtualKey(hive, key_path)
        hive.map_key(key_path, key)

    return hive


@pytest.fixture
def hivecollection(hive: RegistryHive) -> HiveCollection:
    return HiveCollection([hive])


@pytest.fixture
def key_collection(hivecollection: HiveCollection) -> KeyCollection:
    return hivecollection.key("\\")


@pytest.mark.parametrize(
    ("key_path", "key_name"),
    [
        ("\\", "VROOT"),
        ("\\some\\path\\to\\foo", "foo"),
        ("\\some\\nonexisting\\meh", RegistryKeyNotFoundError),
        ("some\\other\\bla\\", "bla"),
    ],
)
def test_registry_key_get(hive: RegistryHive, key_path: str, key_name: str | RegistryKeyNotFoundError) -> None:
    key = hive.key("\\")

    if key_name is RegistryKeyNotFoundError:
        with pytest.raises(key_name):
            key.get(key_path)
    else:
        assert key.get(key_path).name == key_name


@pytest.mark.parametrize(
    ("key_path", "key_name"),
    [
        ("\\", "VROOT"),
        ("\\some\\path\\to\\foo", "foo"),
        ("\\some\\nonexisting\\meh", RegistryKeyNotFoundError),
        ("some\\other\\bla\\", "bla"),
    ],
)
def test_key_collection_get(
    key_collection: KeyCollection,
    key_path: str,
    key_name: str | RegistryKeyNotFoundError,
) -> None:
    if key_name is RegistryKeyNotFoundError:
        with pytest.raises(key_name):
            key_collection.get(key_path)
    else:
        assert key_collection.get(key_path).name == key_name


@pytest.mark.parametrize(
    ("key_path", "key_names"),
    [
        ("\\some\\path\\to\\foo", ["foo"]),
        ("\\non\\existing\\key", []),
    ],
)
def test_glob_ext0(key_collection: KeyCollection, key_path: str, key_names: list[str]) -> None:
    key_collections = glob_ext0(key_collection, key_path)

    collection_names = [key_collection.name for key_collection in key_collections]

    assert collection_names == key_names


@pytest.mark.parametrize(
    ("pattern", "key_names"),
    [
        (
            "*",
            ["foo", "bar", "bla"],
        ),
        (
            "b*",
            ["bar", "bla"],
        ),
        ("z*z", []),
        (
            "F*",
            ["foo"],
        ),
    ],
)
def test_glob_ext1(hivecollection: HiveCollection, pattern: str, key_names: list[str]) -> None:
    key_collection = hivecollection.key("\\some\\path\\to\\")
    key_collections = glob_ext1(key_collection, pattern)

    collection_names = [key_collection.name for key_collection in key_collections]

    assert sorted(collection_names) == sorted(key_names)


@pytest.mark.parametrize(
    ("pattern", "key_paths"),
    [
        (
            "\\some\\path\\to\\foo",
            [
                "\\some\\path\\to\\foo",
            ],
        ),
        (
            "\\some\\path\\to\\foo\\",
            [
                "\\some\\path\\to\\foo",
            ],
        ),
        (
            "some\\path\\to\\foo",
            [
                "\\some\\path\\to\\foo",
            ],
        ),
        (
            "\\some\\path\\to\\*",
            [
                "\\some\\path\\to\\foo",
                "\\some\\path\\to\\bar",
                "\\some\\path\\to\\bla",
            ],
        ),
        (
            "\\some\\path\\to\\*\\",
            [
                "\\some\\path\\to\\foo",
                "\\some\\path\\to\\bar",
                "\\some\\path\\to\\bla",
            ],
        ),
        (
            "\\*\\path\\to\\bla",
            [
                "\\some\\path\\to\\bla",
                "\\other\\path\\to\\bla",
            ],
        ),
        (
            "*\\path\\to\\bla",
            [
                "\\some\\path\\to\\bla",
                "\\other\\path\\to\\bla",
            ],
        ),
        (
            "\\some\\*\\bla",
            [
                "\\some\\path\\bla",
                "\\some\\other\\bla",
            ],
        ),
        (
            "\\some\\path\\to\\z*",
            [],
        ),
        (
            "\\*\\path\\to\\zap",
            [],
        ),
        (
            "\\some\\non-existing\\path\\to\\foo",
            [],
        ),
        (
            "\\some\\*\\path\\*\\bla",
            [
                "\\some\\very-long\\path\\to\\bla",
                "\\some\\other-long\\path\\into\\bla",
            ],
        ),
    ],
)
def test_glob_ext(key_collection: KeyCollection, pattern: str, key_paths: list[str]) -> None:
    key_collections = glob_ext(key_collection, pattern)
    collection_paths = [key_collection.path for key_collection in key_collections]

    assert sorted(collection_paths) == sorted(key_paths)


@pytest.mark.parametrize(
    ("input", "expected_name", "expected_value"),
    [
        (c_regf.REG_NONE, "NONE", 0),
        (c_regf.REG_SZ, "SZ", 1),
        (c_regf.REG_EXPAND_SZ, "EXPAND_SZ", 2),
        (c_regf.REG_BINARY, "BINARY", 3),
        (c_regf.REG_DWORD, "DWORD", 4),
        (c_regf.REG_DWORD_BIG_ENDIAN, "DWORD_BIG_ENDIAN", 5),
        (c_regf.REG_LINK, "LINK", 6),
        (c_regf.REG_MULTI_SZ, "MULTI_SZ", 7),
        (c_regf.REG_RESOURCE_LIST, "RESOURCE_LIST", 8),
        (c_regf.REG_FULL_RESOURCE_DESCRIPTOR, "FULL_RESOURCE_DESCRIPTOR", 9),
        (c_regf.REG_RESOURCE_REQUIREMENTS_LIST, "RESOURCE_REQUIREMENTS_LIST", 10),
        (c_regf.REG_QWORD, "QWORD", 11),
        (1337, None, 1337),
    ],
)
def test_registry_value_type_enum(input: int, expected_name: str | None, expected_value: int) -> None:
    """Test if registry value types are not parsed strictly within the Enum."""
    regf_value = RegistryValueType(input)
    assert regf_value == expected_value
    assert regf_value.name == expected_name
