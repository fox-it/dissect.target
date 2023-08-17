from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import Mock

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.config import (
    ConfigurationEntry,
    ConfigurationFs,
    Default,
)

from ._utils import absolute_path


@pytest.fixture
def etc_directory(tmp_path: Path, fs_unix: VirtualFilesystem) -> VirtualFilesystem:
    tmp_path.joinpath("new/path").mkdir(parents=True, exist_ok=True)
    tmp_path.joinpath("new/config").mkdir(parents=True, exist_ok=True)
    tmp_path.joinpath("new/path/config").write_text(Path(absolute_path("data/config_tree/config")).read_text())
    fs_unix.map_dir("/etc", tmp_path)

    return fs_unix


def test_unix_registry(target_unix: Target, etc_directory: VirtualFilesystem):
    config_fs = ConfigurationFs(target_unix)
    config_path = list(config_fs.get("/").iterdir())

    assert config_path == ["new"]
    assert sorted(list(config_fs.get("/new").iterdir())) == ["config", "path"]
    assert isinstance(config_fs.get("/new/path/config"), ConfigurationEntry)


def test_config_entry():
    class MockableRead(Mock):
        def __enter__(self):
            return self.binary_data

        def __exit__(self, _, __, ___):
            return

    mocked_open = MockableRead(binary_data=BytesIO(b"default=test\n[Unit]\nhelp=me\n"))
    mocked_entry = Mock()
    mocked_entry.open.return_value = mocked_open
    mocked_entry.path = "config.ini"

    entry = ConfigurationEntry(
        Mock(),
        "config.ini",
        entry=mocked_entry,
    )
    assert entry.is_dir()

    assert list(entry.iterdir()) == ["DEFAULT", "Unit"]

    default_section = entry.get("DEFAULT")
    assert default_section.is_dir()
    assert list(default_section.iterdir()) == ["default"]

    default_key_values = default_section.get("default")
    assert default_key_values.open().read() == b"test"


def test_parse_functions(target_unix: Target, etc_directory: VirtualFilesystem):
    config_fs = ConfigurationFs(target_unix)
    entry: ConfigurationEntry = config_fs.get("/new/path/config", collapse=True)

    assert entry.parser_items["help"] == "you"
    assert entry.parser_items["test"] == "you"

    entry = config_fs.get("/new/path/config", collapse={"help"})

    assert entry.parser_items["help"] == "you"
    assert entry.parser_items["test"] == ["me", "you"]


@pytest.mark.parametrize(
    "parser_string, key, value",
    [
        ("hello world", "hello", "world"),
        ("hello world\t# new info", "hello", "world"),
    ],
)
def test_unknown_parser(parser_string: str, key: str, value: str):
    parser = Default(None)
    parser.read_file(StringIO(parser_string))
    assert parser.parsed_data[key] == value
