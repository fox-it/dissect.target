from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.exceptions import FileNotFoundError
from dissect.target.plugins.os.unix.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
    ConfigurationTreePlugin,
    parse_config,
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
    config_fs = ConfigurationFilesystem(target_unix)
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

    parser_items = parse_config(mocked_entry)

    entry = ConfigurationEntry(
        Mock(),
        "config.ini",
        entry=mocked_entry,
        parser_items=parser_items,
    )
    assert entry.is_dir()

    assert list(entry.iterdir()) == ["DEFAULT", "Unit"]

    default_section = entry.get("DEFAULT")
    assert default_section.is_dir()
    assert list(default_section.iterdir()) == ["default"]

    default_key_values = default_section.get("default")
    assert default_key_values.open().read() == b"test"


def test_parse_functions(target_unix: Target, etc_directory: VirtualFilesystem):
    config_fs = ConfigurationFilesystem(target_unix)
    entry: ConfigurationEntry = config_fs.get("/new/path/config", collapse=True)

    assert entry.parser_items["help"] == "you"
    assert entry.parser_items["test"] == "you"

    entry = config_fs.get("/new/path/config", collapse={"help"})

    assert entry.parser_items["help"] == "you"
    assert entry.parser_items["test"] == ["me", "you"]


def test_config_tree_plugin(target_unix: Target, etc_directory: VirtualFilesystem):
    target_unix.add_plugin(ConfigurationTreePlugin)

    assert isinstance(target_unix.config_tree("/etc/new/path/config").get(""), ConfigurationEntry)
    assert isinstance(target_unix.config_tree("/etc/new/path/config").get("help"), ConfigurationEntry)
    assert isinstance(target_unix.config_tree("/etc/new/path/config/help"), ConfigurationEntry)
    assert isinstance(target_unix.config_tree("/etc/").get("/new/path/config"), ConfigurationEntry)
    assert isinstance(target_unix.config_tree.get(), ConfigurationFilesystem)
    assert isinstance(target_unix.config_tree.get("/etc/new/path/config/help"), ConfigurationEntry)

    with pytest.raises(FileNotFoundError):
        target_unix.config_tree("/etc/new/path/help")
