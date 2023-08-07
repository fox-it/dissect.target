from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.registry import (
    ConfigurationEntry,
    ConfigurationTree,
    UnixRegistry,
)

from ._utils import absolute_path


@pytest.fixture
def etc_directory(tmp_path: Path, fs_unix: VirtualFilesystem):
    tmp_path.joinpath("new/path").mkdir(parents=True, exist_ok=True)
    tmp_path.joinpath("new/config").mkdir(parents=True, exist_ok=True)
    fs_unix.map_dir("/etc", tmp_path)
    fs_unix.map_file("new/path/config.ini", absolute_path())


def test_plugin_compatible(target_unix, fs_unix):
    registry = ConfigurationTree(target_unix)

    registry.check_compatible()


def test_unix_registry(target_unix, etc_directory):
    registry = UnixRegistry(target_unix)
    registry_path = list(registry.get("/").iterdir())

    assert registry_path == ["new"]
    assert list(registry.get("/new").iterdir()) == ["path", "config"]
    assert isinstance(registry.get("/new/path/config.ini"), ConfigurationEntry)


def test_config_entry():
    class MockableRead(Mock):
        def __enter__(self):
            return self.binary_data

        def __exit__(self, _, __, ___):
            return

    mocked_open = MockableRead(binary_data=BytesIO(b"default test\n[Unit]\nhelp me\n"))
    mocked_entry = Mock()
    mocked_entry.open.return_value = mocked_open

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
