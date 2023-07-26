from pathlib import Path
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.registry import UnixRegistryPlugin, UnixRegistry, ConfigurationEntry

import pytest

from ._utils import absolute_path


@pytest.fixture
def etc_directory(tmp_path: Path, fs_unix: VirtualFilesystem):
    tmp_path.joinpath("new/path").mkdir(parents=True, exist_ok=True)
    tmp_path.joinpath("new/config").mkdir(parents=True, exist_ok=True)
    fs_unix.map_dir("/etc", tmp_path)
    fs_unix.map_file("new/path/config.ini", absolute_path())


def test_plugin_compatible(target_unix, fs_unix):
    registry = UnixRegistryPlugin(target_unix)

    registry.check_compatible()


def test_unix_registry(target_unix, etc_directory):
    registry = UnixRegistry(target_unix)
    registry_path = list(registry.get("/").iterdir())

    assert registry_path == ["new"]
    assert list(registry.get("/new").iterdir()) == ["path", "config"]
    assert isinstance(registry.get("/new/path/config.ini"), ConfigurationEntry)
