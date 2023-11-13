from pathlib import Path

import pytest

from dissect.target import Target
from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
)
from dissect.target.plugins.general.config import ConfigurationTreePlugin
from tests._utils import absolute_path


def test_config_tree_plugin(target_unix: Target, fs_unix: VirtualFilesystem, tmp_path: Path) -> None:
    tmp_path.joinpath("new/path").mkdir(parents=True, exist_ok=True)
    tmp_path.joinpath("new/config").mkdir(parents=True, exist_ok=True)
    fs_unix.map_dir("/etc", tmp_path)
    fs_unix.map_file("/etc/new/path/config", absolute_path("_data/helpers/configutil/config"))

    target_unix.add_plugin(ConfigurationTreePlugin)

    options = {"seperator": (r"\s",)}

    assert isinstance(target_unix.config_tree("/etc/new/path/config").get(""), ConfigurationEntry)
    assert isinstance(target_unix.config_tree("/etc/new/path/config", **options).get("help"), ConfigurationEntry)
    assert isinstance(target_unix.config_tree("/etc/new/path/config/help", **options), ConfigurationEntry)
    assert isinstance(target_unix.config_tree.get(), ConfigurationFilesystem)
    assert isinstance(target_unix.config_tree.get("/etc/new/path/config/help", **options), ConfigurationEntry)

    assert sorted(list(target_unix.config_tree("/etc/new/path/config", as_dict=True, **options).keys())) == [
        "help",
        "test",
    ]
    assert isinstance(target_unix.config_tree.get("/etc/new/path/config/help", as_dict=True, **options), list)

    with pytest.raises(FileNotFoundError):
        target_unix.config_tree("/etc/new/path/help", **options)
