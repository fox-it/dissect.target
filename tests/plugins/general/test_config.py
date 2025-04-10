from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystems.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
)
from dissect.target.plugins.general.config import ConfigurationTreePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def config_tree(target_unix: Target) -> ConfigurationTreePlugin:
    target_unix.add_plugin(ConfigurationTreePlugin)
    return target_unix.config_tree


def test_config_tree_plugin(config_tree: ConfigurationTreePlugin, fs_unix: VirtualFilesystem, tmp_path: Path) -> None:
    tmp_path.joinpath("new/path").mkdir(parents=True, exist_ok=True)
    tmp_path.joinpath("new/config").mkdir(parents=True, exist_ok=True)
    fs_unix.map_dir("/etc", tmp_path)
    fs_unix.map_file("/etc/new/path/config", absolute_path("_data/helpers/configutil/config"))

    options = {"separator": (r"\s",)}

    assert isinstance(config_tree("/etc/new/path/config"), ConfigurationEntry)
    assert isinstance(config_tree("/etc/new/path/config", **options).get("help"), ConfigurationEntry)
    assert isinstance(config_tree("/etc/new/path/config/help", **options), ConfigurationEntry)
    assert isinstance(config_tree.get(), ConfigurationFilesystem)
    assert isinstance(config_tree.get("/etc/new/path/config/help", **options), ConfigurationEntry)

    assert sorted(config_tree("/etc/new/path/config", as_dict=True, **options).keys()) == [
        "help",
        "test",
    ]
    assert isinstance(config_tree.get("/etc/new/path/config/help", as_dict=True, **options), list)

    with pytest.raises(FileNotFoundError):
        config_tree("/etc/new/path/help", **options)


@pytest.mark.parametrize(
    "collapse_type",
    [
        tuple,
        dict,
        set,
        list,
    ],
)
def test_collapse_types(
    config_tree: ConfigurationTreePlugin, fs_unix: VirtualFilesystem, collapse_type: type[Iterable]
) -> None:
    """Using specifically the SequenceType due to using lru_cache in the plugin."""

    fs_unix.map_file_fh("/etc/new/path/config", BytesIO(b"key=value"))

    config_tree("/etc/new/path/config", collapse=collapse_type())


@pytest.mark.parametrize(
    ("hint", "data_bytes"),
    [
        ("ini", b"[DEFAULT]\nkey=value"),
        ("xml", b"<a>currently_just_text</a>"),
        ("json", b'{"key": "value"}'),
        ("yaml", b"key: value"),
        ("cnf", b"key=value"),
        ("conf", b"key value"),
        ("sample", b"currently_just_text"),
        ("template", b"currently_just_text"),
        ("toml", b"key = 'value'"),
    ],
)
def test_as_dict(
    config_tree: ConfigurationTreePlugin, fs_unix: VirtualFilesystem, hint: str, data_bytes: bytes
) -> None:
    fs_unix.map_file_fh("/etc/new/path/config", BytesIO(data_bytes))
    assert isinstance(config_tree("/etc/new/path/config", hint=hint, as_dict=True), dict)
