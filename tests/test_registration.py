import os
import sys
from pathlib import Path
from unittest.mock import call, patch

import pytest
from dissect.target.container import CONTAINERS
from dissect.target.filesystem import FILESYSTEMS
from dissect.target.loader import LOADERS
from dissect.target.plugin import PLUGINS, filter_files, load_from_environment_variable


@pytest.fixture
def environment_path(tmp_path: Path):
    os.environ.update({"DISSECT_PLUGINS": str(tmp_path.absolute())})
    yield tmp_path


def registry_file(path: str):
    return Path(__file__).parent / f"plugin_register/{path}"


def copy_different_plugin_files(path: Path, file_name: str):
    plugin_file = path / file_name
    plugin_file.touch()
    plugin = registry_file(file_name)
    plugin_file.write_text(plugin.read_text())


def test_load_environment_variable_undefined():
    with patch("dissect.target.plugin.filter_files") as mocked_filter_files:
        mocked_filter_files.return_value = []
        load_from_environment_variable()
        mocked_filter_files.assert_not_called()


def test_load_environment_variable_empty_string():
    with patch("dissect.target.plugin.filter_files") as mocked_filter_files:
        os.environ.update({"DISSECT_PLUGINS": ""})
        mocked_filter_files.return_value = []
        load_from_environment_variable()
        mocked_filter_files.assert_not_called()


def test_load_environment_variable_comma_seperated_string():
    with patch("dissect.target.plugin.filter_files") as mocked_filter_files:
        os.environ.update({"DISSECT_PLUGINS": ","})
        mocked_filter_files.return_value = []
        load_from_environment_variable()
        mocked_filter_files.assert_has_calls(calls=[call(Path(""))])


def test_filter_file(tmp_path: Path):
    assert list(filter_files(tmp_path)) == []


@pytest.mark.parametrize(
    "file_name, empty_list",
    [
        ("__init__.py", True),
        ("__pycache__/help.pyc", True),
        ("hello/test.py", False),
    ],
)
def test_filter_directory(tmp_path: Path, file_name: str, empty_list: bool):
    file = tmp_path / file_name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.touch()

    if empty_list:
        assert list(filter_files(tmp_path)) == []
    else:
        assert file in list(filter_files(tmp_path))


def test_new_plugin_registration(environment_path: Path):
    copy_different_plugin_files(environment_path, "plugin.py")
    load_from_environment_variable()

    assert "plugin" in PLUGINS


def test_new_filesystem_registration(environment_path: Path):
    copy_different_plugin_files(environment_path, "filesystem.py")
    load_from_environment_variable()

    values = [x for (_, x) in FILESYSTEMS]

    assert "TestFilesystem" in values


def test_loader_registration(environment_path: Path):
    copy_different_plugin_files(environment_path, "loader.py")
    load_from_environment_variable()

    assert "TestLoader" == LOADERS[-1].__name__


def test_register_container(environment_path: Path):
    copy_different_plugin_files(environment_path, "container.py")
    load_from_environment_variable()

    values = [x for (_, x) in CONTAINERS]

    assert "TestContainer" in values


@pytest.mark.parametrize(
    "filename, expected_module",
    [
        ("test.py", "test"),
        ("hello_world/help.py", "hello_world.help"),
        ("path/to/file.py", "path.to.file"),
    ],
)
def test_filesystem_module_registration(environment_path: Path, filename: str, expected_module: str):
    path = environment_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()

    load_from_environment_variable()

    assert expected_module in sys.modules.keys()
