import os
import sys
from pathlib import Path
from unittest.mock import call, patch

import pytest

from dissect.target.container import CONTAINERS
from dissect.target.filesystem import FILESYSTEMS
from dissect.target.loader import LOADERS
from dissect.target.plugin import PLUGINS, find_py_files, load_modules_from_paths


@pytest.fixture
def environment_path(tmp_path: Path):
    with patch.object(os, "environ", {"DISSECT_PLUGINS": str(tmp_path.absolute())}):
        yield tmp_path


def registry_file(path: str):
    return Path(__file__).parent / f"data/plugin_register/{path}"


def copy_different_plugin_files(path: Path, file_name: str):
    plugin_file = path / file_name
    plugin_file.touch()
    plugin = registry_file(file_name)
    plugin_file.write_text(plugin.read_text())


def test_load_environment_variable_empty_string():
    with patch("dissect.target.plugin.find_py_files") as mocked_find_py_files:
        load_modules_from_paths([])
        mocked_find_py_files.assert_not_called()


def test_load_environment_variable_comma_seperated_string():
    with patch("dissect.target.plugin.find_py_files") as mocked_find_py_files:
        load_modules_from_paths([Path(""), Path("")])
        mocked_find_py_files.assert_has_calls(calls=[call(Path(""))])


def test_filter_file(tmp_path: Path):
    file = tmp_path / "hello.py"
    file.touch()

    assert list(find_py_files(file)) == [file]

    test_file = tmp_path / "non_existent_file"
    assert list(find_py_files(test_file)) == []

    test_file = tmp_path / "__init__.py"
    test_file.touch()
    assert list(find_py_files(test_file)) == []


@pytest.mark.parametrize(
    "filename, empty_list",
    [
        ("__init__.py", True),
        ("__pycache__/help.pyc", True),
        ("hello/test.py", False),
    ],
)
def test_filter_directory(tmp_path: Path, filename: str, empty_list: bool):
    file = tmp_path / filename
    file.parent.mkdir(parents=True, exist_ok=True)
    file.touch()

    if empty_list:
        assert list(find_py_files(tmp_path)) == []
    else:
        assert file in list(find_py_files(tmp_path))


def test_new_plugin_registration(environment_path: Path):
    copy_different_plugin_files(environment_path, "plugin.py")
    load_modules_from_paths([environment_path])

    assert "plugin" in PLUGINS


@pytest.mark.parametrize(
    "filename, plugin_list, class_name",
    [
        ("loader.py", LOADERS, "TestLoader"),
        ("filesystem.py", FILESYSTEMS, "TestFilesystem"),
        ("container.py", CONTAINERS, "TestContainer"),
    ],
)
def test_registration(environment_path: Path, filename: str, plugin_list: list, class_name: str):
    copy_different_plugin_files(environment_path, filename)
    load_modules_from_paths([environment_path])

    # The plugins are registered at the end of the list.
    values = plugin_list[-1].__name__

    assert class_name == values


def test_register_file(environment_path: Path):
    copy_different_plugin_files(environment_path, "container.py")
    load_modules_from_paths([environment_path / "container.py"])

    values = [container.__name__ for container in CONTAINERS]

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

    load_modules_from_paths([environment_path])

    assert expected_module in sys.modules.keys()
