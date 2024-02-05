import sys
from pathlib import Path
from typing import Iterator
from unittest.mock import call, patch

import pytest

from dissect.target.plugin import PLUGINS, find_py_files, load_modules_from_paths


@pytest.fixture
def environment_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("DISSECT_PLUGINS", str(tmp_path.absolute()))
    yield tmp_path


def registry_file(path: str) -> Path:
    return Path(__file__).parent / "_data/registration/" / path


def copy_different_plugin_files(path: Path, file_name: str) -> None:
    plugin_file = path / file_name
    plugin_file.touch()
    plugin = registry_file(file_name)
    plugin_file.write_text(plugin.read_text())


def test_load_environment_variable_empty_string() -> None:
    with patch("dissect.target.plugin.find_py_files") as mocked_find_py_files:
        load_modules_from_paths([])
        mocked_find_py_files.assert_not_called()


def test_load_environment_variable_comma_seperated_string() -> None:
    with patch("dissect.target.plugin.find_py_files") as mocked_find_py_files:
        load_modules_from_paths([Path(""), Path("")])
        mocked_find_py_files.assert_has_calls(calls=[call(Path(""))])


def test_filter_file(tmp_path: Path) -> None:
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
def test_filter_directory(tmp_path: Path, filename: str, empty_list: bool) -> None:
    file = tmp_path / filename
    file.parent.mkdir(parents=True, exist_ok=True)
    file.touch()

    if empty_list:
        assert list(find_py_files(tmp_path)) == []
    else:
        assert file in list(find_py_files(tmp_path))


def test_new_plugin_registration(environment_path: Path) -> None:
    copy_different_plugin_files(environment_path, "plugin.py")
    load_modules_from_paths([environment_path])

    assert "plugin" in PLUGINS


def test_loader_registration(environment_path: Path) -> None:
    with patch("dissect.target.loader.LOADERS", []) as mocked_loaders, patch(
        "dissect.target.loader.LOADERS_BY_SCHEME", {}
    ):
        copy_different_plugin_files(environment_path, "loader.py")
        load_modules_from_paths([environment_path])

        assert len(mocked_loaders) == 1
        assert mocked_loaders[0].__name__ == "TestLoader"


def test_filesystem_registration(environment_path: Path) -> None:
    with patch("dissect.target.filesystem.FILESYSTEMS", []) as mocked_filesystems:
        copy_different_plugin_files(environment_path, "filesystem.py")
        load_modules_from_paths([environment_path])

        assert len(mocked_filesystems) == 1
        assert mocked_filesystems[0].__name__ == "TestFilesystem"


def test_container_registration(environment_path: Path) -> None:
    with patch("dissect.target.container.CONTAINERS", []) as mocked_containers:
        copy_different_plugin_files(environment_path, "container.py")
        load_modules_from_paths([environment_path])

        assert len(mocked_containers) == 1
        assert mocked_containers[0].__name__ == "TestContainer"


def test_register_file(environment_path: Path) -> None:
    with patch("dissect.target.container.CONTAINERS", []) as mocked_containers:
        copy_different_plugin_files(environment_path, "container.py")
        load_modules_from_paths([environment_path / "container.py"])

        assert len(mocked_containers) == 1
        assert mocked_containers[0].__name__ == "TestContainer"


@pytest.mark.parametrize(
    "filename, expected_module",
    [
        ("test.py", "test"),
        ("hello_world/help.py", "hello_world.help"),
        ("path/to/file.py", "path.to.file"),
    ],
)
def test_filesystem_module_registration(environment_path: Path, filename: str, expected_module: str) -> None:
    path = environment_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()

    load_modules_from_paths([environment_path])

    assert expected_module in sys.modules.keys()
