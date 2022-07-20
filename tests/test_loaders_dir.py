from pathlib import Path

from dissect.target.loaders.dir import DirLoader, find_dirs

from ._utils import mkdirs


def test_dir_loader_windows(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["windows/system32"])

    os_type, dirs = find_dirs(root)
    assert os_type == "windows"
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1


def test_dir_loader_winnt(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["winnt"])

    os_type, dirs = find_dirs(root)
    assert os_type == "windows"
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1


def test_dir_loader_linux(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["etc", "var"])

    os_type, dirs = find_dirs(root)
    assert os_type == "linux"
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1


def test_dir_loader_macos(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["Library"])

    os_type, dirs = find_dirs(root)
    assert os_type == "osx"
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1


def test_dir_loader_windows_drive_letters(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["C/windows/system32", "D/test", "E/test"])

    os_type, dirs = find_dirs(root)
    assert os_type == "windows"
    assert len(dirs) == 3

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 3
    assert len(mock_target.fs.mounts) == 3
