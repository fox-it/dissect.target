from dissect.target.loaders.dir import DirLoader, find_dirs
from dissect.target.plugin import OperatingSystem
from tests._utils import mkdirs


def test_dir_loader_windows(target_bare, tmp_path):
    root = tmp_path
    mkdirs(root, ["windows/system32"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.WINDOWS
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1


def test_dir_loader_winnt(target_bare, tmp_path):
    root = tmp_path
    mkdirs(tmp_path, ["winnt"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.WINDOWS
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1


def test_dir_loader_linux(target_bare, tmp_path):
    root = tmp_path
    mkdirs(root, ["etc", "var"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.LINUX
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1


def test_dir_loader_macos(target_bare, tmp_path):
    root = tmp_path
    mkdirs(root, ["Library"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.OSX
    assert len(dirs) == 1

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1


def test_dir_loader_windows_drive_letters(target_bare, tmp_path):
    root = tmp_path
    mkdirs(root, ["C/windows/system32", "D/test", "E/test"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.WINDOWS
    assert len(dirs) == 3

    assert DirLoader.detect(root)

    loader = DirLoader(root)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 3
    assert len(target_bare.fs.mounts) == 3
