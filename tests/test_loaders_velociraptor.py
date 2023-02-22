from pathlib import Path

from dissect.target.loaders.velociraptor import VelociraptorLoader

from ._utils import mkdirs


def test_velociraptor_loader_windows_ntfs(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(
        root,
        [
            "uploads.json",
            "uploads/mft/%5C%5C.%5CC%3A/windows/system32",
            "uploads/mft/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
            "uploads/mft/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy2",
        ],
    )

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1
    assert "C." in str(mock_target.filesystems[0].base_path)


def test_dir_loader_linux(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["uploads.json", "uploads/etc", "uploads/var"])

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1


def test_dir_loader_macos(mock_target, tmpdir_name):
    root = Path(tmpdir_name)
    mkdirs(root, ["uploads.json", "uploads/Library"])

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1
