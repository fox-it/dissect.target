from pathlib import Path

import pytest

from dissect.target import Target
from dissect.target.loaders.tar import TarLoader
from dissect.target.loaders.zip import ZipLoader
from dissect.target.plugins.os.windows._os import WindowsPlugin
from tests._utils import absolute_path


def test_case_sensitive_drive_letter(target_bare: Target) -> None:
    tar_file = absolute_path("_data/loaders/acquire/uppercase_driveletter.tar")

    loader = TarLoader(Path(tar_file))
    assert loader.detect(Path(tar_file))
    loader.map(target_bare)

    # mounts = c:
    assert sorted(target_bare.fs.mounts.keys()) == ["c:"]

    # Initialize our own WindowsPlugin to override the detection
    target_bare._os_plugin = WindowsPlugin.create(target_bare, target_bare.fs.mounts["c:"])
    target_bare._init_os()

    # sysvol is now added
    assert sorted(target_bare.fs.mounts.keys()) == ["c:", "sysvol"]

    # WindowsPlugin sets the case sensitivity to False
    assert target_bare.fs.get("C:/test.file").open().read() == b"hello_world"
    assert target_bare.fs.get("c:/test.file").open().read() == b"hello_world"


@pytest.mark.parametrize(
    "archive, expected_drive_letter",
    [
        ("_data/loaders/acquire/test-windows-sysvol-absolute.tar", "c:"),  # C: due to backwards compatibility
        ("_data/loaders/acquire/test-windows-sysvol-relative.tar", "c:"),  # C: due to backwards compatibility
        ("_data/loaders/acquire/test-windows-fs-c-relative.tar", "c:"),
        ("_data/loaders/acquire/test-windows-fs-c-absolute.tar", "c:"),
        ("_data/loaders/acquire/test-windows-fs-x.tar", "x:"),
    ],
)
def test_windows_sysvol_formats(target_default: Target, archive: str, expected_drive_letter: str) -> None:
    path = Path(absolute_path(archive))
    assert TarLoader.detect(path)

    loader = TarLoader(path)
    loader.map(target_default)

    assert WindowsPlugin.detect(target_default)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(target_default.fs.mounts.keys()) == [expected_drive_letter]
    assert target_default.fs.get(f"{expected_drive_letter}/Windows/System32/foo.txt")

def test_windows_sysvol_formats_zip(target_default: Target) -> None:
    path = Path(absolute_path("_data/loaders/acquire/test-windows-fs-c.zip"))
    assert ZipLoader.detect(path)

    loader = ZipLoader(path)
    loader.map(target_default)

    assert WindowsPlugin.detect(target_default)
    # NOTE: for the sysvol archives, this also tests the backwards compatibility
    assert sorted(target_default.fs.mounts.keys()) == ["c:"]
    assert target_default.fs.get("c:/Windows/System32/foo.txt")


def test_anonymous_filesystems(target_default: Target) -> None:
    tar_file = Path(absolute_path("_data/loaders/acquire/test-anon-filesystems.tar"))
    assert TarLoader.detect(tar_file)

    loader = TarLoader(tar_file)
    loader.map(target_default)

    assert target_default.fs.get("$fs$/fs0/foo").open().read() == b"hello world\n"
    assert target_default.fs.get("$fs$/fs1/bar").open().read() == b"hello world\n"
