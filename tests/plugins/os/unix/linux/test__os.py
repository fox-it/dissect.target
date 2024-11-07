import pathlib
from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from tests.conftest import make_os_target


@pytest.fixture
def target_linux_proc_sys(tmp_path: pathlib.Path) -> Iterator[Target]:
    root_fs = VirtualFilesystem()
    root_fs.makedirs("/proc/sys")
    root_fs.makedirs("/sys/module")
    target_linux_proc_sys = make_os_target(tmp_path, LinuxPlugin, root_fs)

    yield target_linux_proc_sys


@pytest.fixture
def target_linux_windows_folder(tmp_path: pathlib.Path) -> Iterator[Target]:
    root_fs = VirtualFilesystem()
    root_fs.makedirs("/windows")
    root_fs.makedirs("/var")
    root_fs.makedirs("/etc")
    root_fs.makedirs("/opt")

    target_linux_proc_sys = make_os_target(tmp_path, LinuxPlugin, root_fs)

    yield target_linux_proc_sys


def test_linux_os(target_linux: Target) -> None:
    target_linux.add_plugin(LinuxPlugin)

    assert target_linux.os == "linux"


def test_linux_os_windows_folder(target_linux_windows_folder: Target) -> None:
    target_linux_windows_folder.add_plugin(LinuxPlugin)
    assert target_linux_windows_folder._os_plugin.detect(target_linux_windows_folder) is not None
    assert target_linux_windows_folder.os == "linux"


def test_linux_os_proc_sys(target_linux_proc_sys: Target) -> None:
    assert target_linux_proc_sys._os_plugin.detect(target_linux_proc_sys) is not None
    assert target_linux_proc_sys.os == "linux"
