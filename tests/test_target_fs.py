import os
import random
import shutil
from unittest.mock import Mock

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.tools.fs import _extract_path, cp


@pytest.fixture
def vfs(files) -> VirtualFilesystem:
    vfs = VirtualFilesystem()
    for file in files:
        vfs.map_file_entry(file, VirtualFile(vfs, file, None))
    return vfs


@pytest.mark.parametrize("files", [["file"]])
def test_extract_file(vfs):
    output_file = f"/tmp/file{random.randint(0, 1000)}"
    try:
        _extract_path(vfs.path("file"), output_file)
    except Exception:  # noqua
        # The files are virtual, so we expect the method to raise an exception
        pass

    assert os.path.exists(output_file)
    # cleanup
    os.remove(output_file)


@pytest.mark.parametrize("files", [[]])
def test_file_not_exist(vfs):
    output_file = f"/tmp/file{random.randint(0, 1000)}"

    _extract_path(vfs.path("file"), output_file)

    assert not os.path.exists(output_file)


@pytest.mark.parametrize("files", [["dir/"]])
def test_extract_directory(vfs):
    output = f"/tmp/dir{random.randint(0, 1000)}"

    _extract_path(vfs.path("dir"), f"{output}/test")

    assert os.path.isdir(f"{output}/test")

    # cleanup
    shutil.rmtree(output)


@pytest.mark.parametrize("files", [["dir/", "dir/test"]])
def test_cp_file_path(vfs):
    args = Mock()
    args.output = f"/tmp/dir{random.randint(0, 1000)}"

    cp(None, vfs.path("dir/test"), args)

    assert os.path.isfile(f"{args.output}/test")

    # cleanup
    shutil.rmtree(args.output)


@pytest.mark.parametrize("files", [["dir/", "dir/test"]])
def test_cp_directory(vfs):
    args = Mock()
    args.output = f"/tmp/dir{random.randint(0, 1000)}"

    cp(None, vfs.path("dir"), args)

    assert os.path.isfile(f"{args.output}/test")

    # cleanup
    shutil.rmtree(args.output)


@pytest.mark.parametrize("files", [[]])
def test_cp_non_existing_file(vfs):
    args = Mock()
    args.output = f"/tmp/dir{random.randint(0, 1000)}"

    cp(None, vfs.path("dir/test"), args)

    assert not os.path.exists(args.output)


@pytest.mark.parametrize(
    "files",
    [["dir/", "dir/test", "dir/subdirectory_1/", "dir/subdirectory_2/", "dir/subdirectory_3/subdirectory_4/"]],
)
def test_cp_subdirectories(vfs, files):
    args = Mock()
    args.output = f"/tmp/dir{random.randint(0, 1000)}"

    cp(None, vfs.path("dir/"), args)

    filesystem_files = (file.replace("dir/", "") for file in files)

    for directories in filesystem_files:
        assert os.path.exists(f"{args.output}/{directories}")
    # cleanup
    shutil.rmtree(args.output)
