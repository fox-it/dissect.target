from __future__ import annotations

import io

from dissect.target import container
from dissect.target.containers.ewf import EwfContainer
from dissect.target.filesystem import VirtualFilesystem
from tests._utils import absolute_path


def test_ewf_container() -> None:
    """Test that EWF containers are properly opened.

    Generated with::
    
        echo "testdissecte01" | ewfacquirestream -t small

    """
    path = absolute_path("_data/containers/ewf/small.E01")

    fh = container.open(path)
    assert isinstance(fh, EwfContainer)
    a = fh.read(20)
    assert a == b"testdissecte01\n"
    assert fh.tell() == 15
    fh.seek(0, whence=io.SEEK_SET)
    assert fh.read(20) == b"testdissecte01\n"
    fh.close()


def test_ewf_detect_path() -> None:
    """Test that EWF containers are properly opened, when using the extension based matching."""
    vfs = VirtualFilesystem()
    vfs.map_file("small.E01", absolute_path("_data/containers/ewf/small.E01"))
    fh = container.open(vfs.path("small.E01"))
    assert isinstance(fh, EwfContainer)
    a = fh.read(20)
    assert a == b"testdissecte01\n"
    assert fh.tell() == 15
    fh.seek(0, whence=io.SEEK_SET)
    assert fh.read(20) == b"testdissecte01\n"


def test_ewf_container_splitted() -> None:
    """Test that EWF containers are properly opened when container is split among multiple files.

    ```
    # ewfacquire has a minimum 1mb split size, we generate a bit more than 1Mb of compressed data
    dd if=/dev/urandom bs=512 count=2100 of=random
    cat random | ewfacquirestream -t split -S 1048576
    ```
    """
    path = absolute_path("_data/containers/ewf/split.E01")

    fh = container.open(path)
    assert isinstance(fh, EwfContainer)
    assert fh.read(20) == b'T\x0e\xf4x\x9eT\x17\xda\xca\xbfV\xbb\xda\x99"\xe7S\xa8J\xe7'
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 1075200
    fh.seek(-15, whence=io.SEEK_CUR)
    assert fh.read(20) == b"L5\x089\x8c\xe4\x91~\x9a4\xbcG@\xb4\x11"
    fh.close()


def test_ewf_split_detect_path() -> None:
    """Test that EWF containers are properly opened, when using the extension based matching on multiple files."""
    vfs = VirtualFilesystem()
    vfs.map_file("split.E01", absolute_path("_data/containers/ewf/split.E01"))
    vfs.map_file("split.E02", absolute_path("_data/containers/ewf/split.E02"))
    fh = container.open(vfs.path("split.E01"))
    assert isinstance(fh, EwfContainer)
    assert fh.read(20) == b'T\x0e\xf4x\x9eT\x17\xda\xca\xbfV\xbb\xda\x99"\xe7S\xa8J\xe7'
    fh.seek(0, whence=io.SEEK_END)
    assert fh.tell() == 1075200
    fh.seek(-15, whence=io.SEEK_CUR)
    assert fh.read(20) == b"L5\x089\x8c\xe4\x91~\x9a4\xbcG@\xb4\x11"
