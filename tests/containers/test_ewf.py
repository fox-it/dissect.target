from __future__ import annotations

import os

from dissect.target import container
from dissect.target.containers.ewf import EwfContainer
from tests._utils import absolute_path


def test_ewf_container() -> None:
    """Test that EWF containers are properly opened."""
    path = absolute_path("_data/containers/ewf/small.E01")

    fh = container.open(path)
    assert isinstance(fh, EwfContainer)
    a = fh.read(20)
    assert a == b"testdissecte01\n"
    assert fh.tell() == 15
    fh.seek(0, whence=os.SEEK_SET)
    assert fh.read(20) == b"testdissecte01\n"
    fh.close()


def test_ewf_container_splitted() -> None:
    """Test that EWF containers are properly opened when container is split among multiple files"""
    path = absolute_path("_data/containers/ewf/splitted.E01")

    fh = container.open(path)
    assert isinstance(fh, EwfContainer)
    assert fh.read(20) == b"\x90g`\x023H\xd2_\x18\x9cj\xb7G\x80\x8c\xf1\r\x7f\x80\xda"
    fh.seek(0, whence=os.SEEK_END)
    assert fh.tell() == 1075200
    fh.seek(-15, whence=os.SEEK_CUR)
    assert fh.read(20) == b"CZ_\xbe\xc0\xf5\xfb\xf2\x7f/a\xd6\xb5w="
    fh.close()

