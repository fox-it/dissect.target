import pytest

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.ntfs.usnjrnl import UsnjrnlPlugin

from ._utils import absolute_path


@pytest.fixture
def mocked_timeline_plugin(target_win):
    filesystem = NtfsFilesystem(usnjrnl=open(absolute_path("data/usnjrnl.bin"), "rb"))
    target_win.filesystems = [filesystem]
    plugin = UsnjrnlPlugin(target_win)
    return plugin


def test_usnjrnl_normal(mocked_timeline_plugin):
    """Test parsing of a usnjrnl file"""

    data = list(mocked_timeline_plugin.usnjrnl())

    assert len(data) == 15214
