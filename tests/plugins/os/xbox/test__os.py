from __future__ import annotations

from dissect.target.plugins.os.xbox._os import XboxPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_xbox_os() -> None:
    """Test if we can detect the Xbox operating system from a retail Xbox HDD image."""
    path = absolute_path("_data/volumes/xbox/xbox_hdd.qcow2")

    t = Target.open(path)
    assert t._os_plugin is XboxPlugin

    assert sorted(t.fs.listdir("/")) == ["c:", "e:", "x:", "y:", "z:"]
