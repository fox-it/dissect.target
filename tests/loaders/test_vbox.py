from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

from dissect.target.loaders.vbox import VBoxLoader

if TYPE_CHECKING:
    from dissect.target.target import Target


@patch("pathlib.Path")
@patch("dissect.target.loaders.vbox.VBox")
def test_vbox_loader(VBox: Mock, Path: Mock, target_bare: Target) -> None:
    VBox.return_value = VBox
    VBox.disks.return_value = [Path("/mock.vdi")]
    vbox_loader = VBoxLoader(Path("/mock.vbox"))
    vbox_loader.map(target_bare)
    expected = [call.disks()]
    del VBox.mock_calls[0]
    assert expected == VBox.mock_calls
    assert len(target_bare.disks) == 1
