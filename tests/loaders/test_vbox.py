from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, call, patch

from dissect.target.loaders.vbox import VBoxLoader

if TYPE_CHECKING:
    from dissect.target.target import Target


@patch("dissect.target.loaders.vbox.VBox")
def test_vbox_loader(VBox: Mock, target_bare: Target) -> None:
    VBox.return_value = VBox
    VBox.disks.return_value = [Mock()]
    vbox_loader = VBoxLoader(MagicMock())
    vbox_loader.map(target_bare)
    expected = [call.disks()]
    del VBox.mock_calls[0]
    assert expected == VBox.mock_calls
    assert len(target_bare.disks) == 1
