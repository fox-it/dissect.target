from unittest.mock import call, patch

from dissect.target.loaders.vbox import VBoxLoader


@patch("pathlib.Path")
@patch("dissect.target.loaders.vbox.VBox")
def test_vbox_loader(VBox, Path, target_bare) -> None:
    VBox.return_value = VBox
    VBox.disks.return_value = [Path("/mock.vdi")]
    vbox_loader = VBoxLoader(Path("/mock.vbox"))
    vbox_loader.map(target_bare)
    expected = [call.disks()]
    del VBox.mock_calls[0]
    assert expected == VBox.mock_calls
    assert len(target_bare.disks) == 1
