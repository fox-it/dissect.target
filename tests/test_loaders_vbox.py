from unittest.mock import call, patch

from dissect.target.loaders.vbox import VboxLoader


@patch("dissect.hypervisor.vdi")
@patch("dissect.hypervisor.vdi.Vbox")
@patch("pathlib.Path")
def test_vbox_loader(vdi, vbox, Path, mock_target) -> None:
    vbox.return_value = vbox
    vbox.disks.return_value = [Path("/mock.vdi")]
    vbox_loader = VboxLoader(Path("/mock.vbox"))
    vbox_loader.map(mock_target)
    expected = [call.disks()]
    del vbox.mock_calls[0]
    assert expected == vbox.mock_calls
    assert len(mock_target.disks) == 1
