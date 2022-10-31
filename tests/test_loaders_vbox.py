from unittest.mock import call, patch

from dissect.target.loaders.vbox import VboxLoader


@patch("dissect.hypervisor.vdi")
@patch("dissect.hypervisor.vdi.Vbox")
@patch("pathlib.Path")
def test_vbox_loader(vdi, vbox, Path, mock_target) -> None:
    vbox_loader = VboxLoader(Path("/mock.vbox"))
    vbox_loader.map(mock_target)
    expected = [call().disks(), call().disks().__iter__()]
    del vbox.mock_calls[0]
    assert expected == vbox.mock_calls
