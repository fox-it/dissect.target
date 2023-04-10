from unittest.mock import call, patch

from dissect.target.loaders.pvs import PvsLoader


@patch("pathlib.Path")
@patch("dissect.target.loaders.pvs.HddContainer")
@patch("dissect.target.loaders.pvs.pvs.PVS")
def test_pvs_loader(PVS, HddContainer, Path, mock_target):
    PVS.return_value = PVS
    PVS.disks.return_value = ["mock.hdd"]
    HddContainer.return_value = HddContainer

    pvs_loader = PvsLoader(Path("/mock.pvs"))
    pvs_loader.map(mock_target)

    expected = [call.disks()]
    del PVS.mock_calls[0]
    assert expected == PVS.mock_calls
    assert len(mock_target.disks) == 1
