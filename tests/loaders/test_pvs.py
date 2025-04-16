from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

from dissect.target.loaders.pvs import PvsLoader

if TYPE_CHECKING:
    from dissect.target.target import Target


@patch("dissect.target.loaders.pvs.HddContainer")
@patch("dissect.target.loaders.pvs.pvs.PVS")
def test_pvs_loader(PVS: Mock, HddContainer: Mock, target_bare: Target) -> None:
    PVS.return_value = PVS
    PVS.disks.return_value = ["mock.hdd"]
    HddContainer.return_value = HddContainer

    pvs_loader = PvsLoader(Mock())
    pvs_loader.map(target_bare)

    expected = [call.disks()]
    del PVS.mock_calls[0]
    assert expected == PVS.mock_calls
    assert len(target_bare.disks) == 1
