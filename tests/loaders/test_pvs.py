from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, call, patch

from dissect.target.loaders.pvs import PvsLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@patch("pathlib.Path")
@patch("dissect.target.loaders.pvs.HddContainer")
@patch("dissect.target.loaders.pvs.pvs.PVS")
def test_pvs_loader(PVS: Mock, HddContainer: Mock, Path: Path, target_bare: Target) -> None:
    PVS.return_value = PVS
    PVS.disks.return_value = ["mock.hdd"]
    HddContainer.return_value = HddContainer

    pvs_loader = PvsLoader(Path("/mock.pvs"))
    pvs_loader.map(target_bare)

    expected = [call.disks()]
    del PVS.mock_calls[0]
    assert expected == PVS.mock_calls
    assert len(target_bare.disks) == 1
