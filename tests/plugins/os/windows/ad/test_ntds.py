from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.ad.ntds import NtdsPlugin
from tests._utils import absolute_path
from tests.plugins.os.windows.credential.test_lsa import map_lsa_system_keys

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.fixture
def target_win_ntds(target_win: Target, hive_hklm: VirtualHive) -> Target:
    registry_path = "SYSTEM\\ControlSet001\\Services\\NTDS\\Parameters"
    hive_hklm.map_key(registry_path, VirtualKey(hive_hklm, registry_path))
    hive_hklm.map_value(
        registry_path,
        "DSA Database file",
        VirtualValue(hive_hklm, "DSA Database file", "c:/windows/ntds/ntds.dit"),
    )

    map_lsa_system_keys(
        hive_hklm,
        {
            "JD": "ebaa656d",
            "Skew1": "959f28b0",
            "GBG": "0766a85b",
            "Data": "1af1b31e",
        },
    )

    target_win.fs.map_file(
        "c:/windows/ntds/ntds.dit",
        absolute_path("_data/plugins/os/windows/ad/ntds/goad/ntds.dit.gz"),
        compression="gzip",
    )

    return target_win


def test_users(target_win_ntds: Target) -> None:
    assert NtdsPlugin(target_win_ntds).check_compatible() is None

    results = list(target_win_ntds.ad.users())

    assert len(results) == 78


def test_computers(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ad.computers())

    assert len(results) == 8
