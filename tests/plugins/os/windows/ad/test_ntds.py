from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.ad.ntds import NtdsPlugin
from tests._utils import absolute_path
from tests.plugins.os.windows.credential.test_lsa import map_lsa_system_keys

if TYPE_CHECKING:
    import pathlib

    from _pytest.fixtures import SubRequest

    from dissect.target.target import Target


GOAD_NTDS = absolute_path("_data/plugins/os/windows/ad/ntds/goad/ntds.dit.gz")
LARGE_NTDS = absolute_path("_data/plugins/os/windows/ad/ntds/large/ntds.dit.gz")

DEFAULT_NTDS_LOCATION = "c:/windows/ntds/ntds.dit"


def map_ntds_path(hive_hklm: VirtualHive, ntds_path: pathlib.Path) -> str:
    _, registry_path = NtdsPlugin.NTDS_PARAMETERS_REGISTRY_PATH.replace("CurrentControlSet", "ControlSet001").split(
        "\\", maxsplit=1
    )

    hive_hklm.map_key(registry_path, VirtualKey(hive_hklm, registry_path))
    hive_hklm.map_value(
        registry_path,
        NtdsPlugin.NTDS_PARAMETERS_DB_VALUE,
        VirtualValue(hive_hklm, NtdsPlugin.NTDS_PARAMETERS_DB_VALUE, str(ntds_path)),
    )

    return hive_hklm


@pytest.fixture(
    params=[
        (
            LARGE_NTDS,
            {
                "JD": "3f52f315",
                "Skew1": "57cf423d",
                "GBG": "d972e780",
                "Data": "45d316ac",
            },
            "large",
        ),
        (
            GOAD_NTDS,
            {
                "JD": "ebaa656d",
                "Skew1": "959f28b0",
                "GBG": "0766a85b",
                "Data": "1af1b31e",
            },
            "goad",
        ),
    ]
)
def target_win_ntds(target_win: Target, hive_hklm: VirtualHive, request: SubRequest) -> Target:
    ntds_path, syskey, test_type = request.param

    map_ntds_path(hive_hklm, DEFAULT_NTDS_LOCATION)
    map_lsa_system_keys(hive_hklm, syskey)

    target_win.fs.map_file(DEFAULT_NTDS_LOCATION, ntds_path, compression="gzip")
    target_win.add_plugin(NtdsPlugin)

    target_win.test_type = test_type

    return target_win


def test_user_accounts(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ntds.user_accounts())

    sam_name_to_ntlm_hash_mapping = {
        # Large test data
        "henk.devries": "ac85b86a678c2b19e49cbcd236d037e9",  # Password hash of Winter2025!
        "beau.terham": "59ebeca2c2b7b942370f69e155df8ba2",  # Password hash of Zomer2027!@
        # GOAD test data
    }

    assert len(results) == 26955 if target_win_ntds.test_type == "large" else 78

    for record in results:
        if record.sam_name not in sam_name_to_ntlm_hash_mapping:
            continue

        assert sam_name_to_ntlm_hash_mapping[record.sam_name] == record.nt


def test_computer_accounts(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ntds.computer_accounts())

    assert len(results) == 9045 if target_win_ntds.test_type == "large" else 8
