from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.ad.ntds import DEFAULT_NT_HASH
from tests._utils import absolute_path
from tests.plugins.os.windows.credential.test_credhist import md4
from tests.plugins.os.windows.test_lsa import map_lsa_system_keys

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
    """Tests if ``ad.users`` outputs the correct amount of records and their content"""
    cn_to_ntlm_hash_mapping = {
        "krbtgt": "988160b622eb37838dbff2523015e44c",  # Unknown Password
        "NORTH$": "8048b2621bb71945d6ca6e9a14084af1",  # Unknown Password
        "ESSOS$": "f1580437d0120689ad3909b9fe9b74fe",  # Unknown Password
        "Administrator": "c66d72021a2d4744409969a581a1705e",  # Unknown Password
        "renly.baratheon": "f667bd83b30c87801cef53856618d534",  # Unknown Password
        "vagrant": md4("vagrant").hex(),
        "lord.varys": md4("_W1sper_$").hex(),
        "jaime.lannister": md4("cersei").hex(),
        "tyron.lannister": md4("Alc00L&S3x").hex(),
        "cersei.lannister": md4("il0vejaime").hex(),
        "joffrey.baratheon": md4("1killerlion").hex(),
        "stannis.baratheon": md4("Drag0nst0ne").hex(),
        "petyer.baelish": md4("@littlefinger@").hex(),
        "tywin.lannister": md4("powerkingftw135").hex(),
        "maester.pycelle": md4("MaesterOfMaesters").hex(),
    }

    results = list(target_win_ntds.ad.users())

    assert len(results) == 33

    for result in results:
        if result.cn not in cn_to_ntlm_hash_mapping or result.nt == DEFAULT_NT_HASH:
            continue

        assert cn_to_ntlm_hash_mapping[result.cn] == result.nt


def test_computers(target_win_ntds: Target) -> None:
    """Tests if ``ad.computers`` outputs the correct amount of records and their content"""
    cn_to_ntlm_hash_mapping = {
        "KINGSLANDING": "00e3201a59af7ecc72e939a8c9794c64",  # Unknown Password
    }

    results = list(target_win_ntds.ad.computers())

    assert len(results) == 3

    for result in results:
        if result.cn not in cn_to_ntlm_hash_mapping or result.nt == DEFAULT_NT_HASH:
            continue

        assert cn_to_ntlm_hash_mapping[result.cn] == result.nt


def test_group_policies(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ad.group_policies())

    assert len(results) == 5
