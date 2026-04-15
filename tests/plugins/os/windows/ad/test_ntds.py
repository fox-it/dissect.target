from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.ad.ntds import DEFAULT_NT_HASH
from tests.plugins.os.windows.credential.test_credhist import md4

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_users(target_win_ntds: Target) -> None:
    """Tests if ``ad.users`` outputs the correct amount of records and their content."""
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
    """Tests if ``ad.computers`` outputs the correct amount of records and their content."""
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


def test_secretsdump(target_win_ntds: Target) -> None:
    """Tests if ``ad.secretsdump`` outputs the correct credentials in secretsdump format."""
    results = list(target_win_ntds.ad.secretsdump())

    assert len(results) == 82  # 34 hashes and 48 Kerberos keys
    assert (
        results[0]
        == "Administrator:500:aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e::: (pwdLastSet=2025-12-18 17:11:45.510290+00:00) (status=Enabled)"  # noqa: E501
    )
    assert results[10] == "krbtgt_history0:502:7bd05f9617e7f15e3a6ca037e55f713f:988160b622eb37838dbff2523015e44c:::"
    assert results[-1] == "ESSOS$:des-cbc-md5:f715e30273382546"
