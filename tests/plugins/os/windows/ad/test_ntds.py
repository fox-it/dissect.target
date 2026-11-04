from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

import pytest
from dissect.database.ese.ntds.objects.dnsnode import NamePreferenceRecord, StringRecord, TombStonedRecord
from flow.record.fieldtypes import datetime as dt

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.ad.ntds import DEFAULT_NT_HASH, dns_as_flow_record
from tests._utils import absolute_path
from tests.plugins.os.windows.credential.test_credhist import md4
from tests.plugins.os.windows.test_lsa import map_lsa_system_keys

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive
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
    assert Counter(str(r.source) for r in results) == {"c:\\windows\\ntds\\ntds.dit": 33}

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
    assert Counter(str(r.source) for r in results) == {"c:\\windows\\ntds\\ntds.dit": 3}
    for result in results:
        if result.cn not in cn_to_ntlm_hash_mapping or result.nt == DEFAULT_NT_HASH:
            continue

        assert cn_to_ntlm_hash_mapping[result.cn] == result.nt


def test_group_policies(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ad.group_policies())

    assert len(results) == 5
    assert Counter(str(r.source) for r in results) == {"c:\\windows\\ntds\\ntds.dit": 5}


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


def test_dns_nodes(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ad.dns_nodes())
    results.sort(key=lambda x: x.creation_time)
    assert results[42].dns_name == "_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.sevenkingdoms.local"
    assert results[42].records == [
        "<DnsRecord type='SRV' ttl_seconds=600 timestamp=2025-12-18 17:00:00+00:00 "
        "data=SRVRecord(name_target='kingslanding.sevenkingdoms.local', port=389, "
        "weight=100, priority=0)>"
    ]
    assert results[48].dns_name == "sevenkingdoms.local"
    assert len(results[48].records) == 3
    assert (
        "<DnsRecord type='A' ttl_seconds=600 timestamp=2025-12-19 18:00:00+00:00 "
        "data=DnsARecord(ipv4_address='192.168.56.10')>"
    ) in results[48].records
    assert results[48].creation_time == dt("2025-12-18 17:33:36+00:00")
    assert results[48].last_modified_time == dt("2025-12-19 18:50:44+00:00")
    assert len(results) == 113


def test_dns_records(target_win_ntds: Target) -> None:
    results = list(target_win_ntds.ad.dns_records())
    assert len(results) == 100
    assert Counter([result.dns_type for result in results]) == {
        "NS": 32,
        "SRV": 28,
        "AAAA": 19,
        "A": 17,
        "SOA": 2,
        "CNAME": 2,
    }

    assert Counter([type(result)._desc.name for result in results]) == {
        "windows/ad/dns/node_name": 34,
        "windows/ad/dns/srv": 28,
        "windows/ad/dns/aaaa": 19,
        "windows/ad/dns/a": 17,
        "windows/ad/dns/soa": 2,
    }


def test_dns_as_flow_record() -> None:
    """Test dns records type no present in the GOAD ntds."""
    generic = {
        "ts": dt("2025-12-19 18:00:00+00:00"),
        "dns_name": "sevenkingdoms.local",
        "node_creation_time": dt("2025-12-18 17:33:36+00:00"),
        "node_last_modified_time": "2025-12-19 18:50:44+00:00",
    }
    mx_record = dns_as_flow_record(
        NamePreferenceRecord.from_bytes(b"\x00\x14\x0b\x01\tmailhost2\x00"), {**generic, "dns_type": "MX"}
    )
    assert mx_record.preference == 20
    assert mx_record.name_exchange == "mailhost2"
    assert mx_record._desc.name == "windows/ad/dns/name_preference"

    txt_record = dns_as_flow_record(
        StringRecord.from_bytes(b"\x01q\x02qw\x03qwe\x04qwer\x05qwert\x06qwerty\x08qwertyui"),
        {**generic, "dns_type": "TXT"},
    )
    assert txt_record.string_data == "q\nqw\nqwe\nqwer\nqwert\nqwerty\nqwertyui"
    assert txt_record._desc.name == "windows/ad/dns/string"
    #

    zero_record = dns_as_flow_record(
        TombStonedRecord.from_bytes(b"\xf1\xba\x0c\xa5\xc8 \xdc\x01"), {**generic, "dns_type": "ZERO"}
    )
    assert zero_record.entombed_time == dt("2025-09-08 13:58:24.889522+00:00")
    assert zero_record._desc.name == "windows/ad/dns/tombstoned"

    # DNS record type not unpacked by dissect.database
    atma_records = dns_as_flow_record(b"\xa3\xf1\xba\x0c\xa5\xc8 \xdc\x01", {**generic, "dns_type": "ATMA"})
    assert atma_records.dns_record_data == b"\xa3\xf1\xba\x0c\xa5\xc8 \xdc\x01"
    assert atma_records._desc.name == "windows/ad/dns/generic"
