from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.credential.lsa import LSAPlugin
from tests.plugins.os.windows.test__os import map_version_value

if TYPE_CHECKING:
    from dissect.target.target import Target

SYSTEM_KEY = "SYSTEM\\ControlSet001\\Control\\LSA"
POLICY_KEY_PATH_NT5 = "SECURITY\\Policy\\PolSecretEncryptionKey"
POLICY_KEY_PATH_NT6 = "SECURITY\\Policy\\PolEKList"
SECRETS_KEY = "SECURITY\\Policy\\Secrets"


def map_lsa_system_keys(hive_hklm: VirtualHive, subkeys: dict) -> None:
    """Add values to the registry required to calculate the SYSKEY / BootKey."""

    if subkeys.keys() != {"Data", "GBG", "JD", "Skew1"}:
        raise ValueError("Invalid subkey names")

    system_key = VirtualKey(hive_hklm, SYSTEM_KEY)

    for name, value in subkeys.items():
        system_key.add_subkey(name, VirtualKey(hive_hklm, name, class_name=value))

    hive_hklm.map_key(SYSTEM_KEY, system_key)


def map_lsa_polkey(hive_hklm: VirtualHive, path: str, value: bytes) -> None:
    """Add policy key to the registry which is required to derive the LSA key of the system."""

    policy_key = VirtualKey(hive_hklm, path)
    policy_key.add_value("(Default)", value)
    hive_hklm.map_key(path, policy_key)


def map_lsa_secrets(hive_hklm: VirtualHive, secrets: dict[str, bytes | tuple[bytes, bytes]]) -> None:
    """Add given encrypted LSA secrets to the ``hive_hklm`` :class"`VirtualHive`."""

    secrets_key = VirtualKey(hive_hklm, SECRETS_KEY)

    for name, value in secrets.items():
        if not isinstance(value, (bytes, tuple)):
            raise TypeError(f"Given value for {name} should be in bytes!")

        if isinstance(value, tuple):
            curr_val, old_val = value
        else:
            curr_val = value
            old_val = None

        secret_key = VirtualKey(hive_hklm, name)
        secret_key.timestamp = datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

        currval_key = VirtualKey(hive_hklm, "CurrVal")
        currval_key.add_value("(Default)", curr_val)
        secret_key.add_subkey("CurrVal", currval_key)

        if old_val:
            oldval_key = VirtualKey(hive_hklm, "OldVal")
            oldval_key.add_value("(Default)", old_val)
            secret_key.add_subkey("OldVal", oldval_key)

        secrets_key.add_subkey(name, secret_key)

    hive_hklm.map_key(SECRETS_KEY, secrets_key)


def test_lsa_secrets_win_10(target_win: Target, hive_hklm: VirtualHive) -> None:
    """Test decrypting LSA secrets of a Windows 10 system."""

    map_lsa_system_keys(
        hive_hklm,
        {
            "Data": "3b03ce4f",
            "GBG": "7bf5e093",
            "JD": "51fe8c74",
            "Skew1": "3e14f655",
        },
    )

    policy_key = VirtualKey(hive_hklm, POLICY_KEY_PATH_NT6)
    policy_key_value = (
        "00000001ecffe17b2a997440aa939adbff26f1fc030000000000000061f61040"
        "72b7b9117289a891bc1edb9fa83fafae5d8648b8674825dc9bdcf1bf5ffbe591"
        "27fd3a1baca6c5447530574c27a41ab721b13e54a9af857e682b8458859c0fab"
        "55461a8f1b2b8c12d8f186a80991012e2d3ede5b1167554c726e404ed0eb96f6"
        "488b90ece5b0b3ef9bf244f35dd65a30b2b450c4e227838810b631564b89300e"
        "d4355040f23890f8b6b8eab8"
    )
    policy_key.add_value("(Default)", bytes.fromhex(policy_key_value))
    hive_hklm.map_key(POLICY_KEY_PATH_NT6, policy_key)

    map_lsa_secrets(
        hive_hklm,
        {
            "DPAPI_SYSTEM": (
                # CurrVal
                bytes.fromhex(
                    "00000001001f9b85984f68a8ed3e9d44dbd5b79c0300000000000000835b4ff6"
                    "6e74154ffab75afd31a2860616c87411bc97d368a068fca62d1564ae1396f88e"
                    "06de87b5e5632c668538ee36c75f67cee98d49ebc1e88fa7e9be16144af31e8e"
                    "5fd78329279e50d792e8a6b35a59cb55016748ecd8e12f148b1d32b3"
                ),
                # OldVal
                bytes.fromhex(
                    "00000001001f9b85984f68a8ed3e9d44dbd5b79c0300000000000000835b4ff6"
                    "6e74154ffab75afd31a2860616c87411bc97d368a068fca62d1564ae1396f88e"
                    "06de87b5e5632c668538ee36c75f67cee98d49ebc1e88fa7e9be16144af31e8e"
                    "5fd78329279e50d792e8a6b35a59cb55016748ecd8e12f148b1d32b3"
                ),
            ),
        },
    )

    map_version_value(target_win, "CurrentVersion", 10.0)
    target_win.add_plugin(LSAPlugin)

    assert target_win.lsa.syskey.hex() == "7b143e8c93f5037451f6fe3bcee04f55"
    assert target_win.lsa.lsakey.hex() == "26c34326a9f1d8db4f465487857d47d1481f0040c6becc8c65862c0cfb210631"
    assert target_win.lsa._secrets == {
        "DPAPI_SYSTEM": bytes.fromhex(
            "2c000000000000000000000000000000010000003ac5746c27b424489300a781"
            "ba237676da7605083e7947c67271c16fc84cc567870148931cf29eb800000000"
        ),
        "DPAPI_SYSTEM_OldVal": bytes.fromhex(
            "2c000000000000000000000000000000010000003ac5746c27b424489300a781"
            "ba237676da7605083e7947c67271c16fc84cc567870148931cf29eb800000000"
        ),
    }

    records = list(target_win.lsa.secrets())
    assert len(records) == 2

    assert records[0].ts == datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert records[0].name == "DPAPI_SYSTEM"
    assert (
        records[0].value
        == "2c000000000000000000000000000000010000003ac5746c27b424489300a781ba237676da7605083e7947c67271c16fc84cc567870148931cf29eb800000000"  # noqa: E501
    )

    assert records[1].ts == datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert records[1].name == "DPAPI_SYSTEM_OldVal"
    assert (
        records[1].value
        == "2c000000000000000000000000000000010000003ac5746c27b424489300a781ba237676da7605083e7947c67271c16fc84cc567870148931cf29eb800000000"  # noqa: E501
    )


def test_lsa_secrets_win_xp(target_win: Target, hive_hklm: VirtualHive) -> None:
    """Test decrypting LSA secrets of a Windows XP system."""

    map_lsa_system_keys(
        hive_hklm,
        {
            "Data": "0e1eaddb",
            "GBG": "36ec555b",
            "JD": "8397b619",
            "Skew1": "9dfad6c8",
        },
    )

    policy_key = VirtualKey(hive_hklm, POLICY_KEY_PATH_NT5)
    policy_key_value = (
        "0100000001000000000000003e4253c6ab72f73306ffe45a33a4ec5d47d21483"
        "85be6036b4c5bab2666d7f5793f23fed8513577b79abddb40eaa92c7a19b34ab"
        "b9c134e88bf5dd2b2fbf6356"
    )
    policy_key.add_value("(Default)", bytes.fromhex(policy_key_value))
    hive_hklm.map_key(POLICY_KEY_PATH_NT5, policy_key)

    map_lsa_secrets(
        hive_hklm,
        {
            "DPAPI_SYSTEM": bytes.fromhex(
                "3800000038000020acb90c00a26440bdf0382bdbcb5d51a743cb4cca01cfecb3"
                "202848e00dfae25f8f0f3f4710ff37828532b5f600e97f6a00528fd8e0137f49"
                "6fd2d905"
            ),
        },
    )

    map_version_value(target_win, "CurrentVersion", 5.1)
    target_win.add_plugin(LSAPlugin)

    assert target_win.lsa.syskey.hex() == "36fa9db65bec1e1983d6970ead55dbc8"
    assert target_win.lsa.lsakey.hex() == "e32851688cf1e05b1da350682a2e07d2"
    assert target_win.lsa._secrets == {
        "DPAPI_SYSTEM": bytes.fromhex(
            "2c00000001000000010000000307e7679d5bc2d7a2212e216d527af1687f7183"
            "333dac1af5cc9d33ccd97238f3a25ebfaec94ac600000000"
        )
    }

    records = list(target_win.lsa.secrets())
    assert len(records) == 1
    assert records[0].ts == datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert records[0].name == "DPAPI_SYSTEM"
    assert (
        records[0].value
        == "2c00000001000000010000000307e7679d5bc2d7a2212e216d527af1687f7183333dac1af5cc9d33ccd97238f3a25ebfaec94ac600000000"  # noqa: E501
    )
