from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.bitlocker.autounlock import BitlockerAutoUnlock
from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
from dissect.target.plugins.os.windows.lsa import LSAPlugin
from dissect.target.volume import Volume
from tests._utils import open_file_gz
from tests.conftest import add_win_user
from tests.plugins.os.windows.test__os import map_version_value

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def test_bitlocker_auto_unlock_to_go_compat_mode(
    target_win: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive, hive_hku: VirtualHive
) -> None:
    """Test if Bitlocker auto unlock works. Generated on Windows 11 24H2.

    PS C:\\WINDOWS\\system32> manage-bde -protectors -get E:
    BitLocker Drive Encryption: Configuration Tool version 10.0.26100
    Copyright (C) 2013 Microsoft Corporation. All rights reserved.

    Volume E: [New Volume]
    All Key Protectors

        Numerical Password:
            ID: {4C8CCF1F-886E-4520-9C41-B9A3B5FCA315}
            Password:
                630102-001870-388410-330154-195536-158026-674817-559119
            Backup type:
                Printed

        External Key:
            ID: {84D0AD0A-A440-4606-8D6F-6B20963B3416}
            External Key File Name:
                84D0AD0A-A440-4606-8D6F-6B20963B3416.BEK

        Password:
            ID: {A0EF7ECE-406D-4D59-9EDE-B9BF32A3268B}
    """
    with open_file_gz("_data/plugins/os/windows/bitlocker/autounlock/volume.bin.gz") as vol_fh:
        # Prepare user DPAPI master key
        map_version_value(target_win, "CurrentVersion", 10.0)
        add_win_user(
            hive_hklm,
            hive_hku,
            target_win,
            sid="S-1-5-21-3656658933-2463154391-3030686545-1002",
            home="C:\\Users\\user",
        )
        fs_win.map_file_fh(
            "Users/user/AppData/Roaming/Microsoft/Protect/S-1-5-21-3656658933-2463154391-3030686545-1002/5bbce67f-f0e6-4dbc-a2c7-25ba1949a9d0",
            BytesIO(
                bytes.fromhex(
                    "020000000000000000000000350062006200630065003600370066002d006600"
                    "3000650036002d0034006400620063002d0061003200630037002d0032003500"
                    "6200610031003900340039006100390064003000000000000000000005000000"
                    "b000000000000000900000000000000014000000000000000000000000000000"
                    "020000006d0907a8ee09a015e66619f646f134d2401f00000e80000010660000"
                    "ccc1fdaba4494408b41e5775cdf5a44cc425d73432c1ac7434bb88cb8729933a"
                    "85401723f35e6ec0c4606c9a132edd9873de5bfe9d6e664c83b51f50f4130c26"
                    "53838ba5acea7f4598c7c0dce9ebb519ff5bcd8796feb8e3054effb031cc4e3e"
                    "6fa42c2da3b8d108a4c47d0374a002b24aed76ddeac41eef2cfc85ab8400e29d"
                    "f1e9b472ada37d8747f2d5fb84ac954402000000a6b52b6a17299893a1fea3cb"
                    "88308a51401f00000e80000010660000c00fd3933e665ca33a0fad3c8171ac9b"
                    "8cbfcd8375317ebfd9364fc6ca70c7646519ca135f55efe12e2e893009e1f0cd"
                    "28b785a2ebf14bd7e498e9d48bfa00a32981eb871d678d50f250eadeed2d81c1"
                    "9fba018bed6dd3b17bc1842e0033a34fdf0c4d7a75eac27db561eedcc7489643"
                    "030000004f72221850c7404e96b498ded694e416",
                )
            ),
        )
        keychain.register_key(
            key_type=keychain.KeyType.PASSPHRASE,
            value="password",
            identifier=None,
            provider="user",
        )

        # Add an encrypted volume
        target_win.volumes.add(
            Volume(
                fh=vol_fh,
                number=1,
                offset=0x10000,
                size=104857088,
                name="Basic data partition",
                vtype=313451834834061278758346828331453159879,
                guid="e6fde785-f737-47be-b9ad-28137359d733",
            )
        )

        # Add E: mount info to the registry
        name = "System\\MountedDevices"
        key = VirtualKey(hive_hklm, name)
        key.add_value(
            "\\DosDevices\\E:",
            VirtualValue(hive_hklm, "\\DosDevices\\E:", b"DMIO:ID:\x85\xe7\xfd\xe67\xf7\xbeG\xb9\xad(\x13sY\xd73"),
        )
        hive_hklm.map_key(name, key)

        # Add FveAutoUnlock entry to the HKCU
        name = "Software\\Microsoft\\Windows\\CurrentVersion\\FveAutoUnlock\\{84d0ad0a-a440-4606-8d6f-6b20963b3416}"
        key = VirtualKey(hive_hku, name)
        key.add_value(
            "element",
            VirtualValue(
                hive_hku,
                "element",
                bytes.fromhex(
                    "01000000d08c9ddf0115d1118c7a00c04fc297eb010000007fe6bc5be6f0bc4d"
                    "a2c725ba1949a9d000000000020000000000106600000001000020000000c41f"
                    "50cb50f936495971b1745490acbf234d211cd9c46f37f1b0812daeb937920000"
                    "00000e8000000002000020000000d67084baa5bc348ff109f739bdecb64eaace"
                    "f5c2e791a1481f28c67a2b82fa234000000084094946676b417657899ffdc6ec"
                    "b8633bea28de2d775f81f192353263a1d6ef3e90ebc149803cc1adb53e2723c0"
                    "7fba802242566e6512fa45de8ed80f58fdda40000000d9feda6530f07522203b"
                    "fa1810b8d9acf557c7ea8ca5c7b12dad7f8002bc308867cad1c7852b7b9e6770"
                    "f0b9e91028d0a14102d109daed8b0c25381d369d07e4"
                ),
            ),
        )
        key.add_value(
            "info",
            VirtualValue(
                hive_hku,
                "info",
                bytes.fromhex(
                    "01000000d08c9ddf0115d1118c7a00c04fc297eb010000007fe6bc5be6f0bc4d"
                    "a2c725ba1949a9d00000000002000000000010660000000100002000000086fb"
                    "e697ee9b0193a2ee894b0826f7c3e535ddd68b85415251d2f76278eb14d80000"
                    "00000e80000000020000200000009767b90eecc33397e47ec72cc930f6b0526f"
                    "6ef489f2a881afa52e362ba71885900000009e8efeee13a8ee9a3d8a59403dd1"
                    "2a489ccbda73b223df997205686861a8c2888079f8bcc29e8eb63fe2b4571ef3"
                    "734dc311123fbbe6a6b3a979d5cc94ed3533f64304f9911ad44cf8569f088722"
                    "f3e2fcf7743cc2f17f730ec6c5fe861345852694635f64375ab24519c94df91d"
                    "479c575334d3121748bea183c7341ab76e432d7703f53ff84e49559820ebba87"
                    "235840000000119f9cf38d172b0af1b94fe000835bbad7911da658ca9d3de6b3"
                    "1108984587bb9ee530b73cf2074488d5f375b572e9ce1d22da071ceca1930329"
                    "cf20029dc9bd"
                ),
            ),
        )
        hive_hku.map_key(name, key)

        target_win.add_plugin(LSAPlugin, check_compatible=False)
        target_win.add_plugin(DPAPIPlugin)
        target_win.add_plugin(BitlockerAutoUnlock)
        target_win.apply()

        # Test if FveAutoUnlock registry discovery works
        record = next(target_win.bitlocker.auto_unlock())
        assert record.ts == datetime(2026, 9, 16, 10, 4, 2, 673000, tzinfo=timezone.utc)
        assert record.guid == "84d0ad0a-a440-4606-8d6f-6b20963b3416"
        assert record.key == "91ce76fd339e0243e73a117d9868011e47e636f9cc8925feee80d6c9b7757d5e"
        assert str(record.source).endswith(
            "\\HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\FveAutoUnlock\\{84d0ad0a-a440-4606-8d6f-6b20963b3416}"
        )

        # Test if apply() correctly mounted and unlocked the BDE drive
        assert target_win.fs.path("e:\\hello.txt").read_text() == "Hello world!\n"
