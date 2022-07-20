from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.cit import CITPlugin


CIT_TEST_DATA = bytes.fromhex(
    "9c0500004f0d000091b5000a000c004f0d000000b730bad0906ad7010000bd2d"
    "f810000000aa0a001870001818000c58041c00100100007b4e022e046268009c"
    "c0d860306600d701803a0900100ee8000015004600003e01560114a030030000"
    "300010b8000e410126200600001c001e187002000028004e0216001e3455000f"
    "40080f50000f58080f6c55000f70080f88000f88080fa455000fa0080fc0000f"
    "b8080fdc55000fd0080ff8000fe8080f14ad804f008009854760800708804bb4"
    "1004835f3c805b818168840baa40840b54840b70840b70840baa6c840b78840b"
    "a0840b84840baa80840bd0840b9c840b88840b540005833bb4840b90840b3055"
    "840bcc840b98840b60840be455840ba0840b90840bfc840ba885840bc0840b14"
    "070000816baab0c405f0c4052cc40544c0010632c0418500f7f81552efd62600"
    "4e0004aac006340506c001401b54505424b30304140d004f2c83024201f1c9b8"
    "5648fa312a8158006ec0063a81c806e7b3d0531ca1001e15c004e4c00629c806"
    "bf2cf798513c9f00a6c0043809c3440a9ac00143c00303a5575a88721b1f4002"
    "00002200aa06444202030139ef3c608d622e41af0000ac8001c9295a4035d85f"
    "d72202c22216080b0000c906cfbc0e5e2cf436004b801180cc06ceffb0bf5b62"
    "00004ac006eac006a5c1baffc401140cc3be29c401aa3ec40153c40168c4017d"
    "c401aa92c401a7c401bcc401d1c4016ae6c401fbc401108040c11b250dc4013a"
    "c401414da88a2800e180620007a016c60180288200b9c107b7b74503cf01c107"
    "9ac00f225640038d0428c14e00555cd6220f053f0222040fa0002e7922010000"
    "ed00c402c200e10eea248e05e28bf287a1010000be0c817ca003e50001052103"
    "4c402e41213230782300198002bd08991000c06600e9c60c8fe60061056100e1"
    "04791e23e20210fd031d00409200978ec203419200c2e802e600e50511e10808"
    "751ce205352d007de200d8603ae103ed006102e1051a23800aa140085f12e217"
    "b813e20d6249c14303e60061056100d1e104133512e202f8e005408c3c0013c3"
    "52ee00e105e103e1599a12e2140c0073216d41172103dc0000ed00a102e10361"
    "e003e10648631301a253fc11a102008e00ed00e105e104991201e211a840a800"
    "e20039c30500ed0005e505e5e0030300500053fb2000610205a2442133a1017f"
    "00310496176208210316ca03b700a1ce614102ad004600a139c30330f1e6052e"
    "00114302a2004013a4011b2701010250221b21014e0022fd660700e22aa10221"
    "012906e134e302d76345630161581b440114a811e326070303e38861015c0044"
    "004540005600490043e0005c4000480041005260024411200253004b20034f00"
    "4c100055004da00332005c540057e0024ee0034f20015351e001530059202c54"
    "a0034da8003300210443e001526000a2536069450058200300e00407bf0cbf0c"
    "a90c4c004f0047f530004eb009499f06500aff0cff0cabff0c110b50100f4f50"
    "10453000f62ef00b3f0c45100d9f129f129f12b5390c53b00552101671064d70"
    "17ba4e30004732015f07ff1949301645ff1942501149004e70284fbf300ad900"
    "3f053f053f053f1f5c7007553d1f4df02143581822d0243a37f007df229f034d"
    "b002b5092200b220902f4300bf035f075c7003aa4f700750300047300054f007"
    "8a4db00943100420002f9000b77f273f1b3b1b50101f7125529018ea4db00846"
    "70244c1019912e710a2a41701545f0005c941a4e008254500e58003800367000"
    "da55f046449001311e527f297003bb7f367f364552349f139d13571006fa4130"
    "0043d02ab10fbf361f301f30ab1f301f3d43723648500053f00ebf7f247f247f"
    "247f241f1db10853501d1a525017509a06534b000008fdb45020050171004f01"
    "50014f01a102ff3f001f011201ef038f0213019f027001ff4f014f0110014f01"
    "4f01130150003f05ffa20103610a111963320243009f027001014801"
)

PUU_TEST_DATA = bytes.fromhex(
    "23e86b57010000009700c803ecc52d00d3212e00d3212e00d200000004001f00"
    "1a38ebb951d5e50000d23500c3091d00074c17000f1007000000000000000000"
    "cd070000a9323500c753030023130000285a1564c498d701ecc52d0000000000"
    "01000000ecc52d00624a0000012d0000f00a170100000000"
)

DP_TEST_DATA = bytes.fromhex(
    "d200e800f20000009700000023e86b5738fe2b0100000000285a1564c498d7017"
    "7bb929e9698d70194d1fe00883704000000000031ad7500000000000000000000"
    "00000000000000b4b93400000000000000000000000000000000000000f03f805"
    "101002a2b018014a9042054e98420e4830080cc180800dc180820101d01c02444"
    "340434443614e85100807ab008217fb00837d3cc008045a2891845a28b38f3360"
    "0c094222442d6b32442d00c00804880230648806307dd020180039a8203039bc2"
    "43d1a200807404a500f414af2082a30080002c0330202c0330e41c01c0aa09005"
    "4bf190054"
)


def test_cit_cit_plugin(target_win_tzinfo, hive_hklm):
    system_key_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT\\System"
    system_key = VirtualKey(hive_hklm, system_key_path)

    system_key.add_value(
        "2002134C08A39000000C8D0603667D10",
        VirtualValue(
            hive_hklm,
            "2002134C08A39000000C8D0603667D10",
            CIT_TEST_DATA,
        ),
    )

    hive_hklm.map_key(system_key_path, system_key)

    target_win_tzinfo.add_plugin(CITPlugin)

    results = list(target_win_tzinfo.cit.cit())

    assert len(results) == 48

    program = [r for r in results if r._desc.name == "windows/registry/cit/program"][0]
    assert program.path == "/DEVICE/HARDDISKVOLUME2/WINDOWS/SYSTEM32/CSRSS.EXE"


def test_cit_puu_plugin(target_win, hive_hklm):
    cit_key_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT"
    cit_key = VirtualKey(hive_hklm, cit_key_path)

    cit_key.add_value(
        "PUUActive",
        VirtualValue(
            hive_hklm,
            "PUUActive",
            PUU_TEST_DATA,
        ),
    )

    hive_hklm.map_key(cit_key_path, cit_key)

    target_win.add_plugin(CITPlugin)

    results = list(target_win.cit.puu())

    assert len(results) == 1
    assert results[0].update_key == 1466689571
    assert results[0].build_number == 19042


def test_cit_dp_plugin(target_win, hive_hklm):
    cit_key_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT"
    cit_key = VirtualKey(hive_hklm, cit_key_path)

    cit_key.add_value(
        "DP",
        VirtualValue(
            hive_hklm,
            "DP",
            DP_TEST_DATA,
        ),
    )

    hive_hklm.map_key(cit_key_path, cit_key)

    target_win.add_plugin(CITPlugin)

    results = list(target_win.cit.dp())

    assert len(results) == 15
    assert results[0].update_key == 1466689571
    assert results[0].session_count == 151
    assert results[-1].application == "SKYPE.EXE"
    assert results[-3].duration == 3455412


def test_cit_telemetry_plugin(target_win, hive_hklm):
    win32k_key_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT\\win32k\\1705"
    win32k_key = VirtualKey(hive_hklm, win32k_key_path)

    win32k_key.add_value(
        "\\Device\\HarddiskVolume2\\Windows\\System32\\taskhost.exe",
        VirtualValue(
            hive_hklm,
            "\\Device\\HarddiskVolume2\\Windows\\System32\\taskhost.exe",
            0x20000,
        ),
    )
    win32k_key.add_value(
        "\\Device\\HarddiskVolume3\\Windows\\System32\\csrss.exe",
        VirtualValue(
            hive_hklm,
            "\\Device\\HarddiskVolume3\\Windows\\System32\\csrss.exe",
            0x30000,
        ),
    )

    hive_hklm.map_key(win32k_key_path, win32k_key)

    target_win.add_plugin(CITPlugin)

    results = list(target_win.cit.telemetry())

    assert len(results) == 2
    assert results[0].version == 1705
    assert results[0].path == "/Device/HarddiskVolume2/Windows/System32/taskhost.exe"
    assert results[0].value == "DEVICECHANGE"
    assert results[1].value == "POWERBROADCAST|DEVICECHANGE"


def test_cit_modules_plugin(target_win, hive_hklm):
    module_key_path = (
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\CIT\\Module\\System32/mrt100.dll"
    )
    module_key = VirtualKey(hive_hklm, module_key_path)

    module_key.add_value(
        "\\Device\\HarddiskVolume1\\Windows\\System32\\backgroundTaskHost.exe",
        VirtualValue(
            hive_hklm,
            "\\Device\\HarddiskVolume1\\Windows\\System32\\backgroundTaskHost.exe",
            132502455503084687,
        ),
    )
    module_key.add_value(
        "OverflowValue",
        VirtualValue(
            hive_hklm,
            "OverflowValue",
            132502455486209533,
        ),
    )
    module_key.add_value(
        "OverflowQuota",
        VirtualValue(
            hive_hklm,
            "OverflowQuota",
            132502455486209533,
        ),
    )

    hive_hklm.map_key(module_key_path, module_key)

    target_win.add_plugin(CITPlugin)

    results = list(target_win.cit.modules())

    assert len(results) == 1
    assert results[0].tracked_module == "System32/mrt100.dll"
    assert results[0].executable == "/Device/HarddiskVolume1/Windows/System32/backgroundTaskHost.exe"
    assert results[0].overflow_quota == results[0].overflow_value
