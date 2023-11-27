from dissect.target.helpers.regutil import VirtualKey
from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
from tests._utils import absolute_path

SYSTEM_KEY_PATH = "SYSTEM\\ControlSet001\\Control\\LSA"
POLICY_KEY_PATH = "SECURITY\\Policy\\PolEKList"
DPAPI_KEY_PATH = "SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal"


def test_dpapi_decrypt_blob(target_win_users, fs_win, hive_hklm):
    # Create SYSTEM keys
    system_key = VirtualKey(hive_hklm, SYSTEM_KEY_PATH)
    data_key = VirtualKey(hive_hklm, "Data", class_name="13f032ed")
    system_key.add_subkey("Data", data_key)
    gbg_key = VirtualKey(hive_hklm, "GBG", class_name="c21c0976")
    system_key.add_subkey("GBG", gbg_key)
    jd_key = VirtualKey(hive_hklm, "JD", class_name="ea08e1ce")
    system_key.add_subkey("JD", jd_key)
    skew1_key = VirtualKey(hive_hklm, "Skew1", class_name="f83ed834")
    system_key.add_subkey("Skew1", skew1_key)
    hive_hklm.map_key(SYSTEM_KEY_PATH, system_key)

    policy_key = VirtualKey(hive_hklm, POLICY_KEY_PATH)
    policy_key_value = b"\x00\x00\x00\x01\xec\xff\xe1{*\x99t@\xaa\x93\x9a\xdb\xff&\xf1\xfc\x03\x00\x00\x00\x00\x00\x00\x00~\x12z\xb2cE.\xa5Q\x7fkD\x97\xe7\xf4\xb2\x99R\xd0\x80r\xf9/\x8b\xbb\x81\xd1\x807\xba\xa6\xe8`\xde\xe3\x1e\xa8S\x14i\xac\"$\x14\xf2$\n\xf8'_\x17I\xa9\x9b\xbb#mR\xc5\xee\x90\xeed1\xaa\xdcf\x811e j\xcdhWR\x1d a\x1e_\x01\xcb\x96\xbb\xa6\xc7t\x93p\xba>\xc5?\xb2.M\x88\x9drTX\x8f\x01H\xb3B6dZS\xc7\x9d\x99}9\x9eD\xdcJ\xd9\xfb\xc3\x92\x8c\x87W\x95\x06\x93\xcb{\xea\xff\xa62\x0f\xc8\x9c\x08\x8e/`\x15"  # noqa
    policy_key.add_value("(Default)", policy_key_value)
    hive_hklm.map_key(POLICY_KEY_PATH, policy_key)

    secrets_key = VirtualKey(hive_hklm, DPAPI_KEY_PATH)
    secrets_key_value = b"\x00\x00\x00\x01Z7%\xd6\x9e\xc9\x9e/\x15h\xb3\x13N\x8a\xc1\xfc\x03\x00\x00\x00\x00\x00\x00\x00\xc0'\xaay\xaa\x038\x82\x7f\xe4\xf0\x1b+\x0e]\x1e\x86\x9b\xfc\xeb%I/K(\xc5\xea\xd9i\\#\xff\x0c\xc4\xc1wF1\xfav\r0\x05\x19\xff-\xf2G)\xab`\xad\xb3\x02\x0bRz\xadj\x8d\xff\x9a-yE\xeb\x98iz\xc7\xa8g\xf7C\xa5\x0bJ\x04\x1e\x8b\x96\xec\xe24I\xd3\xc7_)\xea\xea]\"\xae\xe4\xe7"  # noqa
    secrets_key.add_value("(Default)", secrets_key_value)
    hive_hklm.map_key(DPAPI_KEY_PATH, secrets_key)

    fs_win.map_file(
        "Windows/System32/Microsoft/Protect/S-1-5-18/d8ef5e00-328a-4919-9ab6-c058f493a6e3",
        absolute_path("_data/plugins/os/windows/dpapi/master_keys/d8ef5e00-328a-4919-9ab6-c058f493a6e3"),
    )

    target_win_users.add_plugin(DPAPIPlugin)

    with open(absolute_path("_data/plugins/os/windows/dpapi/test_data.dpapi"), "rb") as encrypted_blob:
        decrypted = target_win_users.dpapi.decrypt_system_blob(encrypted_blob.read())
        assert decrypted == b"TestData"
