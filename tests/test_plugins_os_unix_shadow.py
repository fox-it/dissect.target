from dissect.target.plugins.os.unix.shadow import ShadowPlugin

from ._utils import absolute_path


def test_unix_shadow(target_unix_users, fs_unix):
    shadow_file = absolute_path("data/unix/configs/shadow")
    fs_unix.map_file("/etc/shadow", shadow_file)
    target_unix_users.add_plugin(ShadowPlugin)

    results = list(target_unix_users.passwords())
    assert len(results) == 1
    assert results[0].name == "test"
    assert (
        results[0].crypt
        == "$6$oLHns1qc.C3DoQ8c$temOg6X.UF5Ly3gM03cGnBLib30mv8J49dUI.w9.EHTnO4R467zyKbfBnmTa5IIvDr5mRXFoJVBGKF6QuFDpo1"
    )  # noqa E501
    assert results[0].salt == "oLHns1qc.C3DoQ8c"
    assert (
        results[0].hash == "temOg6X.UF5Ly3gM03cGnBLib30mv8J49dUI.w9.EHTnO4R467zyKbfBnmTa5IIvDr5mRXFoJVBGKF6QuFDpo1"
    )  # noqa E501
    assert results[0].algorithm == "sha512"
    assert results[0].crypt_param is None
    assert results[0].last_change == "18963"
    assert results[0].min_age == 0
    assert results[0].max_age == 99999
    assert results[0].warning_period == 7
    assert results[0].inactivity_period == ""
    assert results[0].expiration_date == ""
    assert results[0].unused_field == ""
