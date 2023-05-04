from dissect.target.plugins.os.windows import adpolicy

from ._utils import absolute_path


def test_adpolicy_plugin(target_win, fs_win):
    policy_dir = absolute_path("data/plugins/os/windows/adpolicy/")

    fs_win.map_dir("Windows/sysvol/domain/policies", policy_dir)

    target_win.add_plugin(adpolicy.ADPolicyPlugin)

    records = list(target_win.adpolicy())
    assert len(records) == 10
