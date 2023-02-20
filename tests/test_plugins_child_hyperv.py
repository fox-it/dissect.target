from dissect.target.plugins.child.hyperv import HyperVChildTargetPlugin

from ._utils import absolute_path


def test_plugins_child_wsl(target_win, fs_win):
    fs_win.map_file(
        "ProgramData/Microsoft/Windows/Hyper-V/data.vmcx",
        absolute_path("data/plugins/child/hyperv/data.vmcx"),
    )
    fs_win.map_file(
        "ProgramData/Microsoft/Windows/Hyper-V/Virtual Machines/B90AC31B-C6F8-479F-9B91-07B894A6A3F6.xml",
        absolute_path("data/loaders/hyperv/B90AC31B-C6F8-479F-9B91-07B894A6A3F6.xml"),
    )

    target_win.add_plugin(HyperVChildTargetPlugin)

    children = list(target_win.list_children())

    assert len(children) == 5
    assert (
        str(children[0].path) == "C:\\Hyper-V\\EasyToFind\\Virtual Machines\\EC04F346-DB96-4700-AF5B-77B3C56C38BD.vmcx"
    )
    assert (
        str(children[1].path) == "C:\\Hyper-V\\EasyToFind\\Virtual Machines\\993F7B33-6057-4D1E-A1FE-A1A1D77BE974.vmcx"
    )
    assert (
        str(children[2].path)
        == "C:\\VM\\Other Generation 1\\Virtual Machines\\A5B56431-CA94-482A-B70A-F1F2B12373BE.vmcx"
    )
    assert (
        str(children[3].path)
        == "C:\\VM\\Other Generation 2\\Virtual Machines\\4C57771A-3230-4B92-B029-D63F96518E70.vmcx"
    )
    assert (
        str(children[4].path)
        == "/sysvol/ProgramData/Microsoft/Windows/Hyper-V/Virtual Machines/B90AC31B-C6F8-479F-9B91-07B894A6A3F6.xml"
    )
