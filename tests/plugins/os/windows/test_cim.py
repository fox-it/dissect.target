from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows import cim
from dissect.target.target import Target
from tests._utils import absolute_path


def test_cim_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    wbem_repository = absolute_path("_data/plugins/os/windows/cim")
    fs_win.map_dir("Windows/System32/wbem/repository", wbem_repository)

    target_win.add_plugin(cim.CimPlugin)

    assert len(list(target_win.cim())) == 220
    assert len(list(target_win.cim.command_line_event_consumer())) == 203
    assert len(list(target_win.cim.active_script_event_consumer())) == 3
