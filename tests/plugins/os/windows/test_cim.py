from __future__ import annotations

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows import cim
from dissect.target.plugins.os.windows.cim import ActiveScriptEventConsumerRecord, CommandLineEventConsumerRecord
from dissect.target.target import Target
from tests._utils import absolute_path


def test_cim_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    wbem_repository = absolute_path("_data/plugins/os/windows/cim")
    fs_win.map_dir("Windows/System32/wbem/repository", wbem_repository)

    target_win.add_plugin(cim.CimPlugin)
    consumer_records = list(target_win.cim.consumerbindings())
    assert len(consumer_records) == 3
    assert len([r for r in consumer_records if type(r) == CommandLineEventConsumerRecord.recordType]) == 1  # noqa: E721
    assert len([r for r in consumer_records if type(r) == ActiveScriptEventConsumerRecord.recordType]) == 2  # noqa: E721
    # Ensure associated filter query was correctly found for all
    assert len([record for record in target_win.cim() if record.filter_query]) == 3
