from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.windows.log.schedlgu import SchedLgUPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_shedlgu(target_win: Target, fs_win: VirtualFilesystem) -> None:
    shedlgu_file = absolute_path("_data/plugins/os/windows/log/schedlgu/schedlgu.txt")
    fs_win.map_file("Windows/SchedLgU.Txt", shedlgu_file)

    target_win.add_plugin(SchedLgUPlugin)

    records = list(target_win.schedlgu())
    task_scheduler_started_event = records[0]
    task_scheduler_version_event = records[1]
    task_scheduler_exited_event = records[2]
    job_task_event = records[58]

    assert task_scheduler_started_event.ts == datetime("2006-11-02 07:35:17+00:00")
    assert task_scheduler_started_event.job == "Task Scheduler Service"
    assert task_scheduler_started_event.status == "Started"

    assert task_scheduler_version_event.job == "Task Scheduler Service"
    assert task_scheduler_version_event.version == "6.0.6000.16386 (vista_rtm.061101-2205)"

    assert task_scheduler_exited_event.job == "Task Scheduler Service"
    assert task_scheduler_exited_event.ts == datetime("2006-11-02 07:55:10+00:00")
    assert task_scheduler_exited_event.status == "Exited"

    assert job_task_event.ts == datetime("2003-09-14 13:01:00+00:00")
    assert job_task_event.job == "Symantec NetDetect.job"
    assert job_task_event.command == "NDETECT.EXE"
    assert job_task_event.status == "Finished"
    assert job_task_event.exit_code == 65
