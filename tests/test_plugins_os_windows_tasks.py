from dissect.target.plugins.os.windows.tasks import TasksPlugin

from ._utils import absolute_path


def test_tasks(target_win, fs_win):
    task_file = absolute_path("data/plugins/os/windows/tasks/MapsToastTask")
    fs_win.map_file("windows/system32/tasks/Microsoft/Windows/Maps/MapsToastTask", task_file)

    target_win.add_plugin(TasksPlugin)

    records = list(target_win.tasks())

    task = records[0]
    task_grouped = records[1]

    assert len(records) == 2

    assert task.uri == "/Microsoft/Windows/Maps/MapsToastTask"
    assert (
        task.security_descriptor
        == "D:(A;;0x111FFFFF;;;SY)(A;;0x111FFFFF;;;BA)(A;;0x111FFFFF;;;S-1-5-80-3028837079-3186095147-955107200-3701964851-1150726376)(A;;FRFX;;;AU)"  # noqa: E501
    )
    assert task.source is None
    assert str(task.date) == "2014-11-05 00:00:00"
    assert task.author == "$(@%SystemRoot%\\system32\\mapstoasttask.dll,-600)"
    assert task.version is None
    assert task.description == "$(@%SystemRoot%\\system32\\mapstoasttask.dll,-602)"
    assert task.documentation is None
    assert task.principal_id == "Users"
    assert task.user_id is None
    assert task.logon_type is None
    assert task.group_id is None
    assert task.display_name is None
    assert task.run_level is None
    assert task.process_token_sid_type is None
    assert task.required_privileges is None
    assert task.allow_start_on_demand is None
    assert task.restart_on_failure_interval is None
    assert task.restart_on_failure_count is None
    assert task.mutiple_instances_policy == "Queue"
    assert task.dissalow_start_on_batteries == "false"
    assert task.stop_going_on_batteries == "false"
    assert task.start_when_available == "true"
    assert task.network_profile_name is None
    assert task.run_only_network_available is None
    assert task.wake_to_run is None
    assert task.enabled is None
    assert task.hidden == "true"
    assert task.delete_expired_task_after is None
    assert task.idle_duration is None
    assert task.idle_wait_timeout is None
    assert task.idle_stop_on_idle_end == "false"
    assert task.idle_restart_on_idle == "false"
    assert task.network_settings_name is None
    assert task.network_settings_id is None
    assert task.execution_time_limit == "PT5S"
    assert task.priority is None
    assert task.run_only_idle is None
    assert task.unified_scheduling_engine == "true"
    assert task.disallow_start_on_remote_app_session is None
    assert task.data is None

    assert task_grouped.action_type == "ComHandler"
    assert task_grouped.class_id == "{9885AEF2-BD9F-41E0-B15E-B3141395E803}"
    assert task_grouped.data is None
