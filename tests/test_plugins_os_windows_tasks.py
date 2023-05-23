from datetime import datetime

import pytest

from dissect.target.plugins.os.windows.tasks import TasksPlugin

from ._utils import absolute_path


@pytest.fixture
def setup_tasks_test(target_win, fs_win):
    xml_task_file = absolute_path("data/plugins/os/windows/tasks/MapsToastTask")
    atjob_task_file = absolute_path("data/plugins/os/windows/tasks/AtTask.job")

    fs_win.map_file("windows/system32/tasks/Microsoft/Windows/Maps/MapsToastTask", xml_task_file)
    fs_win.map_file("windows/tasks/AtTask.job", atjob_task_file)

    target_win.add_plugin(TasksPlugin)


def assert_xml_task_properties(xml_task):
    assert str(xml_task.uri) == "\\Microsoft\\Windows\\Maps\\MapsToastTask"
    assert (
        xml_task.security_descriptor
        == "D:(A;;0x111FFFFF;;;SY)(A;;0x111FFFFF;;;BA)(A;;0x111FFFFF;;;S-1-5-80-3028837079-3186095147-955107200-3701964851-1150726376)(A;;FRFX;;;AU)"  # noqa: E501
    )
    assert xml_task.source is None
    assert str(xml_task.date) == "2014-11-05 00:00:00"
    assert xml_task.last_run_date is None
    assert xml_task.author == "$(@%SystemRoot%\\system32\\mapstoasttask.dll,-600)"
    assert xml_task.version is None
    assert xml_task.description == "$(@%SystemRoot%\\system32\\mapstoasttask.dll,-602)"
    assert xml_task.documentation is None
    assert xml_task.principal_id == "Users"
    assert xml_task.user_id is None
    assert xml_task.logon_type is None
    assert xml_task.group_id is None
    assert xml_task.display_name is None
    assert xml_task.run_level is None
    assert xml_task.process_token_sid_type is None
    assert xml_task.required_privileges is None
    assert xml_task.allow_start_on_demand is None
    assert xml_task.restart_on_failure_interval is None
    assert xml_task.restart_on_failure_count is None
    assert xml_task.mutiple_instances_policy == "Queue"
    assert xml_task.dissalow_start_on_batteries == "false"
    assert xml_task.stop_going_on_batteries == "false"
    assert xml_task.start_when_available == "true"
    assert xml_task.network_profile_name is None
    assert xml_task.run_only_network_available is None
    assert xml_task.wake_to_run is None
    assert xml_task.enabled is None
    assert xml_task.hidden == "true"
    assert xml_task.delete_expired_task_after is None
    assert xml_task.idle_duration is None
    assert xml_task.idle_wait_timeout is None
    assert xml_task.idle_stop_on_idle_end == "false"
    assert xml_task.idle_restart_on_idle == "false"
    assert xml_task.network_settings_name is None
    assert xml_task.network_settings_id is None
    assert xml_task.execution_time_limit == "PT5S"
    assert xml_task.priority is None
    assert xml_task.run_only_idle is None
    assert xml_task.unified_scheduling_engine == "true"
    assert xml_task.disallow_start_on_remote_app_session is None
    assert xml_task.data is None


def assert_at_task_properties(at_task):
    assert at_task.uri is None
    assert at_task.security_descriptor is None
    assert at_task.source == "sysvol/windows/tasks/AtTask.job"
    assert at_task.date is None
    assert at_task.last_run_date == datetime.strptime("2023-05-21 10:44:25.794000", "%Y-%m-%d %H:%M:%S.%f")
    assert at_task.author == "user1"
    assert at_task.version == "1"
    assert at_task.description == "At job task for testing purposes"
    assert at_task.documentation is None
    assert at_task.principal_id is None
    assert at_task.user_id is None
    assert at_task.logon_type is None
    assert at_task.group_id is None
    assert at_task.display_name is None
    assert at_task.run_level is None
    assert at_task.process_token_sid_type is None
    assert at_task.required_privileges is None
    assert at_task.allow_start_on_demand is None
    assert at_task.restart_on_failure_interval is None
    assert at_task.restart_on_failure_count == "0"
    assert at_task.mutiple_instances_policy is None
    assert at_task.dissalow_start_on_batteries == "True"
    assert at_task.stop_going_on_batteries == "True"
    assert at_task.start_when_available is None
    assert at_task.network_profile_name is None
    assert at_task.run_only_network_available == "False"
    assert at_task.wake_to_run == "True"
    assert at_task.enabled == "True"
    assert at_task.hidden == "False"
    assert at_task.delete_expired_task_after is None
    assert at_task.idle_duration == "PT15M"
    assert at_task.idle_wait_timeout == "PT1H"
    assert at_task.idle_stop_on_idle_end == "True"
    assert at_task.idle_restart_on_idle == "False"
    assert at_task.network_settings_name is None
    assert at_task.network_settings_id is None
    assert at_task.execution_time_limit == "P3D"
    assert at_task.priority == "normal"
    assert at_task.run_only_idle == "True"
    assert at_task.unified_scheduling_engine is None
    assert at_task.disallow_start_on_remote_app_session is None
    assert at_task.data == "[]"


def assert_xml_task_grouped_properties(xml_task_grouped):
    assert xml_task_grouped.action_type == "ComHandler"
    assert xml_task_grouped.class_id == "{9885AEF2-BD9F-41E0-B15E-B3141395E803}"
    assert xml_task_grouped.data is None


def assert_at_task_grouped_exec(at_task_grouped):
    assert at_task_grouped.action_type == "Exec"
    assert at_task_grouped.arguments == ""
    assert at_task_grouped.command == "C:\\WINDOWS\\NOTEPAD.EXE"
    assert at_task_grouped.working_directory == "C:\\Documents and Settings\\John"


def assert_at_task_grouped_daily(at_task_grouped):
    assert at_task_grouped.days_between_triggers == 3
    assert at_task_grouped.end_boundary == "2023-05-12"
    assert at_task_grouped.execution_time_limit == "P3D"
    assert at_task_grouped.repetition_duration == "PT13H15M"
    assert at_task_grouped.repetition_interval == "PT12M"
    assert at_task_grouped.repetition_stop_duration_end == "True"
    assert at_task_grouped.start_boundary == "2023-05-11"
    assert_at_task_grouped_padding(at_task_grouped)


def assert_at_task_grouped_padding(at_task_grouped):
    assert at_task_grouped.padding == 0
    assert at_task_grouped.reserved2 == 0
    assert at_task_grouped.reserved3 == 0


def assert_at_task_grouped_monthlydow(at_task_grouped):
    assert at_task_grouped.records[1].enabled == "True"
    assert at_task_grouped.start_boundary == "2023-05-11"
    assert at_task_grouped.end_boundary == "2023-05-20"
    assert at_task_grouped.repetition_interval == "PT1M"
    assert at_task_grouped.repetition_duration == "PT12H13M"
    assert at_task_grouped.repetition_stop_duration_end == "True"
    assert at_task_grouped.execution_time_limit == "P3D"
    assert at_task_grouped.which_week == "SECOND_WEEK"
    assert at_task_grouped.days_of_week == ["Wednesday"]
    assert at_task_grouped.months_of_year == ["June", "September"]
    assert_at_task_grouped_padding(at_task_grouped)


def assert_at_task_grouped_weekly(at_task_grouped):
    assert at_task_grouped.records[1].enabled == "True"
    assert at_task_grouped.end_boundary == "2023-05-27"
    assert at_task_grouped.execution_time_limit == "P3D"
    assert at_task_grouped.repetition_duration == "PT1H"
    assert at_task_grouped.repetition_interval == "PT10M"
    assert at_task_grouped.repetition_stop_duration_end == "True"
    assert at_task_grouped.start_boundary == "2023-05-23"
    assert at_task_grouped.days_of_week == ["Monday", "Wednesday", "Friday"]
    assert at_task_grouped.unused == [0]
    assert at_task_grouped.weeks_between_triggers == 1
    assert_at_task_grouped_padding(at_task_grouped)


def assert_at_task_grouped_monthly_date(at_task_grouped):
    assert at_task_grouped.day_of_month == "15"
    assert at_task_grouped.months_of_year == ["March", "May", "June", "July", "August", "October"]
    assert at_task_grouped.records[1].enabled == "True"
    assert at_task_grouped.end_boundary == "2023-05-29"
    assert at_task_grouped.execution_time_limit == "P3D"
    assert at_task_grouped.repetition_duration == "PT4H44M"
    assert at_task_grouped.repetition_interval == "PT17M"
    assert at_task_grouped.repetition_stop_duration_end == "True"
    assert at_task_grouped.start_boundary == "2023-05-23"


@pytest.mark.parametrize(
    "record_index,assert_func",
    [
        (0, assert_xml_task_properties),
        (2, assert_at_task_properties),
    ],
)
def test_single_record_properties(target_win, setup_tasks_test, record_index, assert_func):
    records = list(target_win.tasks())
    assert len(records) == 8

    record = records[record_index]
    assert_func(record)


@pytest.mark.parametrize(
    "record_index,assert_func",
    [
        (1, assert_xml_task_grouped_properties),
        (3, assert_at_task_grouped_exec),
        (4, assert_at_task_grouped_daily),
        (5, assert_at_task_grouped_monthlydow),
        (6, assert_at_task_grouped_weekly),
        (7, assert_at_task_grouped_monthly_date),
    ],
)
def test_grouped_record_properties(target_win, setup_tasks_test, record_index, assert_func):
    records = list(target_win.tasks())
    assert len(records) == 8

    grouped_record = records[record_index]
    assert_func(grouped_record)
