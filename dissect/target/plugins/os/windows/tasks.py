import warnings

from defusedxml import ElementTree
from flow.record import GroupedRecord, RecordDescriptor
from flow.record.fieldtypes import uri

from dissect.target.exceptions import InvalidTaskError, UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

warnings.simplefilter(action="ignore", category=FutureWarning)

TaskRecord = TargetRecordDescriptor(
    "filesystem/windows/task",
    [
        ("uri", "uri"),
        ("string", "security_descriptor"),
        ("string", "source"),
        ("string", "date"),
        ("string", "author"),
        ("string", "version"),
        ("string", "description"),
        ("string", "documentation"),
        ("string", "principal_id"),
        ("string", "user_id"),
        ("string", "logon_type"),
        ("string", "group_id"),
        ("string", "display_name"),
        ("string", "run_level"),
        ("string", "process_token_sid_type"),
        ("string", "required_privileges"),
        ("boolean", "allow_start_on_demand"),
        ("string", "restart_on_failure_interval"),
        ("string", "restart_on_failure_count"),
        ("string", "mutiple_instances_policy"),
        ("string", "dissalow_start_on_batteries"),
        ("string", "stop_going_on_batteries"),
        ("string", "allow_start_on_demand"),
        ("string", "start_when_available"),
        ("string", "network_profile_name"),
        ("string", "run_only_network_available"),
        ("string", "wake_to_run"),
        ("string", "enabled"),
        ("string", "hidden"),
        ("string", "delete_expired_task_after"),
        ("string", "idle_duration"),
        ("string", "idle_wait_timeout"),
        ("string", "idle_stop_on_idle_end"),
        ("string", "idle_restart_on_idle"),
        ("string", "network_settings_name"),
        ("string", "network_settings_id"),
        ("string", "execution_time_limit"),
        ("string", "priority"),
        ("string", "run_only_idle"),
        ("string", "unified_scheduling_engine"),
        ("string", "disallow_start_on_remote_app_session"),
        ("string", "data"),
    ],
)

ExecRecord = RecordDescriptor(
    "filesystem/windows/task/action/Exec",
    [
        ("string", "action_type"),
        ("string", "command"),
        ("string", "arguments"),
        ("string", "working_directory"),
    ],
)

ComHandlerRecord = RecordDescriptor(
    "filesystem/windows/task/action/ComHandler",
    [
        ("string", "action_type"),
        ("string", "class_id"),
        ("string", "data"),
    ],
)

SendEmailRecord = RecordDescriptor(
    "filesystem/windows/task/action/SendEmail",
    [
        ("string", "action_type"),
        ("string", "server"),
        ("string", "subject"),
        ("string", "to"),
        ("string", "cc"),
        ("string", "bcc"),
        ("string", "replyto"),
        ("string", "email_from"),
        ("string", "header_name"),
        ("string", "header_value"),
        ("string", "body"),
        ("string", "attachment"),
    ],
)

ShowMessageRecord = RecordDescriptor(
    "filesystem/windows/task/action/ShowMessage",
    [
        ("string", "tile"),
        ("string", "body"),
    ],
)

LogonTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/LogonTrigger",
    [
        ("string", "user_id"),
        ("string", "delay"),
    ],
)

BootTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/BootTrigger",
    [
        ("string", "delay"),
    ],
)

IdleTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/IdleTrigger",
    [],
)

TimeTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/TimeTrigger",
    [
        ("string", "random_delay"),
    ],
)

TriggerRecord = RecordDescriptor(
    "filesystem/windows/task/Trigger",
    [
        ("string", "enabled"),
        ("string", "start_boundary"),
        ("string", "end_boundary"),
        ("string", "repetition_interval"),
        ("string", "repetition_duration"),
        ("string", "repetition_stop_duration_end"),
        ("string", "execution_time_limit"),
    ],
)

EventTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/EventTrigger",
    [
        ("string", "subscription"),
        ("string", "delay"),
        ("string", "period_of_occurence"),
        ("string", "number_of_occurences"),
        ("string", "matching_elements"),
        ("string", "value_queries"),
    ],
)

SessionStateChangeTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/SessionStateChangeTrigger",
    [
        ("string", "user_id"),
        ("string", "delay"),
        ("string", "state_change"),
    ],
)

CalendarTriggerRecord = RecordDescriptor(
    "filesystem/windows/task/trigger/CalendarTrigger",
    [
        ("string", "random_delay"),
        ("string", "schedule_by_day"),
        ("string", "schedule_by_week"),
        ("string", "schedule_by_month"),
        ("string", "schedule_by_day_of_week"),
    ],
)


def strip_namespace(data):
    if data.tag.startswith("{"):
        ns_length = data.tag.find("}")
        ns = data.tag[0 : ns_length + 1]
        for element in data.iter():
            if element.tag.startswith(ns):
                element.tag = element.tag[len(ns) :]
    return data


class Task:
    def __init__(self, xml_data):
        self.xml_data = xml_data

    def get_element(self, path, xml_data=None):
        xml_data = xml_data or self.xml_data
        try:
            return xml_data.find(path).text
        except AttributeError:
            return

    def get_raw(self, path):
        data = self.xml_data.find(path)
        if data:
            return ElementTree.tostring(data, encoding="utf-8")

    def get_triggers(self):
        for trigger in self.xml_data.findall("Triggers/*"):
            trigger_type = trigger.tag
            enabled = self.get_element("Enabled", trigger)
            start_boundary = self.get_element("StartBoundary", trigger)
            end_boundary = self.get_element("EndBoundary", trigger)
            repetition_interval = self.get_element("Repetition/Interval", trigger)
            repetition_duration = self.get_element("Repetition/Duration", trigger)
            repetition_stop_duration_end = self.get_element("Repetition/StopAtDurationEnd", trigger)
            execution_time_limit = self.get_element("ExecutionTimeLimit", trigger)

            base = TriggerRecord(
                enabled=enabled,
                start_boundary=start_boundary,
                end_boundary=end_boundary,
                repetition_interval=repetition_interval,
                repetition_duration=repetition_duration,
                repetition_stop_duration_end=repetition_stop_duration_end,
                execution_time_limit=execution_time_limit,
            )

            if trigger_type == "LogonTrigger":
                user_id = self.get_element("UserId", trigger)
                delay = self.get_element("UserId", trigger)
                record = LogonTriggerRecord(
                    user_id=user_id,
                    delay=delay,
                )
                yield GroupedRecord("filesystem/windows/task/LogonTrigger", [base, record])

            if trigger_type == "BootTrigger":
                delay = self.get_element("Delay", trigger)
                record = BootTriggerRecord(delay=delay)
                yield GroupedRecord("filesystem/windows/task/BootTrigger", [base, record])

            if trigger_type == "IdleTrigger":
                pass  # No extra fields

            if trigger_type == "TimeTrigger":
                random_delay = self.get_element("RandomDelay", trigger)

                record = TimeTriggerRecord(random_delay=random_delay)
                yield GroupedRecord("filesystem/windows/task/TimeTrigger", [base, record])

            if trigger_type == "EventTrigger":
                subscription = self.get_element("Subscription", trigger)
                delay = self.get_element("Delay", trigger)
                period_of_occurence = self.get_element("PeriodOfOccurrence", trigger)
                number_of_occurences = self.get_element("NumberOfOccurences", trigger)
                matching_elements = self.get_element("MatchingElement", trigger)
                value_queries = self.get_element("ValueQueries/Value", trigger)

                record = EventTriggerRecord(
                    subscription=subscription,
                    delay=delay,
                    period_of_occurence=period_of_occurence,
                    number_of_occurences=number_of_occurences,
                    matching_elements=matching_elements,
                    value_queries=value_queries,
                )

                yield GroupedRecord("filesystem/windows/task/EventTrigger", [base, record])

            if trigger_type == "SessionStateChangeTrigger":
                user_id = self.get_element("UserId", trigger)
                delay = self.get_element("Delay", trigger)
                state_change = self.get_element("StateChange", trigger)

                record = SessionStateChangeTriggerRecord(
                    user_id=user_id,
                    delay=delay,
                    state_change=state_change,
                )

                yield GroupedRecord("filesystem/windows/task/SessionStateTrigger", [base, record])

            if trigger_type == "CalendarTrigger":
                pass
                """
                random_delay = self.get_element("RandomDelay", trigger)
                schedule_by_day = self.get_element("ScheduleByDay/DaysInterval", trigger)
                schedule_by_week_interval = self.get_element("ScheduleByWeek/WeeksInterval", trigger)
                schedule_by_week_ = self.get_element("ScheduleByWeek/WeeksInterval", trigger)
                record = task_calendar()
                grouped = GroupedRecord("filesystem/windows/task/CalendarTrigger", [base, record])
                yield grouped
                """

    def get_actions(self):
        for action in self.xml_data.findall("Actions/*"):
            action_type = action.tag
            if action_type == "Exec":
                command = self.get_element("Actions/Exec/Command")
                args = self.get_element("Actions/Exec/Arguments")
                wrkdir = self.get_element("Actions/Exec/WorkingDirectory")
                yield ExecRecord(
                    action_type=action_type,
                    command=command,
                    arguments=args,
                    working_directory=wrkdir,
                )

            if action_type == "ComHandler":
                com_class_id = self.get_element("Actions/ComHandler/ClassId")
                com_data = self.get_raw("Actions/ComHandler/Data")
                yield ComHandlerRecord(
                    action_type=action_type,
                    class_id=com_class_id,
                    data=com_data,
                )

            if action_type == "SendEmail":
                email_server = self.get_element("Actions/ShowMessage/Server")
                email_subject = self.get_element("Actions/ShowMessage/Subject")
                email_to = self.get_element("Actions/ShowMessage/To")
                email_cc = self.get_element("Actions/ShowMessage/Cc")
                email_bcc = self.get_element("Actions/ShowMessage/Bcc")
                email_reply_to = self.get_element("Actions/ShowMessage/ReplyTo")
                email_from = self.get_element("Actions/ShowMessage/From")
                email_body = self.get_element("Actions/ShowMessage/Body")
                email_attachments = self.get_element("Actions/ShowMessage/Attachments/File")
                email_headers_name = self.get_element("Actions/ShowMessage/Headers/HeadersField/Name")
                email_headers_value = self.get_element("Actions/ShowMessage/Headers/headersField/Value")
                yield SendEmailRecord(
                    action_type=action_type,
                    server=email_server,
                    subject=email_subject,
                    to=email_to,
                    cc=email_cc,
                    bcc=email_bcc,
                    replyto=email_reply_to,
                    email_from=email_from,
                    header_name=email_headers_name,
                    header_value=email_headers_value,
                    body=email_body,
                    attachment=email_attachments,
                )

            if action_type == "ShowMessage":
                title = self.get_element("Actions/ShowMessage/Title")
                body = self.get_element("Actions/ShowMessage/Body")
                yield ShowMessageRecord(
                    action_type=action,
                    title=title,
                    body=body,
                )


class TasksPlugin(Plugin):
    """TODO."""

    PATHS = [
        "sysvol/windows/system32/tasks",
        "sysvol/windows/system32/tasks_migrated",
        "sysvol/windows/syswow64/tasks",
    ]

    def __init__(self, target):
        super().__init__(target)
        self.files = []

        for path in self.PATHS:
            fpath = self.target.fs.path(path)
            if not fpath.exists():
                continue

            for entry in fpath.rglob("*"):
                if entry.is_file():
                    self.files.append(entry)

    def check_compatible(self):
        if len(self.files) == 0:
            raise UnsupportedPluginError("No task files")

    @export(record=DynamicDescriptor(["uri", "datetime"]))
    def tasks(self):
        """Return all scheduled tasks on a Widows system.

        On a Windows system, a scheduled task is a program or script that is executed on a specific time or at specific
        intervals. An adversary may leverage such scheduled tasks to gain persistence on a system.

        Sources:
            - https://en.wikipedia.org/wiki/Windows_Task_Scheduler
        """
        for f in self.files:
            try:
                for entry in self.parse_task(f):
                    yield entry
            except Exception as e:
                self.target.log.warning("An error occured parsing task %s: %s", f, str(e))
                self.target.log.debug("", exc_info=e)

    def parse_task(self, entry):
        try:
            task_xml = strip_namespace(ElementTree.fromstring(entry.open().read(), forbid_dtd=True))
        except ElementTree.ParseError:
            raise InvalidTaskError()

        # RegistrationInfo
        task = Task(task_xml)
        task.hostname = self.target.hostname
        task.uri = task.get_element("RegistrationInfo/URI")
        task.security_descriptor = task.get_element("RegistrationInfo/SecurityDescriptor")
        task.source = task.get_element("RegistrationInfo/Source")
        task.date = task.get_element("RegistrationInfo/Date")
        task.author = task.get_element("RegistrationInfo/Author")
        task.version = task.get_element("RegistrationInfo/Version")
        task.description = task.get_element("RegistrationInfo/Description")
        task.documentation = task.get_element("RegistrationInfo/Documentation")

        # Principals
        task.principal_id = task_xml.find("Principals/Principal").get("id")
        task.user_id = task.get_element("Principals/Principal/UserId")
        task.logon_type = task.get_element("Principals/Principal/LogonType")
        task.group_id = task.get_element("Principals/Principal/GroupId")
        task.display_name = task.get_element("Principals/Principal/DisplayName")
        task.run_level = task.get_element("Principals/Principal/RunLevel")
        task.process_token_sid_type = task.get_element("Principals/Principal/ProcessTokenSidType")
        task.required_privileges = task.get_element("Principals/Principal/RequiredPrivileges")

        # Settings
        task.allow_start_on_demand = task.get_element("Settings/AllowStartOnDemand")
        task.restart_on_failure_interval = task.get_element("Settings/RestartOnFailure/Interval")
        task.restart_on_failure_count = task.get_element("Settings/RestartOnFailure/Count")
        task.mutiple_instances_policy = task.get_element("Settings/MultipleInstancesPolicy")
        task.dissalow_start_on_batteries = task.get_element("Settings/DisallowStartIfOnBatteries")
        task.stop_going_on_batteries = task.get_element("Settings/StopIfGoingOnBatteries")
        task.allow_hard_terminate = task.get_element("Settings/AllowHardTerminate")
        task.start_when_available = task.get_element("Settings/StartWhenAvailable")
        task.network_profile_name = task.get_element("Settings/NetworkProfileName")
        task.run_only_network_available = task.get_element("Settings/RunOnlyIfNetworkAvailable")
        task.wake_to_run = task.get_element("Settings/WakeToRun")
        task.enabled = task.get_element("Settings/Enabled")
        task.hidden = task.get_element("Settings/Hidden")
        task.delete_expired_task_after = task.get_element("Settings/DeleteExpiredTaskAfter")
        task.idle_duration = task.get_element("Settings/IdleSettings/Duration")
        task.idle_wait_timeout = task.get_element("Settings/IdleSettings/WaitTimeout")
        task.idle_stop_on_idle_end = task.get_element("Settings/IdleSettings/StopOnIdleEnd")
        task.idle_restart_on_idle = task.get_element("Settings/IdleSettings/RestartOnIdle")
        task.network_settings_name = task.get_element("Settings/NetworkSettings/Name")
        task.network_settings_id = task.get_element("Settings/NetworkSettings/Id")
        task.execution_time_limit = task.get_element("Settings/ExecutionTimeLimit")
        task.priority = task.get_element("Settings/Priority")
        task.run_only_idle = task.get_element("Settings/RunOnlyIfIdle")
        task.unified_scheduling_engine = task.get_element("Settings/UseUnifiedSchedulingEngine")
        task.disallow_start_on_remote_app_session = task.get_element("Settings/DisallowStartOnRemoteAppSession")

        # Data
        task.data = task.get_raw("Data")

        record = TaskRecord(
            uri=uri.from_windows(task.uri) if task.uri else None,
            security_descriptor=task.security_descriptor,
            source=task.source,
            date=task.date,
            author=task.author,
            version=task.version,
            description=task.description,
            documentation=task.documentation,
            principal_id=task.principal_id,
            user_id=task.user_id,
            logon_type=task.logon_type,
            display_name=task.display_name,
            run_level=task.run_level,
            process_token_sid_type=task.process_token_sid_type,
            required_privileges=task.required_privileges,
            allow_start_on_demand=task.allow_start_on_demand,
            restart_on_failure_interval=task.restart_on_failure_interval,
            restart_on_failure_count=task.restart_on_failure_count,
            mutiple_instances_policy=task.mutiple_instances_policy,
            dissalow_start_on_batteries=task.dissalow_start_on_batteries,
            stop_going_on_batteries=task.stop_going_on_batteries,
            start_when_available=task.start_when_available,
            network_profile_name=task.network_profile_name,
            run_only_network_available=task.run_only_network_available,
            wake_to_run=task.wake_to_run,
            enabled=task.enabled,
            hidden=task.hidden,
            delete_expired_task_after=task.delete_expired_task_after,
            idle_duration=task.idle_duration,
            idle_wait_timeout=task.idle_wait_timeout,
            idle_stop_on_idle_end=task.idle_stop_on_idle_end,
            idle_restart_on_idle=task.idle_restart_on_idle,
            network_settings_name=task.network_settings_name,
            network_settings_id=task.network_settings_id,
            execution_time_limit=task.execution_time_limit,
            priority=task.priority,
            run_only_idle=task.run_only_idle,
            unified_scheduling_engine=task.unified_scheduling_engine,
            disallow_start_on_remote_app_session=task.disallow_start_on_remote_app_session,
            data=task.data,
            _target=self.target,
        )

        yield record  # Without groups

        # Actions
        for entry in task.get_actions():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, entry])
            yield grouped

        # Triggers
        for entry in task.get_triggers():
            grouped = GroupedRecord("filesystem/windows/task/grouped", [record, entry])
            yield grouped
