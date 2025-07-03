from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree
from flow.record import GroupedRecord

from dissect.target.exceptions import InvalidTaskError
from dissect.target.plugins.os.windows.tasks.records import (
    BaseTriggerRecord,
    BootTriggerRecord,
    CalendarTriggerRecord,
    ComHandlerRecord,
    DailyTriggerRecord,
    EventTriggerRecord,
    ExecRecord,
    IdleTriggerRecord,
    LogonTriggerRecord,
    MonthlyDateTriggerRecord,
    MonthlyDowTriggerRecord,
    RegistrationTrigger,
    SendEmailRecord,
    SessionStateChangeTriggerRecord,
    ShowMessageRecord,
    TimeTriggerRecord,
    WeeklyTriggerRecord,
    WnfTriggerRecord,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from xml.etree.ElementTree import Element

    from dissect.target.helpers.fsutil import TargetPath


class ScheduledTasks:
    def __init__(self, xml_file: TargetPath):
        try:
            self.xml_data = self.strip_namespace(ElementTree.fromstring(xml_file.open().read(), forbid_dtd=True))
        except Exception as e:
            raise InvalidTaskError(e)

        self.task_path = xml_file
        self.tasks = self.get_tasks()

    def strip_namespace(self, data: Element) -> Element:
        """Strip namespace from XML data.

        If the data has a namespace, it will be removed from all the XML tags.

        Args:
            data: The XML data as an Element object.

        Returns:
            The XML data with the stripped namespace.
        """
        if data.tag.startswith("{"):
            ns_length = data.tag.find("}")
            ns = data.tag[0 : ns_length + 1]
            for element in data.iter():
                element.tag = element.tag.removeprefix(ns)
        return data

    def get_tasks(self) -> list[XmlTask]:
        tasks = []
        if self.xml_data.tag == "Task":
            tasks.append(XmlTask(self.xml_data, self.task_path))
        else:
            tasks.extend(XmlTask(task_element, self.task_path) for task_element in self.xml_data.findall(".//{*}Task"))

        return tasks


def str_to_bool(string_to_convert: str) -> bool | None:
    """Convert a string to a boolean value.

    The conversion is case-insensitive and only accepts 'true' or 'false'
    (with optional surrounding whitespace). Raises a ValueError for any
    other input.

    Args:
        string_to_convert: The input string to convert. Should be 'true' or 'false', case-insensitively.

    Returns:
        None for an empty string, True if the input string is 'true' (case-insensitive), False if 'false'.
    """
    if not string_to_convert:
        return None

    string_to_convert_lower = string_to_convert.strip().lower()
    if string_to_convert_lower == "true":
        return True
    if string_to_convert_lower == "false":
        return False

    raise ValueError(f"Invalid boolean string: '{string_to_convert}' (expected 'true' or 'false')")


class XmlTask:
    """Parses and extracts information from an XML-based Task Scheduler file.

    This class is used to extract metadata, triggers, and actions from a task
    defined in an XML format (used in newer versions of Windows Task Scheduler).

    Args:
        task_element: The root XML element representing the task.
        task_path: The path of the task in the target system.
    """

    def __init__(self, task_element: Element, task_path: TargetPath):
        self.task_path = task_path
        self.task_element = task_element

        # Properties
        self.task_name = self.get_element("Properties", attribute="name")
        self.app_name = self.get_element("Properties", attribute="appName")
        self.args = self.get_element("Properties", attribute="args")
        self.start_in = self.get_element("Properties", attribute="startIn")
        self.comment = self.get_element("Properties", attribute="comment")
        self.run_as = self.get_element("Properties", attribute="runAs")
        self.cpassword = self.get_element("Properties", attribute="cpassword")
        self.action = self.get_element("Properties", attribute="action")

        self.uri = self.get_element("RegistrationInfo/URI")
        self.security_descriptor = self.get_element("RegistrationInfo/SecurityDescriptor")
        self.source = self.get_element("RegistrationInfo/Source")
        self.date = self.get_element("RegistrationInfo/Date")
        self.author = self.get_element("RegistrationInfo/Author")
        self.version = self.get_element("RegistrationInfo/Version")
        self.description = self.get_element("RegistrationInfo/Description")
        self.documentation = self.get_element("RegistrationInfo/Documentation")

        # Principals
        self.principal_id = self.get_element("Principals/Principal", attribute="id")
        self.user_id = self.get_element("Principals/Principal/UserId")
        self.logon_type = self.get_element("Principals/Principal/LogonType")
        self.group_id = self.get_element("Principals/Principal/GroupId")
        self.display_name = self.get_element("Principals/Principal/DisplayName") or task_path.name
        self.run_level = self.get_element("Principals/Principal/RunLevel")
        self.process_token_sid_type = self.get_element("Principals/Principal/ProcessTokenSidType")
        self.required_privileges = self.get_element("Principals/Principal/RequiredPrivileges")

        # Settings
        self.allow_start_on_demand = str_to_bool(self.get_element("Settings/AllowStartOnDemand"))
        self.restart_on_failure_interval = self.get_element("Settings/RestartOnFailure/Interval")
        self.restart_on_failure_count = self.get_element("Settings/RestartOnFailure/Count")
        self.mutiple_instances_policy = self.get_element("Settings/MultipleInstancesPolicy")
        self.disallow_start_on_batteries = str_to_bool(self.get_element("Settings/DisallowStartIfOnBatteries"))
        self.stop_going_on_batteries = str_to_bool(self.get_element("Settings/StopIfGoingOnBatteries"))
        self.allow_hard_terminate = self.get_element("Settings/AllowHardTerminate")
        self.start_when_available = str_to_bool(self.get_element("Settings/StartWhenAvailable"))
        self.network_profile_name = self.get_element("Settings/NetworkProfileName")
        self.run_only_network_available = str_to_bool(self.get_element("Settings/RunOnlyIfNetworkAvailable"))
        self.wake_to_run = str_to_bool(self.get_element("Settings/WakeToRun"))

        self.hidden = str_to_bool(self.get_element("Settings/Hidden"))
        self.delete_expired_task_after = self.get_element("Settings/DeleteExpiredTaskAfter")
        self.idle_duration = self.get_element("Settings/IdleSettings/Duration")
        self.idle_wait_timeout = self.get_element("Settings/IdleSettings/WaitTimeout")
        self.idle_stop_on_idle_end = str_to_bool(self.get_element("Settings/IdleSettings/StopOnIdleEnd"))
        self.idle_restart_on_idle = str_to_bool(self.get_element("Settings/IdleSettings/RestartOnIdle"))
        self.network_settings_name = self.get_element("Settings/NetworkSettings/Name")
        self.network_settings_id = self.get_element("Settings/NetworkSettings/Id")
        self.execution_time_limit = self.get_element("Settings/ExecutionTimeLimit")
        self.priority = self.get_element("Settings/Priority")
        self.run_only_idle = str_to_bool(self.get_element("Settings/RunOnlyIfIdle"))
        self.unified_scheduling_engine = str_to_bool(self.get_element("Settings/UseUnifiedSchedulingEngine"))
        self.disallow_start_on_remote_app_session = str_to_bool(
            self.get_element("Settings/DisallowStartOnRemoteAppSession")
        )

        # Enabled
        self.enabled = str_to_bool(self.get_element("Settings/Enabled"))
        if self.enabled is None:
            self.enabled = str_to_bool(self.get_element("Properties", attribute="enabled"))

        if self.enabled is None:
            self.enabled = True

        # Data
        self.data = self.get_raw("Data")

        self.raw_data = self.get_raw()

    def strip_namespace(self, data: Element) -> Element:
        """Strip namespace from XML data.

        If the data has a namespace, it will be removed from all the XML tags.

        Args:
            data: The XML data as an Element object.

        Returns:
            The XML data with the stripped namespace.
        """
        if data.tag.startswith("{"):
            ns_length = data.tag.find("}")
            ns = data.tag[0 : ns_length + 1]
            for element in data.iter():
                element.tag = element.tag.removeprefix(ns)
        return data

    def get_element(self, xml_path: str, xml_data: Element | None = None, attribute: str | None = None) -> str | None:
        """Get the value of the specified XML element.

        Args:
            xml_path: The string used to locate the element.
            xml_data: The XML data to search in. If not provided, use self.xml_data.
            attribute: The name of a specific attribute from an element that should be returned.

        Returns:
            str: The value of the XML element if found, otherwise None.
        """
        xml_data = xml_data if xml_data is not None else self.task_element
        data = xml_data.find(xml_path)

        if data is None:
            return None
        if attribute:
            return data.get(attribute)

        return data.text

    def get_raw(self, xml_path: str | None = None) -> str:
        """Get the raw XML data of the specified element.

        Args:
            xml_path: The string used to locate the element.

        Returns:
            bytes: The raw XML data as string of the element if found, otherwise None.
        """
        data = self.task_element.find(xml_path) if xml_path else self.task_element
        if data is not None:
            return ElementTree.tostring(data, encoding="utf-8").strip()
        return None

    def get_triggers(self) -> Iterator[GroupedRecord]:
        """Get the triggers from the XML task data.

        Yields:
            GroupedRecord: The grouped record representing a trigger.
        """
        for trigger in self.task_element.findall("Triggers/*"):
            trigger_type = trigger.tag
            trigger_enabled = str_to_bool(self.get_element("Enabled", trigger))
            start_boundary = self.get_element("StartBoundary", trigger)
            end_boundary = self.get_element("EndBoundary", trigger)
            repetition_interval = self.get_element("Repetition/Interval", trigger)
            repetition_duration = self.get_element("Repetition/Duration", trigger)
            repetition_stop_duration_end = str_to_bool(self.get_element("Repetition/StopAtDurationEnd", trigger))
            execution_time_limit = self.get_element("ExecutionTimeLimit", trigger)
            delay = self.get_element("Delay", trigger)
            random_delay = self.get_element("RandomDelay", trigger)
            trigger_data = self.get_element("Data", trigger)

            base = BaseTriggerRecord(
                trigger_enabled=trigger_enabled,
                start_boundary=start_boundary,
                end_boundary=end_boundary,
                repetition_interval=repetition_interval,
                repetition_duration=repetition_duration,
                repetition_stop_duration_end=repetition_stop_duration_end,
                execution_time_limit=execution_time_limit,
                delay=delay,
                random_delay=random_delay,
                trigger_data=trigger_data,
            )

            if trigger_type == "LogonTrigger":
                user_id = self.get_element("UserId", trigger)
                record = LogonTriggerRecord(
                    user_id=user_id,
                )
                yield GroupedRecord(LogonTriggerRecord.name, [base, record])

            elif trigger_type == "BootTrigger":
                yield GroupedRecord(BootTriggerRecord.name, [base])

            elif trigger_type == "IdleTrigger":
                yield GroupedRecord(IdleTriggerRecord.name, [base])

            elif trigger_type == "TimeTrigger":
                yield GroupedRecord(TimeTriggerRecord.name, [base])

            elif trigger_type == "EventTrigger":
                subscription = self.get_element("Subscription", trigger)
                period_of_occurence = self.get_element("PeriodOfOccurrence", trigger)
                number_of_occurences = self.get_element("NumberOfOccurences", trigger)
                matching_elements = self.get_element("MatchingElement", trigger)
                value_queries = self.get_element("ValueQueries/Value", trigger)

                record = EventTriggerRecord(
                    subscription=subscription,
                    period_of_occurence=period_of_occurence,
                    number_of_occurences=number_of_occurences,
                    matching_elements=matching_elements,
                    value_queries=value_queries,
                )

                yield GroupedRecord(EventTriggerRecord.name, [base, record])

            elif trigger_type == "SessionStateChangeTrigger":
                user_id = self.get_element("UserId", trigger)
                state_change = self.get_element("StateChange", trigger)

                record = SessionStateChangeTriggerRecord(
                    user_id=user_id,
                    state_change=state_change,
                )

                yield GroupedRecord(SessionStateChangeTriggerRecord.name, [base, record])

            elif trigger_type == "CalendarTrigger":
                if days_between_triggers := self.get_element("ScheduleByDay/DaysInterval", trigger):
                    record = DailyTriggerRecord(
                        days_between_triggers=int(days_between_triggers),
                    )

                elif weeks_between_triggers := self.get_element("ScheduleByWeek/WeeksInterval", trigger):
                    days_of_week = [day.tag for day in trigger.find("ScheduleByWeek/DaysOfWeek/").iter("*")]
                    record = WeeklyTriggerRecord(
                        weeks_between_triggers=int(weeks_between_triggers),
                        days_of_week=days_of_week,
                    )

                elif trigger.find("ScheduleByMonth/") is not None:
                    day_of_month = [int(day.text) for day in trigger.iter("Day")]
                    months_of_year = [month.tag for month in trigger.findall("*/Months/*")]
                    record = MonthlyDateTriggerRecord(
                        day_of_month=day_of_month,
                        months_of_year=months_of_year,
                    )

                elif trigger.find("ScheduleByMonthDayOfWeek/") is not None:
                    which_week = [int(week.text) for week in trigger.iter("Week")]
                    days_of_week = [day.tag for day in trigger.findall("*/DaysOfWeek/*")]
                    months_of_year = [month.tag for month in trigger.findall("*/Months/*")]
                    record = MonthlyDowTriggerRecord(
                        which_week=which_week,
                        days_of_week=days_of_week,
                        months_of_year=months_of_year,
                    )

                else:
                    raise ValueError("Unknown calendar type")

                yield GroupedRecord(CalendarTriggerRecord.name, [base, record])

            elif trigger_type == "WnfStateChangeTrigger":
                state_name = self.get_element("StateName", trigger)

                record = WnfTriggerRecord(
                    state_name=state_name,
                )

                yield GroupedRecord(WnfTriggerRecord.name, [base, record])

            elif trigger_type == "RegistrationTrigger":
                date = self.get_element("Date", trigger)

                record = RegistrationTrigger(
                    date=date,
                )

                yield GroupedRecord(RegistrationTrigger.name, [base, record])

            else:
                raise ValueError(f"Unknown trigger type: {trigger_type}")

    def get_actions(self) -> Iterator[GroupedRecord]:
        """Get the actions from the XML task data.

        Yields:
            ActionRecord: The action record representing an action.
        """
        for action in self.task_element.findall("Actions/*"):
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
                    com_data=com_data,
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
