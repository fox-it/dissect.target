import warnings
from typing import Iterator, Optional
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from flow.record import GroupedRecord, RecordDescriptor

from dissect.target.exceptions import InvalidTaskError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.plugins.os.windows.task_helpers.tasks_records import (
    BootTriggerRecord,
    ComHandlerRecord,
    EventTriggerRecord,
    ExecRecord,
    LogonTriggerRecord,
    SendEmailRecord,
    SessionStateChangeTriggerRecord,
    ShowMessageRecord,
    TimeTriggerRecord,
    TriggerRecord,
)

warnings.simplefilter(action="ignore", category=FutureWarning)


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
                if element.tag.startswith(ns):
                    element.tag = element.tag[len(ns) :]
        return data

    def get_tasks(self):
        tasks = []
        if self.xml_data.tag == "Task":
            tasks.append(XmlTask(self.xml_data, self.task_path))
        else:
            for task_element in self.xml_data.findall(".//{*}Task"):
                tasks.append(XmlTask(task_element, self.task_path))

        return tasks


class XmlTask:
    """Initialize the XmlTask class for open XML-based task files.

    Args:
        xml_file: the file to be parsed.
        target: the target system.
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
        self.enabled = self.get_element("Properties", attribute="enabled")
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
        self.display_name = self.get_element("Principals/Principal/DisplayName")
        self.run_level = self.get_element("Principals/Principal/RunLevel")
        self.process_token_sid_type = self.get_element("Principals/Principal/ProcessTokenSidType")
        self.required_privileges = self.get_element("Principals/Principal/RequiredPrivileges")

        # Settings
        self.allow_start_on_demand = self.get_element("Settings/AllowStartOnDemand")
        self.restart_on_failure_interval = self.get_element("Settings/RestartOnFailure/Interval")
        self.restart_on_failure_count = self.get_element("Settings/RestartOnFailure/Count")
        self.mutiple_instances_policy = self.get_element("Settings/MultipleInstancesPolicy")
        self.dissalow_start_on_batteries = self.get_element("Settings/DisallowStartIfOnBatteries")
        self.stop_going_on_batteries = self.get_element("Settings/StopIfGoingOnBatteries")
        self.allow_hard_terminate = self.get_element("Settings/AllowHardTerminate")
        self.start_when_available = self.get_element("Settings/StartWhenAvailable")
        self.network_profile_name = self.get_element("Settings/NetworkProfileName")
        self.run_only_network_available = self.get_element("Settings/RunOnlyIfNetworkAvailable")
        self.wake_to_run = self.get_element("Settings/WakeToRun")
        self.enabled = self.get_element("Settings/Enabled")
        self.hidden = self.get_element("Settings/Hidden")
        self.delete_expired_task_after = self.get_element("Settings/DeleteExpiredTaskAfter")
        self.idle_duration = self.get_element("Settings/IdleSettings/Duration")
        self.idle_wait_timeout = self.get_element("Settings/IdleSettings/WaitTimeout")
        self.idle_stop_on_idle_end = self.get_element("Settings/IdleSettings/StopOnIdleEnd")
        self.idle_restart_on_idle = self.get_element("Settings/IdleSettings/RestartOnIdle")
        self.network_settings_name = self.get_element("Settings/NetworkSettings/Name")
        self.network_settings_id = self.get_element("Settings/NetworkSettings/Id")
        self.execution_time_limit = self.get_element("Settings/ExecutionTimeLimit")
        self.priority = self.get_element("Settings/Priority")
        self.run_only_idle = self.get_element("Settings/RunOnlyIfIdle")
        self.unified_scheduling_engine = self.get_element("Settings/UseUnifiedSchedulingEngine")
        self.disallow_start_on_remote_app_session = self.get_element("Settings/DisallowStartOnRemoteAppSession")

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
                if element.tag.startswith(ns):
                    element.tag = element.tag[len(ns) :]
        return data

    def get_element(
        self, xml_path: str, xml_data: Optional[Element] = None, attribute: Optional[str] = None
    ) -> Optional[str]:
        """Get the value of the specified XML element.

        Args:
            xml_path: The string used to locate the element.
            xml_data: The XML data to search in. If not provided, use self.xml_data.
            attribute: The name of a specific attribute from an element that should be returned.

        Returns:
            str: The value of the XML element if found, otherwise None.
        """
        xml_data = xml_data or self.task_element
        data = xml_data.find(xml_path)

        if data is None:
            return
        if attribute:
            return data.get(attribute)

        return data.text

    def get_raw(self, xml_path: Optional[str] = None) -> str:
        """Get the raw XML data of the specified element.

        Args:
            xml_path: The string used to locate the element.

        Returns:
            bytes: The raw XML data as string of the element if found, otherwise None.
        """
        data = self.task_element.find(xml_path) if xml_path else self.task_element
        if data:
            return ElementTree.tostring(data, encoding="utf-8").strip()

    def get_triggers(self) -> Iterator[GroupedRecord]:
        """Get the triggers from the XML task data.

        Yields:
            GroupedRecord: The grouped record representing a trigger.
        """
        for trigger in self.task_element.findall("Triggers/*"):
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
                delay = self.get_element("Delay", trigger)
                record = LogonTriggerRecord(
                    user_id=user_id,
                    delay=delay,
                )
                yield GroupedRecord("filesystem/windows/task/logon_trigger", [base, record])

            if trigger_type == "BootTrigger":
                delay = self.get_element("Delay", trigger)
                record = BootTriggerRecord(delay=delay)
                yield GroupedRecord("filesystem/windows/task/boot_trigger", [base, record])

            if trigger_type == "IdleTrigger":
                pass  # No extra fields

            if trigger_type == "TimeTrigger":
                random_delay = self.get_element("RandomDelay", trigger)

                record = TimeTriggerRecord(random_delay=random_delay)
                yield GroupedRecord("filesystem/windows/task/time_trigger", [base, record])

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

                yield GroupedRecord("filesystem/windows/task/event_trigger", [base, record])

            if trigger_type == "SessionStateChangeTrigger":
                user_id = self.get_element("UserId", trigger)
                delay = self.get_element("Delay", trigger)
                state_change = self.get_element("StateChange", trigger)

                record = SessionStateChangeTriggerRecord(
                    user_id=user_id,
                    delay=delay,
                    state_change=state_change,
                )

                yield GroupedRecord("filesystem/windows/task/sessionstate_trigger", [base, record])

            if trigger_type == "CalendarTrigger":
                pass

    def get_actions(self) -> Iterator[RecordDescriptor]:
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
