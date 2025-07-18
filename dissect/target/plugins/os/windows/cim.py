from __future__ import annotations

import ast
import json
import urllib.parse
from typing import TYPE_CHECKING
from dataclasses import dataclass, asdict

from dissect.cim import cim
from dissect.util.sid import read_sid

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

# https://learn.microsoft.com/en-us/windows/win32/wmisdk/--eventconsumer
COMMON_ELEMENTS = [
    ("string", "creator_sid"),
    ("string", "machine_name"),
    ("string", "filter_query"),
    ("string", "filter_name"),
    ("string", "filter_query_language"),
    ("string", "filter_creator_sid"),
]

CommandLineEventConsumerRecord = TargetRecordDescriptor(
    "filesystem/windows/cim/consumerbinding/commandlineeventconsumer",
    COMMON_ELEMENTS
    + [
        ("string", "command_line_template"),
        ("string", "executable_path"),
        ("string", "working_directory"),
    ],
)

# https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer
ActiveScriptEventConsumerRecord = TargetRecordDescriptor(
    "filesystem/windows/cim/consumerbinding/activescripteventconsumer",
    COMMON_ELEMENTS
    + [
        ("string", "script_text"),
        ("string", "script_file_name"),
        ("string", "scripting_engine"),
        ("string", "name"),
    ],
)


@dataclass
class EventFilter:
    """
    object representing information extracted from __EventFilter
    References:
        - https://learn.microsoft.com/en-us/windows/win32/wmisdk/--eventfilter
    """

    filter_query: str = ""
    filter_name: str = ""
    filter_query_language: str = ""
    filter_creator_sid: str = ""


class CimPlugin(Plugin):
    """CIM database plugin.

    Provides functions for getting useful data out the CIM (WBEM) database.
    """

    __namespace__ = "cim"

    def __init__(self, target: Target):
        super().__init__(target)
        self._repo = None
        repodir = self.target.resolve("%windir%/system32/wbem/repository")
        self._subscription_ns = None
        self._filters: dict[str, EventFilter] = {}
        if repodir.exists():
            index = repodir.joinpath("index.btr")
            objects = repodir.joinpath("objects.data")
            mappings = [repodir.joinpath(f"mapping{i}.map") for i in range(1, 4)]

            if all([index.exists(), objects.exists(), all(m.exists() for m in mappings)]):
                try:
                    self._repo = cim.CIM(index.open(), objects.open(), [m.open() for m in mappings])
                except cim.Error as e:
                    self.target.log.warning("Error opening CIM database")
                    self.target.log.debug("", exc_info=e)
            self._subscription_ns = self._repo.root.namespace("subscription")
            self._filters = self.generate_filters_dict()

    def check_compatible(self) -> None:
        if not self._repo:
            raise UnsupportedPluginError("No WBEM repository found")

    @internal
    def repo(self) -> cim.CIM:
        return self._repo

    def yield_consumerbinings(self) -> Iterator[tuple[cim.Instance, str]]:
        """
        yield consumer binded to __filtertoconsumerbinding of subscription namespace
        """
        subscription_ns = self._repo.root.namespace("subscription")
        filters = {}
        try:
            for binding in subscription_ns.class_("__filtertoconsumerbinding").instances:
                filter_name = self.get_filter_name(binding)
                yield (
                    subscription_ns.query(binding.properties["Consumer"].value),
                    filter_name,
                )
        except Exception as e:  # noqa
            self.target.log.warning("Error during consumerbindings execution", exc_info=e)
            self.target.log.debug("", exc_info=e)

    @export(record=CommandLineEventConsumerRecord)
    def command_line_event_consumer(self) -> Iterator[CommandLineEventConsumerRecord]:
        """Return all CommandLineEventConsumer queries.

        WMI permanent event subscriptions can be used to trigger actions when specified conditions are met. Attackers
        often use this functionality to persist the execution of backdoors at system start up. WMI Consumers specify an
        action to be performed, including executing a command, running a script, adding an entry to a log, or sending
        an email. WMI Filters define conditions that will trigger a Consumer.

        References:
            - https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/
            - https://www.mandiant.com/resources/dissecting-one-ofap
            - https://support.sophos.com/support/s/article/KB-000038535?language=en_US&c__displayLanguage=en_US
            - https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer
        """
        for consumer, filter_name in self.yield_consumerbinings():
            if query := consumer.properties.get("CommandLineTemplate"):
                yield CommandLineEventConsumerRecord(
                    command_line_template=self.get_property_value_safe(consumer, "CommandLineTemplate", ""),
                    executable_path=self.get_property_value_safe(consumer, "ExecutablePath", ""),
                    working_directory=self.get_property_value_safe(consumer, "WorkingDirectory", ""),
                    creator_sid=self.get_creator_sid(consumer),
                    _target=self.target,
                    **asdict(self._filters.get(filter_name, EventFilter(filter_name=filter_name))),
                )

    @export(record=ActiveScriptEventConsumerRecord)
    def active_script_event_consumer(self) -> Iterator[ActiveScriptEventConsumerRecord]:
        """Return all ActiveScriptEventConsumer.

        WMI permanent event subscriptions can be used to trigger actions when specified conditions are met. Attackers
        often use this functionality to persist the execution of backdoors at system start up. WMI Consumers specify an
        action to be performed, including executing a command, running a script, adding an entry to a log, or sending
        an email. WMI Filters define conditions that will trigger a Consumer.

        References:
            - https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/
            - https://www.mandiant.com/resources/dissecting-one-ofap
            - https://support.sophos.com/support/s/article/KB-000038535?language=en_US&c__displayLanguage=en_US
            - https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer
        """
        for consumer, filter_name in self.yield_consumerbinings():
            if query := consumer.properties.get("ScriptText"):
                yield ActiveScriptEventConsumerRecord(
                    script_text=self.get_property_value_safe(consumer, "ScriptText", ""),
                    script_file_name=self.get_property_value_safe(consumer, "ScriptFileName", ""),
                    scripting_engine=self.get_property_value_safe(consumer, "ScriptingEngine", ""),
                    machine_name=self.get_property_value_safe(consumer, "MachineName", ""),
                    name=self.get_property_value_safe(consumer, "Name", ""),
                    creator_sid=self.get_creator_sid(consumer),
                    **asdict(self._filters.get(filter_name, EventFilter(filter_name=filter_name))),
                    _target=self.target,
                )

    @staticmethod
    def get_property_value_safe(consumer, prop_name: str, default_value: str | None = None) -> str | None:
        """
        Extract value of a consumer properties. Fallback to default_value if properties is missing
        """
        prop = consumer.properties.get(prop_name)
        if not prop:
            return default_value
        try:
            return str(prop.value)
        except ValueError:
            return default_value

    def get_creator_sid(self, class_instance) -> str | None:
        """
        Extract and parse CreatorSID member
        """
        creator_sid = class_instance.properties.get("CreatorSID")
        if creator_sid:
            creator_sid_value = getattr(creator_sid, "value", None)
            if creator_sid:
                return read_sid(bytes(creator_sid_value))
        return None

    def generate_filters_dict(self) -> dict[str, EventFilter]:
        """
        Generate a dict of __EventFilter that will be mapped with __filtertoconsumerbinding
        """
        filters = {}
        for event in self._subscription_ns.class_("__EventFilter").instances:
            filter_name = event.properties["Name"].value
            filters[filter_name] = EventFilter(
                filter_query=event.properties["Query"].value,
                filter_query_language=event.properties["QueryLanguage"].value,
                filter_name=filter_name,
                filter_creator_sid=self.get_creator_sid(event),
            )
        return filters

    @staticmethod
    def get_filter_name(binding: cim.ClassInstance) -> str:
        """
        return unquoted filter name from a __filtertoconsumerbinding class instance
        """
        filter_name = binding.properties["Filter"].value
        # filter name is not always consistent
        # e.g : __EventFilter.Name="Windows Update Event MOF" or \\.\root\subscription:__EventFilter.Name="Windows Update Event MOF"
        if "=" in filter_name:
            # Required to manage filters name with escaped "
            filter_name = filter_name.split("=", maxsplit=1)[1]
            filter_name = filter_name.strip('"').replace('\\"', '"')
        return filter_name
