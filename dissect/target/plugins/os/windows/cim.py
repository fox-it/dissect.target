from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

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
    [
        *COMMON_ELEMENTS,
        ("string", "command_line_template"),
        ("string", "executable_path"),
        ("string", "working_directory"),
    ],
)

# https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer
ActiveScriptEventConsumerRecord = TargetRecordDescriptor(
    "filesystem/windows/cim/consumerbinding/activescripteventconsumer",
    [
        *COMMON_ELEMENTS,
        ("string", "script_text"),
        ("string", "script_file_name"),
        ("string", "scripting_engine"),
        ("string", "name"),
    ],
)


@dataclass
class EventFilter:
    """Extracted information from ``__EventFilter``.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/wmisdk/--eventfilter
    """

    filter_name: str = ""
    filter_query: str = ""
    filter_query_language: str = ""
    filter_creator_sid: str = ""


def get_property_value_safe(consumer: cim.Instance, prop_name: str, default_value: str | None = None) -> str | None:
    """Extract value of a consumer properties. Fallback to ``default_value`` if property is missing."""
    if not (prop := consumer.properties.get(prop_name)):
        return default_value
    try:
        return str(prop.value)
    except ValueError:
        return default_value


def get_filter_name(binding: cim.Instance) -> str:
    """Return unquoted filter name from a ``__filtertoconsumerbinding`` class instance."""
    filter_name = binding.properties["Filter"].value
    # filter name is not always consistent
    # e.g : __EventFilter.Name="Windows Update Event MOF" or
    # \\.\root\subscription:__EventFilter.Name="Windows Update Event MOF"
    if "=" in filter_name:
        # Required to manage filters name with escaped "
        _, _, filter_name = filter_name.partition("=")
        filter_name = filter_name.strip('"').replace('\\"', '"')
    return filter_name


def get_creator_sid(class_instance: cim.Instance) -> str | None:
    """Extract and parse ``CreatorSID`` member, if available."""
    if (creator_sid := class_instance.properties.get("CreatorSID")) and (
        creator_sid_value := getattr(creator_sid, "value", None)
    ):
        return read_sid(bytes(creator_sid_value))
    return None


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
            self._filters = self._get_filters()

    def check_compatible(self) -> None:
        if not self._repo:
            raise UnsupportedPluginError("No WBEM repository found")

    @internal
    def repo(self) -> cim.CIM:
        return self._repo

    def _iter_consumerbindings(self) -> Iterator[tuple[cim.Instance, str]]:
        """Yield consumer bindings from ``__filtertoconsumerbinding`` of subscription namespace."""
        try:
            for binding in self._subscription_ns.class_("__filtertoconsumerbinding").instances:
                yield (
                    self._subscription_ns.query(binding.properties["Consumer"].value),
                    get_filter_name(binding),
                )
        except Exception as e:
            self.target.log.warning("Error retrieving consumerbindings")
            self.target.log.debug("", exc_info=e)

    @export(record=[ActiveScriptEventConsumerRecord, CommandLineEventConsumerRecord])
    def consumerbindings(self) -> Iterator[ActiveScriptEventConsumerRecord | CommandLineEventConsumerRecord]:
        """Return all ActiveScriptEventConsumer and CommandLineEventConsumer.

        WMI permanent event subscriptions can be used to trigger actions when specified conditions are met. Attackers
        often use this functionality to persist the execution of backdoors at system start up. WMI Consumers specify an
        action to be performed, including executing a command, running a script, adding an entry to a log, or sending
        an email. WMI Filters define conditions that will trigger a Consumer.

        References:
            - https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/
            - https://www.mandiant.com/resources/dissecting-one-ofap
            - https://support.sophos.com/support/s/article/KB-000038535?language=en_US&c__displayLanguage=en_US
            - https://learn.microsoft.com/en-us/windows/win32/wmisdk/activescripteventconsumer
            - https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer
        """
        for consumer, filter_name in self._iter_consumerbindings():
            if consumer.properties.get("ScriptText"):
                yield ActiveScriptEventConsumerRecord(
                    script_text=get_property_value_safe(consumer, "ScriptText", ""),
                    script_file_name=get_property_value_safe(consumer, "ScriptFileName", ""),
                    scripting_engine=get_property_value_safe(consumer, "ScriptingEngine", ""),
                    machine_name=get_property_value_safe(consumer, "MachineName", ""),
                    name=get_property_value_safe(consumer, "Name", ""),
                    creator_sid=get_creator_sid(consumer),
                    _target=self.target,
                    **asdict(self._filters.get(filter_name, EventFilter(filter_name=filter_name))),
                )
            if consumer.properties.get("CommandLineTemplate"):
                yield CommandLineEventConsumerRecord(
                    command_line_template=get_property_value_safe(consumer, "CommandLineTemplate", ""),
                    executable_path=get_property_value_safe(consumer, "ExecutablePath", ""),
                    working_directory=get_property_value_safe(consumer, "WorkingDirectory", ""),
                    creator_sid=get_creator_sid(consumer),
                    _target=self.target,
                    **asdict(self._filters.get(filter_name, EventFilter(filter_name=filter_name))),
                )

    def _get_filters(self) -> dict[str, EventFilter]:
        """Generate a dictionary of ``__EventFilter`` that can be mapped with ``__filtertoconsumerbinding``."""
        filters = {}
        for event in self._subscription_ns.class_("__EventFilter").instances:
            filter_name = event.properties["Name"].value
            filters[filter_name] = EventFilter(
                filter_name=filter_name,
                filter_query=event.properties["Query"].value,
                filter_query_language=event.properties["QueryLanguage"].value,
                filter_creator_sid=get_creator_sid(event),
            )
        return filters
