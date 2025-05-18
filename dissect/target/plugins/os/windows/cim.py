from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cim import cim

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

ConsumerBindingRecord = TargetRecordDescriptor(
    "filesystem/windows/cim/consumerbinding",
    [
        ("string", "query"),
    ],
)


class CimPlugin(Plugin):
    """CIM database plugin.

    Provides functions for getting useful data out the CIM (WBEM) database.
    """

    __namespace__ = "cim"

    def __init__(self, target: Target):
        super().__init__(target)
        self._repo = None

        repodir = self.target.fs.path("sysvol/windows/system32/wbem/repository")
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

    def check_compatible(self) -> None:
        if not self._repo:
            raise UnsupportedPluginError("No WBEM repository found")

    @internal
    def repo(self) -> cim.CIM:
        return self._repo

    @export(record=ConsumerBindingRecord)
    def consumerbindings(self) -> Iterator[ConsumerBindingRecord]:
        """Return all __FilterToConsumerBinding queries.

        WMI permanent event subscriptions can be used to trigger actions when specified conditions are met. Attackers
        often use this functionality to persist the execution of backdoors at system start up. WMI Consumers specify an
        action to be performed, including executing a command, running a script, adding an entry to a log, or sending
        an email. WMI Filters define conditions that will trigger a Consumer.

        References:
            - https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/
            - https://www.mandiant.com/resources/dissecting-one-ofap
            - https://support.sophos.com/support/s/article/KB-000038535?language=en_US&c__displayLanguage=en_US
        """
        subscription_ns = self._repo.root.namespace("subscription")
        try:
            for binding in subscription_ns.class_("__filtertoconsumerbinding").instances:
                consumer = subscription_ns.query(binding.properties["Consumer"].value)
                if query := consumer.properties.get("CommandLineTemplate"):
                    yield ConsumerBindingRecord(
                        query=query.value,
                        _target=self.target,
                    )
        except Exception as e:
            self.target.log.warning("Error during consumerbindings execution")
            self.target.log.debug("", exc_info=e)
