from __future__ import annotations

import json
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

OSInfoRecord = TargetRecordDescriptor(
    "generic/osinfo",
    [
        ("string", "values"),
    ],
)


class OSInfoPlugin(Plugin):
    """Convenience plugin that wraps _os.* functions in records."""

    def check_compatible(self) -> None:
        if not self.target._os_plugin:
            raise UnsupportedPluginError("No operating system detected on target")

    @export(record=OSInfoRecord)
    def osinfo(self) -> Iterator[OSInfoRecord]:
        """Yield one aggregated OS info record for the current target."""
        values = {}

        for os_func in self.target._os.__exports__:
            value = getattr(self.target._os, os_func)

            if isinstance(value, Callable):
                try:
                    value = value()
                except Exception:
                    # Ignore exceptions triggered by functions that cannot
                    # be executed in this context.
                    continue

            if isinstance(value, Generator):
                # Materialize generator-style exports so they can be represented
                # in the aggregated payload.
                try:
                    values[os_func] = list(value)
                except Exception:
                    # Ignore exceptions triggered while consuming generators
                    # that cannot be executed in this context.
                    continue
                continue

            values[os_func] = value

        yield OSInfoRecord(values=json.dumps(values, default=str, sort_keys=True), _target=self.target)
