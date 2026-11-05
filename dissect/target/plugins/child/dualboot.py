from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import TargetError, UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator


class DualBootChildTargetPlugin(ChildTargetPlugin):
    """Dual boot child plugin."""

    __type__ = "dualboot"

    def check_compatible(self) -> None:
        if not self.target.fs.path("/$fs$").is_dir():
            raise UnsupportedPluginError("No unused mounted filesystems found on target")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        """Iterate over all filesystem mounts in ``/$fs$`` and yields those with an OS."""
        for path, fs in self.target.fs.mounts.items():
            if not path.startswith("/$fs$"):
                continue

            try:
                target = Target.open_filesystem(fs)
            except TargetError:
                continue

            if not target.os or target.os == "default":
                continue

            try:
                name = target.hostname
            except Exception:
                name = None

            yield ChildTargetRecord(
                type=f"{self.__type__}_{target.os}",
                name=name,
                path=path,
                _target=self.target,
            )
