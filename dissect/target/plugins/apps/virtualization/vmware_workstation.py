from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, alias, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

VmwareDragAndDropRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "virtualization/vmware/clipboard",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

VMWARE_DND_PATHS = [
    # Windows
    "AppData/Local/Temp/VmwareDND",
    # Linux
    ".cache/vmware/drag_and_drop",
]


class VmwareWorkstationPlugin(Plugin):
    """VMware Workstation plugin."""

    __namespace__ = "vmware"

    def __init__(self, target: Target):
        super().__init__(target)
        self.dnd_dirs = list(self.find_dnd_dirs())

    def check_compatible(self) -> None:
        if not self.dnd_dirs:
            raise UnsupportedPluginError("No VMware Workstation DnD artifact(s) found")

    def find_dnd_dirs(self) -> Iterator[tuple[UserDetails, TargetPath]]:
        for user_details in self.target.user_details.all_with_home():
            for dnd_path in VMWARE_DND_PATHS:
                if (dnd_dir := user_details.home_path.joinpath(dnd_path)).exists():
                    yield user_details, dnd_dir

    @alias("draganddrop")
    @export(record=VmwareDragAndDropRecord)
    def clipboard(self) -> Iterator[VmwareDragAndDropRecord]:
        """Yield cached VMware Workstation drag-and-drop file artifacts."""

        for user_details, dnd_dir in self.dnd_dirs:
            for file in dnd_dir.rglob("*/*"):
                if file.is_dir():
                    continue

                yield VmwareDragAndDropRecord(
                    ts=file.lstat().st_mtime,
                    path=file,
                    _user=user_details.user,
                    _target=self.target,
                )
