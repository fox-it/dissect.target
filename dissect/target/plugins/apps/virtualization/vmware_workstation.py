from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from dissect.hypervisor.descriptor.vmx import VMX

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, alias, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

VmwareDragAndDropRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "virtualization/vmware/clipboard",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

VmwareVirtualMachineRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "virtualization/vmware/virtual_machine",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("boolean", "is_clone"),
        ("boolean", "is_favorite"),
        ("string", "state"),
        ("string", "uuid"),
        ("string", "annotation"),
        ("string[]", "mac_addresses"),
        ("path[]", "disks"),
        ("path[]", "sources"),
    ],
)


INVENTORY_PATHS = [
    # Windows
    "AppData/Roaming/VMware/inventory.vmls",
    # Linux
    ".vmware/inventory.vmls",
    # macOS (Fusion)
    "Library/Application Support/VMware Fusion/vmInventory",
]


DND_PATHS = [
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
        self.inventories = list(find_vm_inventory(self.target))
        self.dnd_dirs = list(self.find_dnd_dirs())

    def check_compatible(self) -> None:
        if not self.dnd_dirs and not self.inventories:
            raise UnsupportedPluginError("No VMware Workstation artifact(s) found")

    def find_dnd_dirs(self) -> Iterator[tuple[UserDetails, Path]]:
        for user_details in self.target.user_details.all_with_home():
            for dnd_path in DND_PATHS:
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

    @export(record=VmwareVirtualMachineRecord)
    def config(self) -> Iterator[VmwareVirtualMachineRecord]:
        """Yield VMware Workstation Virtual Machine inventory configurations.

        Parses ``inventory.vmls`` and ``.vmx`` descriptor files. Does not parse newer ``.vmxf`` XML files.
        Does not support older ``vmAutoStart.xml`` or ``vmInventory.xml`` formats.

        References:
            - https://sanbarrow.com/vmx/vmx-network-advanced.html
        """

        for inventory, user_details in self.inventories:
            for config in parse_inventory_file(inventory).values():
                vmx_config = {}

                if (vmx_path := self.target.fs.path(config.get("config"))).exists():
                    vmx = VMX.parse(vmx_path.read_text())
                    vmx_config = vmx.attr

                yield VmwareVirtualMachineRecord(
                    ts=vmx_path.lstat().st_mtime if vmx_config else inventory.lstat().st_mtime,
                    # Inventory config fields
                    name=config.get("DisplayName"),
                    is_clone=config.get("IsClone", "").lower() == "true",
                    is_favorite=config.get("IsFavorite", "").lower() == "true",
                    state=config.get("State"),
                    uuid=config.get("UUID").replace(" ", ""),
                    # VMX config fields
                    annotation=vmx_config.get("annotation"),
                    mac_addresses={v for k, v in vmx_config.items() if k.endswith(("generatedAddress", "address"))},
                    disks=vmx.disks(),
                    # Metadata
                    sources=[inventory, vmx_path],
                    _user=user_details.user if user_details else None,
                    _target=self.target,
                )


def find_vm_inventory(target: Target) -> Iterator[tuple[Path, UserDetails]]:
    """Search for ``inventory.vmls`` files in user home folders."""

    for user_details in target.user_details.all_with_home():
        for inv_path in INVENTORY_PATHS:
            if (inv_file := user_details.home_path.joinpath(inv_path)).exists():
                yield inv_file, user_details


def parse_inventory_file(inventory: Path) -> dict[str, Any] | None:
    """Parse a single ``inventory.vmls`` (Windows, Linux) or ``vmInventory`` (macOS) file."""

    config = defaultdict(dict)
    with inventory.open("rt") as fh:
        for line in map(str.strip, fh):
            if not line or line.startswith("."):
                continue
            full_key, value = map(str.strip, line.split("=", 1))
            vm, key = full_key.split(".", 1)

            # Only process vmlist entries, not index entries
            if "vmlist" not in vm:
                continue

            config[vm][key] = value.strip('"')
        return config
