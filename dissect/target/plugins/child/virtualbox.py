from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree as ET
from dissect.hypervisor.descriptor.vbox import VBox

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


class VirtualBoxChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Oracle VirtualBox VMs.

    Tested with configuration files from major versions 5, 6 and 7.

    Resources:
        - https://docs.oracle.com/en/virtualization/virtualbox/6.1/admin/TechnicalBackground.html
    """

    __type__ = "virtualbox"

    USER_PATHS = (
        # Windows
        ".VirtualBox",
        # Linux
        ".config/VirtualBox",
        # macOS
        "Library/VirtualBox",
    )

    DEFAULT_PATHS = ("VirtualBox VMs",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.vboxes = list(self.find_vms())

    def find_vms(self) -> Iterator[Path]:
        """Yield Oracle VirtualBox ``.vbox`` file(s) found on the target."""
        seen = set()

        for user_details in self.target.user_details.all_with_home():
            # Yield `.vbox` from default locations and add to seen.
            for default_path in self.DEFAULT_PATHS:
                for path in user_details.home_path.joinpath(default_path).glob("*/*.vbox"):
                    if path not in seen and path.is_file():
                        seen.add(path)
                        yield path

            # Parse VirtualBox.xml configs
            for user_path in self.USER_PATHS:
                # Search for both VirtualBox.xml and VirtualBox.xml-prev
                for path in user_details.home_path.joinpath(user_path).glob("VirtualBox.xml*"):
                    if not path.is_file():
                        self.target.log.warning("Unable to parse %s: not a file", path)
                        continue

                    try:
                        config = ET.fromstring(path.read_text())
                    except Exception as e:
                        self.target.log.warning("Unable to parse %s: %s", path, e)
                        self.target.log.debug("", exc_info=e)
                        continue

                    # Parse MachineEntries
                    for machine in config.findall(f".//{VBox.VBOX_XML_NAMESPACE}MachineEntry"):
                        if (
                            (src := machine.get("src"))
                            and (src_path := self.target.fs.path(src)).exists()
                            and src_path not in seen
                        ):
                            seen.add(src_path)
                            yield src_path

                    # Glob for SystemProperties defaultMachineFolder
                    for system_properties in config.findall(f".//{VBox.VBOX_XML_NAMESPACE}SystemProperties"):
                        if (folder_str := system_properties.get("defaultMachineFolder")) and (
                            folder_dir := self.target.fs.path(folder_str)
                        ).is_dir():
                            for vbox_file in folder_dir.glob("*/*.vbox"):
                                if vbox_file not in seen:
                                    seen.add(vbox_file)
                                    yield vbox_file

    def check_compatible(self) -> None:
        if not self.vboxes:
            raise UnsupportedPluginError("No VirtualBox children found on target")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for vbox in self.vboxes:
            yield ChildTargetRecord(
                type=self.__type__,
                path=vbox,
                _target=self.target,
            )
