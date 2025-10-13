from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

HyperVHostInfo = TargetRecordDescriptor("hypervisor/hyperv/host_info", [("string", "hyperv_host_name")])


class HyperVPlugin(Plugin):
    __namespace__ = "hyperv"

    def check_compatible(self) -> None:
        pass

    @export(record=HyperVHostInfo)
    def host(self) -> Iterator[TargetRecordDescriptor]:
        """Extract the hostname of the parent Hyper-V system (Windows or Linux guest)."""
        if self.target.os == OperatingSystem.WINDOWS.value:
            host_name = self._get_parent_hostname_windows()
        if self.target.os == OperatingSystem.LINUX.value:
            host_name = self._get_parent_hostname_linux()

        yield HyperVHostInfo(hyperv_host_name=host_name)

    def _get_parent_hostname_windows(self) -> str | None:
        try:
            key = self.target.registry.key("HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")
            return key.value("HostName").value
        except Exception:
            return None

    def _get_parent_hostname_linux(self) -> str | None:
        try:
            # Check if running under Hyper-V
            product_name = Path("/sys/class/dmi/id/product_name").read_text().strip()
            if "hyper-v" not in product_name.lower():
                return None
            # Try to get the host name from DMI sys_vendor or board_vendor
            for dmi_file in ["/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor"]:
                p = Path(dmi_file)
                if p.exists():
                    vendor = p.read_text().strip()
                    if vendor:
                        return vendor
        except Exception:
            return None
