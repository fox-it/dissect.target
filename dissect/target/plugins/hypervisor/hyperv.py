from __future__ import annotations
import subprocess
from pathlib import Path

from dissect.target.plugin import Plugin, internal, OperatingSystem


class HyperVPlugin(Plugin):
    __namespace__ = "hyperv"

    @internal
    def get_parent_hostname(self) -> str | None:
        """Extract the hostname of the parent Hyper-V system (Windows or Linux guest)."""
        if self.target.os == OperatingSystem.WINDOWS.value:
            return self._get_parent_hostname_windows()
        if self.target.os == OperatingSystem.LINUX.value:
            return self._get_parent_hostname_linux()
        return None

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
            return None
        except Exception:
            return None
