from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util import ts

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.generic import calculate_last_activity

if TYPE_CHECKING:
    from datetime import datetime


class GenericPlugin(Plugin):
    """Generic FortiOS plugin."""

    def check_compatible(self) -> None:
        if self.target.os != "fortios":
            raise UnsupportedPluginError("FortiOS specific plugin loaded on non-FortiOS target")

    @export(property=True)
    def install_date(self) -> datetime | None:
        """Return the likely install date of FortiOS."""
        files = ["/data/etc/cloudinit.log", "/data/.vm_provisioned", "/data/etc/ssh/ssh_host_dsa_key"]
        for file in files:
            if (fp := self.target.fs.path(file)).exists():
                return ts.from_unix(fp.stat().st_mtime)
        return None

    @export(property=True)
    def activity(self) -> datetime | None:
        """Return last seen activity based on filesystem timestamps."""
        log_dirs = ["/var/log/log/root", "/var/log/root", "/data"]
        for log_dir in log_dirs:
            if (var_log := self.target.fs.path(log_dir)).exists():
                return calculate_last_activity(var_log)
        return None
