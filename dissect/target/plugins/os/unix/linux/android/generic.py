from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util import ts

from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.generic import calculate_last_activity

if TYPE_CHECKING:
    from datetime import datetime


class GenericPlugin(Plugin):
    """Generic plugin for Android targets."""

    def check_compatible(self) -> None:
        pass

    @export(property=True)
    def activity(self) -> datetime | None:
        """Return last seen activity based on filesystem timestamps."""
        for dir in (
            "/dev/log",  # legacy Android
            "/data/system/dropbox",
        ):
            if (path := self.target.fs.path(dir)).is_dir():
                return calculate_last_activity(self.target.fs.path(path), recursive=True)
        return None

    @export(property=True)
    def install_date(self) -> datetime | None:
        """Return the likely install date of the operating system."""
        for path in (
            "/data/data/com.google.android.setupwizard/shared_prefs/SetupWizardPrefs.xml",
            "/data/data/com.google.android.setupwizard/shared_prefs/SetupWizardCredentialProtectedPrefs.xml",
        ):
            if (file := self.target.fs.path(path)).exists():
                return ts.from_unix(file.lstat().st_mtime)
        return None
