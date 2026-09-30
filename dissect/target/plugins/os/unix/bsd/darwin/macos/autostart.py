from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


# ── Record Descriptors ───────────────────────────────────────────────────

LaunchItemRecord = TargetRecordDescriptor(
    "macos/autostart/launchitem",
    [
        ("string", "label"),
        ("string", "program"),
        ("string", "program_arguments"),
        ("boolean", "run_at_load"),
        ("boolean", "keep_alive"),
        ("boolean", "disabled"),
        ("string", "user_name"),
        ("string", "group_name"),
        ("string", "start_interval"),
        ("string", "item_type"),
        ("string", "item_location"),
        ("path", "source"),
    ],
)

SystemExtensionRecord = TargetRecordDescriptor(
    "macos/autostart/system_extension",
    [
        ("string", "identifier"),
        ("string", "team_id"),
        ("string", "version"),
        ("string", "bundle_version"),
        ("string", "state"),
        ("string", "category"),
        ("string", "container_app"),
        ("string", "origin_path"),
        ("string", "unique_id"),
        ("path", "source"),
    ],
)

KernelExtensionRecord = TargetRecordDescriptor(
    "macos/autostart/kernel_extension",
    [
        ("string", "name"),
        ("string", "bundle_identifier"),
        ("string", "version"),
        ("string", "executable"),
        ("string", "info_string"),
        ("path", "source"),
    ],
)

CronJobRecord = TargetRecordDescriptor(
    "macos/autostart/cronjob",
    [
        ("string", "schedule"),
        ("string", "command"),
        ("string", "cron_user"),
        ("path", "source"),
    ],
)

PeriodicRecord = TargetRecordDescriptor(
    "macos/autostart/periodic",
    [
        ("string", "script_name"),
        ("string", "period"),
        ("path", "source"),
    ],
)

StartupItemRecord = TargetRecordDescriptor(
    "macos/autostart/startup_item",
    [
        ("string", "name"),
        ("string", "item_location"),
        ("string", "provides"),
        ("string", "requires"),
        ("string", "order_preference"),
        ("path", "source"),
    ],
)

StartupFileRecord = TargetRecordDescriptor(
    "macos/autostart/startup_file",
    [
        ("string", "filename"),
        ("string", "content"),
        ("path", "source"),
    ],
)


class MacOSAutostartPlugin(Plugin):
    """Plugin to parse macOS autostart/persistence mechanisms.

    Parses:
    - Launch Agents (user + system + Apple)
    - Launch Daemons (system + Apple)
    - Startup Items (legacy)
    - System Extensions
    - Kernel Extensions
    - Cron jobs
    - Periodic scripts
    - /private/etc/launchd.conf
    - /private/etc/rc.common
    """

    __namespace__ = "autostart"

    LAUNCH_AGENT_GLOBS = [
        "Users/*/Library/LaunchAgents/*.plist",
        "Library/LaunchAgents/*.plist",
        "System/Library/LaunchAgents/*.plist",
    ]

    LAUNCH_DAEMON_GLOBS = [
        "Library/LaunchDaemons/*.plist",
        "System/Library/LaunchDaemons/*.plist",
    ]

    SYSEXT_DB = "Library/SystemExtensions/db.plist"

    KEXT_GLOBS = [
        "Library/Extensions/*/Contents/Info.plist",
        "System/Library/Extensions/*/Contents/Info.plist",
    ]

    CRON_GLOBS = [
        "var/at/tabs/*",
        "private/var/at/tabs/*",
        "etc/crontab",
    ]

    STARTUP_ITEM_GLOBS = [
        "Library/StartupItems/*/StartupParameters.plist",
        "System/Library/StartupItems/*/StartupParameters.plist",
    ]

    STARTUP_FILES = [
        "private/etc/launchd.conf",
        "private/etc/rc.common",
        "etc/launchd.conf",
        "etc/rc.common",
    ]

    PERIODIC_GLOBS = [
        "etc/periodic/daily/*",
        "etc/periodic/weekly/*",
        "etc/periodic/monthly/*",
        "private/etc/periodic/daily/*",
        "private/etc/periodic/weekly/*",
        "private/etc/periodic/monthly/*",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._launch_agent_plists = []
        for pattern in self.LAUNCH_AGENT_GLOBS:
            self._launch_agent_plists.extend(self.target.fs.path("/").glob(pattern))

        self._launch_daemon_plists = []
        for pattern in self.LAUNCH_DAEMON_GLOBS:
            self._launch_daemon_plists.extend(self.target.fs.path("/").glob(pattern))

        self._kext_plists = []
        for pattern in self.KEXT_GLOBS:
            self._kext_plists.extend(self.target.fs.path("/").glob(pattern))

    def check_compatible(self) -> None:
        if not self._launch_agent_plists and not self._launch_daemon_plists:
            raise UnsupportedPluginError("No autostart items found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _classify_location(self, path_str):
        if "/Users/" in path_str:
            return "user"
        if "/System/Library/" in path_str:
            return "apple"
        return "system"

    def _parse_launch_plist(self, plist_path, item_type):
        data = self._read_plist(plist_path)
        if data is None:
            return None

        program = data.get("Program", "")
        prog_args = data.get("ProgramArguments", [])
        if not program and prog_args:
            program = prog_args[0] if prog_args else ""
        prog_args_str = " ".join(str(a) for a in prog_args) if prog_args else ""

        keep_alive = data.get("KeepAlive", False)
        if isinstance(keep_alive, dict):
            keep_alive = True

        start_interval = data.get("StartInterval", "")
        start_calendar = data.get("StartCalendarInterval", "")
        if start_calendar and not start_interval:
            start_interval = str(start_calendar)

        location = self._classify_location(str(plist_path))

        return LaunchItemRecord(
            label=data.get("Label", ""),
            program=program,
            program_arguments=prog_args_str,
            run_at_load=bool(data.get("RunAtLoad", False)),
            keep_alive=bool(keep_alive),
            disabled=bool(data.get("Disabled", False)),
            user_name=data.get("UserName", ""),
            group_name=data.get("GroupName", ""),
            start_interval=str(start_interval),
            item_type=item_type,
            item_location=location,
            source=plist_path,
            _target=self.target,
        )

    # ── Launch Agents ────────────────────────────────────────────────────

    @export(record=LaunchItemRecord)
    def launch_agents(self) -> Iterator[LaunchItemRecord]:
        """Parse Launch Agents (user, system, and Apple)."""
        for plist_path in sorted(self._launch_agent_plists):
            try:
                record = self._parse_launch_plist(plist_path, "launch_agent")
                if record:
                    yield record
            except Exception as e:
                self.target.log.warning("Error parsing launch agent %s: %s", plist_path, e)

    # ── Launch Daemons ───────────────────────────────────────────────────

    @export(record=LaunchItemRecord)
    def launch_daemons(self) -> Iterator[LaunchItemRecord]:
        """Parse Launch Daemons (system and Apple)."""
        for plist_path in sorted(self._launch_daemon_plists):
            try:
                record = self._parse_launch_plist(plist_path, "launch_daemon")
                if record:
                    yield record
            except Exception as e:
                self.target.log.warning("Error parsing launch daemon %s: %s", plist_path, e)

    # ── All launch items combined ────────────────────────────────────────

    @export(record=LaunchItemRecord)
    def launch_items(self) -> Iterator[LaunchItemRecord]:
        """Parse all Launch Agents and Daemons combined."""
        yield from self.launch_agents()
        yield from self.launch_daemons()

    # ── System Extensions ────────────────────────────────────────────────

    @export(record=SystemExtensionRecord)
    def system_extensions(self) -> Iterator[SystemExtensionRecord]:
        """Parse installed System Extensions from db.plist."""
        db_path = self.target.fs.path(f"/{self.SYSEXT_DB}")
        if not db_path.exists():
            return

        try:
            data = self._read_plist(db_path)
            if not data:
                return

            for ext in data.get("extensions", []):
                bv = ext.get("bundleVersion", {})
                categories = ext.get("categories", [])
                container = ext.get("container", {})

                yield SystemExtensionRecord(
                    identifier=ext.get("identifier", ""),
                    team_id=ext.get("teamID", ""),
                    version=bv.get("CFBundleShortVersionString", ""),
                    bundle_version=bv.get("CFBundleVersion", ""),
                    state=ext.get("state", ""),
                    category=", ".join(categories),
                    container_app=container.get("bundlePath", ""),
                    origin_path=ext.get("originPath", ""),
                    unique_id=ext.get("uniqueID", ""),
                    source=db_path,
                    _target=self.target,
                )
        except Exception as e:
            self.target.log.warning("Error parsing system extensions: %s", e)

    # ── Kernel Extensions ────────────────────────────────────────────────

    @export(record=KernelExtensionRecord)
    def kernel_extensions(self) -> Iterator[KernelExtensionRecord]:
        """Parse installed Kernel Extensions (kexts)."""
        for plist_path in sorted(self._kext_plists):
            try:
                data = self._read_plist(plist_path)
                if not data:
                    continue

                yield KernelExtensionRecord(
                    name=data.get("CFBundleName", ""),
                    bundle_identifier=data.get("CFBundleIdentifier", ""),
                    version=data.get("CFBundleShortVersionString", data.get("CFBundleVersion", "")),
                    executable=data.get("CFBundleExecutable", ""),
                    info_string=data.get("CFBundleGetInfoString", ""),
                    source=plist_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error parsing kext %s: %s", plist_path, e)

    # ── Cron Jobs ────────────────────────────────────────────────────────

    @export(record=CronJobRecord)
    def cronjobs(self) -> Iterator[CronJobRecord]:
        """Parse cron jobs from /var/at/tabs/ and /etc/crontab."""
        for pattern in self.CRON_GLOBS:
            for cron_path in self.target.fs.path("/").glob(pattern):
                if not cron_path.is_file():
                    continue
                try:
                    cron_user = cron_path.name if "tabs" in str(cron_path) else "system"
                    yield from self._parse_crontab(cron_path, cron_user)
                except Exception as e:
                    self.target.log.warning("Error parsing crontab %s: %s", cron_path, e)

    def _parse_crontab(self, path, cron_user):
        try:
            with path.open("rb") as fh:
                text = fh.read().decode("utf-8", errors="replace")
        except Exception:
            return

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                schedule = " ".join(parts[:5])
                command = parts[5]
            else:
                schedule = ""
                command = line

            yield CronJobRecord(
                schedule=schedule,
                command=command,
                cron_user=cron_user,
                source=path,
                _target=self.target,
            )

    # ── Periodic Scripts ─────────────────────────────────────────────────

    @export(record=PeriodicRecord)
    def periodic(self) -> Iterator[PeriodicRecord]:
        """Parse periodic scripts (daily/weekly/monthly)."""
        for pattern in self.PERIODIC_GLOBS:
            for script_path in self.target.fs.path("/").glob(pattern):
                if not script_path.is_file():
                    continue

                # Derive period from path
                path_str = str(script_path)
                if "/daily/" in path_str:
                    period = "daily"
                elif "/weekly/" in path_str:
                    period = "weekly"
                elif "/monthly/" in path_str:
                    period = "monthly"
                else:
                    period = "unknown"

                yield PeriodicRecord(
                    script_name=script_path.name,
                    period=period,
                    source=script_path,
                    _target=self.target,
                )

    # ── Startup Items (legacy) ───────────────────────────────────────────

    @export(record=StartupItemRecord)
    def startup_items(self) -> Iterator[StartupItemRecord]:
        """Parse legacy StartupItems from /Library/StartupItems/ and /System/Library/StartupItems/."""
        for pattern in self.STARTUP_ITEM_GLOBS:
            for plist_path in self.target.fs.path("/").glob(pattern):
                try:
                    data = self._read_plist(plist_path)
                    if not data:
                        continue

                    location = self._classify_location(str(plist_path))
                    provides = data.get("Provides", [])
                    requires = data.get("Requires", [])
                    order = data.get("OrderPreference", "")

                    yield StartupItemRecord(
                        name=data.get("Description", provides[0] if provides else ""),
                        item_location=location,
                        provides=", ".join(provides) if isinstance(provides, list) else str(provides),
                        requires=", ".join(requires) if isinstance(requires, list) else str(requires),
                        order_preference=str(order),
                        source=plist_path,
                        _target=self.target,
                    )
                except Exception as e:
                    self.target.log.warning("Error parsing startup item %s: %s", plist_path, e)

    # ── Startup config files (launchd.conf, rc.common) ───────────────────

    @export(record=StartupFileRecord)
    def startup_files(self) -> Iterator[StartupFileRecord]:
        """Parse /private/etc/launchd.conf and /private/etc/rc.common."""
        seen = set()
        for rel_path in self.STARTUP_FILES:
            path = self.target.fs.path(f"/{rel_path}")
            if not path.exists():
                continue
            # Avoid duplicates from symlinks (/etc -> /private/etc)
            str(path)
            if path.name in seen:
                continue
            seen.add(path.name)

            try:
                with path.open("rb") as fh:
                    content = fh.read().decode("utf-8", errors="replace")

                yield StartupFileRecord(
                    filename=path.name,
                    content=content,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading %s: %s", path, e)
