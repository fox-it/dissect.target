from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


PfRuleRecord = TargetRecordDescriptor(
    "macos/firewall/pf_rules",
    [
        ("string", "rule"),
        ("string", "rule_type"),
        ("path", "source"),
    ],
)

AlfConfigRecord = TargetRecordDescriptor(
    "macos/firewall/alf_config",
    [
        ("string", "setting"),
        ("string", "value"),
        ("path", "source"),
    ],
)

AlfExceptionRecord = TargetRecordDescriptor(
    "macos/firewall/alf_exceptions",
    [
        ("string", "entry_type"),
        ("string", "path"),
        ("string", "bundle_id"),
        ("varint", "state"),
        ("path", "source"),
    ],
)

AlfServiceRecord = TargetRecordDescriptor(
    "macos/firewall/alf_services",
    [
        ("string", "service_name"),
        ("string", "process"),
        ("string", "bundle_id"),
        ("varint", "state"),
        ("path", "source"),
    ],
)

AlfAppRecord = TargetRecordDescriptor(
    "macos/firewall/alf_apps",
    [
        ("string", "bundle_id"),
        ("string", "path"),
        ("varint", "state"),
        ("path", "source"),
    ],
)


class MacOSFirewallPlugin(Plugin):
    """Plugin to parse macOS firewall configuration.

    Parses:
    - /etc/pf.conf — PF packet filter ruleset
    - /etc/pf.anchors/* — PF anchor rules (AirDrop, Application Firewall)
    - ALF (Application Level Firewall) plist — app exceptions, services,
      explicit authorizations, and global firewall state

    ALF plist locations:
    - /usr/libexec/ApplicationFirewall/com.apple.alf.plist (default)
    - /Library/Preferences/com.apple.alf.plist (user-modified)
    """

    __namespace__ = "firewall"

    PF_CONF_PATHS = [
        "etc/pf.conf",
        "private/etc/pf.conf",
    ]

    PF_ANCHOR_GLOBS = [
        "etc/pf.anchors/*",
        "private/etc/pf.anchors/*",
    ]

    ALF_PATHS = [
        "Library/Preferences/com.apple.alf.plist",
        "usr/libexec/ApplicationFirewall/com.apple.alf.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._pf_conf_paths = []
        self._pf_anchor_paths = []
        self._alf_paths = []

        root = self.target.fs.path("/")

        for p in self.PF_CONF_PATHS:
            path = root.joinpath(p)
            if path.exists():
                self._pf_conf_paths.append(path)

        for pattern in self.PF_ANCHOR_GLOBS:
            self._pf_anchor_paths.extend(root.glob(pattern))

        for p in self.ALF_PATHS:
            path = root.joinpath(p)
            if path.exists():
                self._alf_paths.append(path)

    def check_compatible(self) -> None:
        if not self._pf_conf_paths and not self._alf_paths:
            raise UnsupportedPluginError("No firewall configuration found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    # ── PF Rules ─────────────────────────────────────────────────────────

    @export(record=PfRuleRecord)
    def pf_rules(self) -> Iterator[PfRuleRecord]:
        """Parse PF packet filter rules from /etc/pf.conf and anchors."""
        for path in self._pf_conf_paths + self._pf_anchor_paths:
            try:
                with path.open("r") as fh:
                    content = fh.read()

                for line in content.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue

                    # Classify rule type
                    rule_type = "unknown"
                    first_word = stripped.split()[0] if stripped.split() else ""
                    if first_word in ("pass", "block"):
                        rule_type = first_word
                    elif first_word == "scrub-anchor":
                        rule_type = "scrub_anchor"
                    elif first_word == "nat-anchor":
                        rule_type = "nat_anchor"
                    elif first_word == "rdr-anchor":
                        rule_type = "rdr_anchor"
                    elif first_word == "dummynet-anchor":
                        rule_type = "dummynet_anchor"
                    elif first_word == "anchor":
                        rule_type = "anchor"
                    elif first_word == "load":
                        rule_type = "load"
                    elif first_word == "scrub":
                        rule_type = "scrub"
                    elif first_word == "nat":
                        rule_type = "nat"
                    elif first_word == "rdr":
                        rule_type = "rdr"
                    elif first_word == "table":
                        rule_type = "table"
                    elif first_word == "set":
                        rule_type = "set"

                    yield PfRuleRecord(
                        rule=stripped,
                        rule_type=rule_type,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)

    # ── ALF Config ───────────────────────────────────────────────────────

    @export(record=AlfConfigRecord)
    def alf_config(self) -> Iterator[AlfConfigRecord]:
        """Parse ALF (Application Level Firewall) global configuration."""
        for path in self._alf_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                settings = {
                    "globalstate": "Global firewall state (0=off, 1=on, 2=block all)",
                    "stealthenabled": "Stealth mode",
                    "loggingenabled": "Logging enabled",
                    "loggingoption": "Logging option",
                    "firewallunload": "Firewall unloaded",
                    "allowsignedenabled": "Allow signed apps",
                    "allowdownloadsignedenabled": "Allow downloaded signed apps",
                    "version": "ALF version",
                }

                for key, _description in settings.items():
                    if key in data:
                        yield AlfConfigRecord(
                            setting=key,
                            value=str(data[key]),
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing ALF config %s: %s", path, e)

    # ── ALF Exceptions ───────────────────────────────────────────────────

    @export(record=AlfExceptionRecord)
    def alf_exceptions(self) -> Iterator[AlfExceptionRecord]:
        """Parse ALF firewall exceptions and explicit authorizations."""
        for path in self._alf_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                for exc in data.get("exceptions", []):
                    yield AlfExceptionRecord(
                        entry_type="exception",
                        path=exc.get("path", ""),
                        bundle_id=exc.get("bundleid", ""),
                        state=exc.get("state", 0),
                        source=path,
                        _target=self.target,
                    )

                for auth in data.get("explicitauths", []):
                    yield AlfExceptionRecord(
                        entry_type="explicit_auth",
                        path="",
                        bundle_id=auth.get("id", ""),
                        state=0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ALF exceptions %s: %s", path, e)

    # ── ALF Services ─────────────────────────────────────────────────────

    @export(record=AlfServiceRecord)
    def alf_services(self) -> Iterator[AlfServiceRecord]:
        """Parse ALF firewall service rules (SSH, file sharing, screen sharing, etc.)."""
        for path in self._alf_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                firewall = data.get("firewall", {})
                for service_name, info in firewall.items():
                    yield AlfServiceRecord(
                        service_name=service_name,
                        process=info.get("proc", ""),
                        bundle_id=info.get("servicebundleid", ""),
                        state=info.get("state", 0),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ALF services %s: %s", path, e)

    # ── ALF Apps ─────────────────────────────────────────────────────────

    @export(record=AlfAppRecord)
    def alf_apps(self) -> Iterator[AlfAppRecord]:
        """Parse ALF per-application firewall rules."""
        for path in self._alf_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                for app in data.get("applications", []):
                    yield AlfAppRecord(
                        bundle_id=app.get("bundleid", ""),
                        path=app.get("path", ""),
                        state=app.get("state", 0),
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing ALF apps %s: %s", path, e)
