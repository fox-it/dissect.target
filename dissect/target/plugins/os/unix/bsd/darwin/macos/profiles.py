from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


ProfileRecord = TargetRecordDescriptor(
    "macos/profiles/installed",
    [
        ("datetime", "ts_install"),
        ("string", "display_name"),
        ("string", "identifier"),
        ("string", "organization"),
        ("string", "description"),
        ("string", "profile_type"),
        ("string", "uuid"),
        ("boolean", "is_encrypted"),
        ("boolean", "has_removal_passcode"),
        ("boolean", "is_managed"),
        ("varint", "payload_count"),
        ("path", "source"),
    ],
)

ProfilePayloadRecord = TargetRecordDescriptor(
    "macos/profiles/payloads",
    [
        ("string", "profile_identifier"),
        ("string", "payload_type"),
        ("string", "payload_identifier"),
        ("string", "payload_display_name"),
        ("string", "payload_organization"),
        ("string", "payload_uuid"),
        ("varint", "payload_version"),
        ("path", "source"),
    ],
)

ProfileSettingRecord = TargetRecordDescriptor(
    "macos/profiles/settings",
    [
        ("string", "filename"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class ProfilesPlugin(Plugin):
    """Plugin to parse macOS Configuration Profiles and MDM settings.

    Parses installed configuration profiles, MDM enrollment, and managed
    preferences from:
    - /private/var/db/ConfigurationProfiles/Settings/*.plist
    - /private/var/db/ConfigurationProfiles/Store/*.plist
    - /private/var/db/ConfigurationProfiles/Setup/*.plist
    - /Library/Managed Preferences/*.plist
    - ~/Library/ConfigurationProfiles/*.plist
    - ~/Library/ManagedPreferences/*.plist

    On managed/enterprise machines this reveals MDM enrollment, installed
    profiles, restrictions, VPN configs, Wi-Fi configs, and more.
    """

    __namespace__ = "profiles"

    PROFILE_GLOBS = [
        "private/var/db/ConfigurationProfiles/Settings/*.plist",
        "private/var/db/ConfigurationProfiles/Store/*.plist",
        "private/var/db/ConfigurationProfiles/Setup/*.plist",
        "Library/Managed Preferences/*.plist",
        "Library/Managed Preferences/*/*.plist",
        "Users/*/Library/ConfigurationProfiles/*.plist",
        "Users/*/Library/ManagedPreferences/*.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._paths = []
        root = self.target.fs.path("/")
        for pattern in self.PROFILE_GLOBS:
            self._paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No configuration profiles found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _ts(self, value):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value
        return datetime(1970, 1, 1, tzinfo=timezone.utc)

    @export(record=ProfileRecord)
    def installed(self) -> Iterator[ProfileRecord]:
        """Parse installed configuration profiles."""
        for path in self._paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                # Handle single profile plist
                profiles = []
                if isinstance(data, dict):
                    if "PayloadIdentifier" in data:
                        profiles.append(data)
                    # Handle profile store format (dict of profiles)
                    elif any(isinstance(v, dict) and "PayloadIdentifier" in v for v in data.values()):
                        profiles.extend(v for v in data.values() if isinstance(v, dict) and "PayloadIdentifier" in v)
                    # Handle array format
                elif isinstance(data, list):
                    profiles.extend(p for p in data if isinstance(p, dict) and "PayloadIdentifier" in p)

                for profile in profiles:
                    payloads = profile.get("PayloadContent", [])

                    yield ProfileRecord(
                        ts_install=self._ts(profile.get("InstallDate")),
                        display_name=profile.get("PayloadDisplayName", ""),
                        identifier=profile.get("PayloadIdentifier", ""),
                        organization=profile.get("PayloadOrganization", ""),
                        description=profile.get("PayloadDescription", ""),
                        profile_type=profile.get("PayloadType", ""),
                        uuid=profile.get("PayloadUUID", ""),
                        is_encrypted=profile.get("IsEncrypted", False),
                        has_removal_passcode=profile.get("HasRemovalPasscode", False),
                        is_managed=profile.get("IsManaged", False),
                        payload_count=len(payloads) if isinstance(payloads, list) else 0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing profile %s: %s", path, e)

    @export(record=ProfilePayloadRecord)
    def payloads(self) -> Iterator[ProfilePayloadRecord]:
        """Parse individual payloads from installed configuration profiles."""
        for path in self._paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                profiles = []
                if isinstance(data, dict):
                    if "PayloadIdentifier" in data:
                        profiles.append(data)
                    elif any(isinstance(v, dict) and "PayloadIdentifier" in v for v in data.values()):
                        profiles.extend(v for v in data.values() if isinstance(v, dict) and "PayloadIdentifier" in v)
                elif isinstance(data, list):
                    profiles.extend(p for p in data if isinstance(p, dict) and "PayloadIdentifier" in p)

                for profile in profiles:
                    profile_id = profile.get("PayloadIdentifier", "")
                    payloads = profile.get("PayloadContent", [])
                    if not isinstance(payloads, list):
                        continue

                    for payload in payloads:
                        if not isinstance(payload, dict):
                            continue

                        yield ProfilePayloadRecord(
                            profile_identifier=profile_id,
                            payload_type=payload.get("PayloadType", ""),
                            payload_identifier=payload.get("PayloadIdentifier", ""),
                            payload_display_name=payload.get("PayloadDisplayName", ""),
                            payload_organization=payload.get("PayloadOrganization", ""),
                            payload_uuid=payload.get("PayloadUUID", ""),
                            payload_version=payload.get("PayloadVersion", 0),
                            source=path,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing profile payloads %s: %s", path, e)

    @export(record=ProfileSettingRecord)
    def settings(self) -> Iterator[ProfileSettingRecord]:
        """Parse configuration profile settings plists (key-value pairs)."""
        for path in self._paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                # Skip profile plists (handled by installed/payloads)
                if isinstance(data, dict) and "PayloadIdentifier" in data:
                    continue

                if not isinstance(data, dict):
                    continue

                filename = str(path).rsplit("/", 1)[-1]

                def _flatten(obj, prefix=""):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            key = f"{prefix}.{k}" if prefix else k
                            if isinstance(v, (dict, list)):
                                yield from _flatten(v, key)
                            else:
                                yield key, str(v) if v is not None else ""
                    elif isinstance(obj, list):
                        for i, v in enumerate(obj):
                            key = f"{prefix}[{i}]"
                            if isinstance(v, (dict, list)):
                                yield from _flatten(v, key)
                            else:
                                yield key, str(v) if v is not None else ""

                for key, value in _flatten(data):
                    yield ProfileSettingRecord(
                        filename=filename,
                        key=key,
                        value=value,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing profile settings %s: %s", path, e)
