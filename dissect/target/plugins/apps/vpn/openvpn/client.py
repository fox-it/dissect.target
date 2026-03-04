from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.certificate import (
    COMMON_CERTIFICATE_FIELDS,
    parse_x509,
)
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.vpn.openvpn.openvpn import OpenVPNPlugin
from dissect.target.plugins.apps.vpn.openvpn.util import OpenVPNParser, parse_config

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


OpenVPNLogRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/client/log",
    [
        ("datetime", "ts"),
        ("string", "message"),
        ("path", "source"),
    ],
)

OpenVPNProfileRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/client/profile",
    [
        ("datetime", "ts"),
        ("string", "proto"),
        ("string", "dev"),
        ("string[]", "remote"),
        ("string", "ca"),
        ("string", "cert"),
        ("string", "key"),
        ("string", "auth"),
        ("string", "status"),
        ("string", "log"),
        ("string", "verb"),
        ("string", "tls_auth"),
        ("path", "source"),
    ],
)

OpenVPNCertificateRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/client/profile/certificate",
    [
        ("datetime", "ts"),
        *COMMON_CERTIFICATE_FIELDS,
        ("path", "source"),
    ],
)

OpenVPNConfigProxyRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/client/config/proxy",
    [
        ("datetime", "ts"),
        ("string", "proxy_id"),
        ("string", "display_name"),
        ("net.ipaddress", "host"),
        ("uint16", "port"),
        ("string", "username"),
        ("string", "password"),
        ("path", "source"),
    ],
)

OpenVPNConfigProfileRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/client/config/profile",
    [
        ("datetime", "ts"),
        ("string", "profile_id"),
        ("string", "display_name"),
        ("net.ipaddress", "host"),
        ("path", "file_path"),
        ("datetime", "last_connected"),
        ("string", "saved_password"),
        ("string", "private_key_password"),
        ("path", "source"),
    ],
)

RE_LOG_MESSAGE = re.compile(r"^(?P<normal_ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\+\d{4})?)\s*(?P<message>.+)")


class OpenVPNClientPlugin(OpenVPNPlugin):
    """OpenVPN client plugin.

    Tested on Windows OpenVPN GUI v11.56.0.0, Windows OpenVPN Connect Client v3.8.0 and macOS OpenVPN Connect v3.

    Linux OpenVPN clients store logs in the journal or syslog.

    References:
        - https://support.openvpn.com/hc/en-us/articles/35154796757275-CloudConnexa-Where-to-Find-OpenVPN-Client-Logs
        - https://codeberg.org/OpenVPN/openvpn3-linux#logging
    """

    __namespace__ = "openvpn.client"

    DEFAULT_SYSTEM_PATHS = (
        # Windows
        "/sysvol/Program Files/OpenVPN",
        # macOS
        "/Library/Application Support/OpenVPN Connect",
    )
    DEFAULT_USER_PATHS = (
        # Windows
        "OpenVPN",
        "AppData/Roaming/OpenVPN Connect",
        # macOS
        "Library/Application Support/OpenVPN Connect",
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.log_files = list(self._find_log_files())
        self.profile_files = list(self._find_profile_files())
        self.config_files = list(self._find_config_files())

    def _find_log_files(self) -> Iterator[Path]:
        """Search user home folders and system paths for OpenVPN log files."""

        for user_details in self.target.user_details.all_with_home():
            home_dir = user_details.home_path

            for openvpn_path in self.DEFAULT_USER_PATHS:
                if (install_path := home_dir.joinpath(openvpn_path)).is_dir():
                    yield from install_path.rglob("*.log")

        for system_path in self.DEFAULT_SYSTEM_PATHS:
            if (log_path := self.target.fs.path(system_path)).is_dir():
                yield from log_path.rglob("*.log")

    def _find_profile_files(self) -> Iterator[Path]:
        """Search user home folders and system paths for connection profile files."""

        for user_details in self.target.user_details.all_with_home():
            home_dir = user_details.home_path

            for openvpn_path in self.DEFAULT_USER_PATHS:
                if (install_path := home_dir.joinpath(openvpn_path)).is_dir():
                    yield from install_path.rglob("*.ovpn")

        for openvpn_path in self.DEFAULT_SYSTEM_PATHS:
            if (install_path := self.target.fs.path(openvpn_path)).is_dir():
                yield from install_path.rglob("*.ovpn")

    def _find_config_files(self) -> Iterator[Path]:
        """Searches user home folders for OpenVPN Connect client config files."""

        for user_details in self.target.user_details.all_with_home():
            home_dir = user_details.home_path

            for openvpn_path in self.DEFAULT_USER_PATHS:
                if (install_path := home_dir.joinpath(openvpn_path)).is_dir():
                    yield from install_path.rglob("*.json")

    def check_compatible(self) -> None:
        if not any([self.log_files, self.profile_files, self.config_files]):
            raise UnsupportedPluginError("No OpenVPN Client file(s) found on target")

    @export(record=OpenVPNLogRecord)
    def logs(self) -> Iterator[OpenVPNLogRecord]:
        """Parses full log files from OpenVPN installs"""

        for log_file in self.log_files:
            for line in open_decompress(log_file, "rt"):
                if not (line := line.strip()):
                    continue

                if not (match := RE_LOG_MESSAGE.search(line)):
                    self.target.log.warning("Unable to match OpenVPN log line in %s: %r", log_file, line)
                    continue

                group = match.groupdict()
                ts = (
                    datetime.strptime(group["normal_ts"], "%Y-%m-%d %H:%M:%S")
                    .replace(tzinfo=self.target.datetime.tzinfo)
                    .astimezone(timezone.utc)
                )

                yield OpenVPNLogRecord(
                    ts=ts,
                    message=group["message"],
                    source=log_file,
                    _target=self.target,
                )

    @export(record=OpenVPNProfileRecord)
    def profiles(self) -> Iterator[OpenVPNProfileRecord]:
        """Yield OpenVPN client connection profile (*.ovpn) records."""

        parser = OpenVPNParser(boolean_fields={})

        for profile_path in self.profile_files:
            if not (config := parse_config(self.target, parser, profile_path)):
                continue

            yield OpenVPNProfileRecord(
                ts=profile_path.lstat().st_mtime,
                proto=config.get("proto"),
                dev=config.get("dev"),
                remote=config.get("remote"),
                ca=config.get("ca"),
                cert=config.get("cert"),
                key=config.get("key"),
                auth=config.get("auth"),
                status=config.get("status"),
                log=config.get("log"),
                verb=config.get("verb"),
                tls_auth=config.get("tls-auth"),
                source=profile_path,
                _target=self.target,
            )

            # Yield certificate records for each x509 blob in the config
            for cert in config.get("ca"), config.get("cert"), config.get("key"):
                if cert.startswith("-----"):
                    data = cert
                elif (path := profile_path.parent.joinpath(cert)).is_file():
                    data = path.read_text()
                else:
                    self.target.log.warning("Profile %s references invalid certificate: %r", profile_path, cert)
                    continue

                try:
                    crt = parse_x509(data)
                except (ValueError, TypeError) as e:
                    self.target.log.warning("Unable to parse OpenVPN Server certificate in %s: %s", profile_path, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                yield OpenVPNCertificateRecord(
                    ts=crt.not_valid_before,
                    **crt._asdict(),
                    source=profile_path,
                    _target=self.target,
                )

    @export(records=[OpenVPNConfigProxyRecord, OpenVPNConfigProfileRecord])
    def config(self) -> Iterator[OpenVPNConfigProxyRecord, OpenVPNConfigProfileRecord]:
        """Yield Windows OpenVPN Connect client configuration records.

        Currently does not parse embedded certificates in ``config.json``.
        """

        for config_path in self.config_files:
            with config_path.open("rt") as fh:
                try:
                    status_data = json.loads(json.loads(json.loads(fh.read())["persist:root"])["status"])
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    self.target.warning("Failed to parse JSON in file %s: %s", config_path, e)
                    continue

            proxy_list = status_data.get("proxyList", {})
            profile_list = status_data.get("profiles", {})

            for proxy_id, group in proxy_list.items():
                yield OpenVPNConfigProxyRecord(
                    ts=config_path.lstat().st_mtime,
                    proxy_id=proxy_id,
                    display_name=group["displayName"],
                    host=group["hostname"],
                    port=int(group["port"]),
                    username=group["username"],
                    password=group["password"],
                    source=config_path,
                    _target=self.target,
                )

            for profile_id, group in profile_list.items():
                last_connected = datetime.fromtimestamp(
                    (group["lastConnected"] / 1000), self.target.datetime.tzinfo
                ).strftime("%Y-%m-%d %H:%M:%S%z")

                yield OpenVPNConfigProfileRecord(
                    ts=last_connected,
                    profile_id=profile_id,
                    display_name=group["profileDisplayName"],
                    host=group["hostname"],
                    file_path=group["filePath"],
                    last_connected=last_connected,
                    saved_password=group["savedPassword"],
                    private_key_password=group["privateKeyPassword"],
                    source=config_path,
                    _target=self.target,
                )
