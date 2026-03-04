from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.database import SQLite3
from dissect.database.exception import Error as DBError

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.certificate import COMMON_CERTIFICATE_FIELDS, parse_x509
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import arg, export
from dissect.target.plugins.apps.vpn.openvpn.openvpn import OpenVPNPlugin
from dissect.target.plugins.apps.vpn.openvpn.util import OpenVPNParser, parse_config

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


OpenVPNLogRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/server/log",
    [
        ("datetime", "ts"),
        ("string", "message"),
        ("path", "source"),
    ],
)

OpenVPNLiveConnectionRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/server/connection/live",
    [
        ("datetime", "client_conn_since"),
        ("string", "client_common_name"),
        ("net.ipaddress", "client_ip"),
        ("varint", "client_port"),
        ("net.ipaddress[]", "client_vpn_ip"),
        ("string", "client_username"),
        ("string", "client_id"),
        ("string", "peer_id"),
        ("varint", "bytes_received"),
        ("varint", "bytes_sent"),
        ("string", "client_ciphers"),
        ("path", "source"),
    ],
)


OpenVPNHistoryConnectionRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/server/connection/history",
    [
        ("datetime", "ts"),
        ("string", "client_id"),
        ("string", "client_username"),
        ("net.ipaddress", "client_ip"),
        ("varint", "client_port"),
        ("net.ipaddress[]", "client_vpn_ip"),
        ("string", "client_proto"),
        ("string", "client_version"),
        ("string", "client_platform"),
        ("string", "client_plat_rel"),
        ("string", "client_gui_ver"),
        ("string", "client_ciphers"),
        ("string", "client_ssl"),
        ("string", "client_hwaddr"),
        ("uint16", "client_conn_duration"),
        ("path", "source"),
    ],
)

OpenVPNConfigRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/server/config",
    [
        ("datetime", "ts"),
        ("net.ipaddress", "local"),
        ("uint16", "port"),
        ("string", "proto"),
        ("string", "dev"),
        ("string", "ca"),
        ("string", "cert"),
        ("string", "key"),
        ("string", "dh"),
        ("string", "auth"),
        ("string", "topology"),
        ("string", "server"),
        ("string", "ifconfig_pool_persist"),
        ("string[]", "pushed_options"),
        ("boolean", "client_to_client"),
        ("boolean", "duplicate_cn"),
        ("string", "status"),
        ("string", "log"),
        ("string", "verb"),
        ("string", "tls_auth"),
        ("path", "source"),
    ],
)

OpenVPNCertificateRecord = TargetRecordDescriptor(
    "application/vpn/openvpn/server/config/certificate",
    [
        ("datetime", "ts"),
        *COMMON_CERTIFICATE_FIELDS,
        ("path", "source"),
    ],
)

OpenVPNUser = TargetRecordDescriptor(
    "application/vpn/openvpn/server/config/user",
    [
        ("string", "user_id"),
        ("string", "user_name"),
        ("string", "user_type"),
        ("boolean", "is_superuser"),
        ("string", "password_digest"),
        ("string", "user_auth_type"),
        ("path", "source"),
    ],
)

RE_LOG_MESSAGE = re.compile(r"^(?P<normal_ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\+\d{4})?)\s*(?P<message>.+)")
RE_LOG_CONNECTION = re.compile(
    r"^\[stdout#info\] \[OVPN (?P<connection_id>\d+)\] OUT: '(?P<acces_server_ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+) peer info: (?P<key>[A-Z_]+)=(?P<value>\S+)'$"
)


class OpenVPNServerPlugin(OpenVPNPlugin):
    """OpenVPN Server (Linux) plugin.

    Supports OpenVPN Server v2 and OpenVPN Access Server (AS) artifacts. Tested with OpenVPN Server v2.6.14
    and OpenVPN Access Server v3.0.1 on Linux. Does not parse OpenVPN Server v2 and v3 logs as those
    are saved in the Linux journal or syslog.

    Does not parse custom ``log`` or ``log-append`` directives (yet).

    References:
        - https://openvpn.net/vpn-server-resources/logging-and-debug-flag-options-for-%20access-server/
        - https://openvpn.net/as-docs/tutorials/tutorial--syslog.html
    """

    __namespace__ = "openvpn.server"

    def __init__(self, target: Target):
        super().__init__(target)

        self.DEFAULT_LOG_GLOBS = [
            # OpenVPN Server
            "/var/log/openvpn.log*",
            "/sysvol/Program files/OpenVPN/log/*.log",
            # OpenVPN Access Server
            "/var/log/openvpnas.log*",
            "/var/log/openvpnas.node.log",
            # OpenVPN Server v2
            "/etc/openvpn/server/openvpn.log",
        ]

        self.DEFAULT_CONFIG_GLOBS = [
            # OpenVPN Server
            "/etc/openvpn/server.conf",
            "/etc/openvpn/server/server.conf",
            "/sysvol/Program Files/OpenVPN/config/*.conf",
            # OpenVPN Access Server
            "/usr/local/openvpn_as/etc/as.conf",
        ]

        self.DEFAULT_STATUS_PATHS = [
            "/run/openvpn-server/status-server.log",
            "/var/log/openvpn/status.log",
            "/etc/openvpn/openvpn-status.log",
            "/var/log/openvpn/openvpn-status.log",
        ]

        self.DEFAULT_CONNECTION_DB_PATHS = [
            "/usr/local/openvpn_as/etc/db/log.db",
        ]

        self.DEFAULT_USERS_DB_PATHS = [
            "/usr/local/openvpn_as/etc/db/userprop.db",
            "/usr/local/openvpn_as/etc/db/cluster.db",
        ]

        self.config_files = list(self._find_config_files())
        self.log_files = list(self._find_logs_files())
        self.user_db_files = list(self._find_user_db_files())
        self.connection_db_files = list(self._find_connection_db_files())
        self.status_files = list(self._find_status_files())

    def _find_config_files(self) -> Iterator[Path]:
        """Find configuration files for OpenVPN installs."""
        seen = set()

        for config_path in self.DEFAULT_CONFIG_GLOBS:
            if "*" in config_path:
                base, _, glob = config_path.rpartition("/")
                for path in self.target.fs.path(base).glob(glob):
                    if path not in seen:
                        seen.add(path)
                        yield path

            elif (path := self.target.fs.path(config_path)).is_file() and path not in seen:
                seen.add(path)
                yield path

    def _find_logs_files(self) -> Iterator[Path]:
        """Find log paths for OpenVPN installs"""
        seen = set()

        for log in self.DEFAULT_LOG_GLOBS:
            if "*" in log:
                base, _, glob = log.rpartition("/")
                for path in self.target.fs.path(base).glob(glob):
                    if path not in seen:
                        seen.add(path)
                        yield path
            elif (path := self.target.fs.path(log)).is_file() and path not in seen:
                seen.add(path)
                yield path

    def _find_user_db_files(self) -> Iterator[Path]:
        """Find database paths for OpenVPN installs."""
        for db in self.DEFAULT_USERS_DB_PATHS:
            if (db_path := self.target.fs.path(db)).is_file():
                yield db_path

    def _find_connection_db_files(self) -> Iterator[Path]:
        """Find database paths for OpenVPN installs."""
        for db in self.DEFAULT_CONNECTION_DB_PATHS:
            if (db_path := self.target.fs.path(db)).is_file():
                yield db_path

    def _find_status_files(self) -> Iterator[Path]:
        """Find OpenVPN server status files."""
        for file in self.DEFAULT_STATUS_PATHS:
            if (path := self.target.fs.path(file)).is_file():
                yield path

    def check_compatible(self) -> None:
        if not any([self.config_files, self.log_files, self.user_db_files, self.connection_db_files]):
            raise UnsupportedPluginError("No OpenVPN Server install found on target")

    @export(record=[OpenVPNConfigRecord, OpenVPNCertificateRecord])
    @arg("--export-key", action="store_true", help="export private keys to records")
    def config(self, export_key: bool = False) -> Iterator[OpenVPNConfigRecord, OpenVPNCertificateRecord]:
        """Yield OpenVPN server configuration records."""

        parser = OpenVPNParser(boolean_fields=OpenVPNConfigRecord.getfields("boolean"))

        for config_path in self.config_files:
            if not (config := parse_config(self.target, parser, config_path)):
                continue

            # Infers default values from openvpn man page (8)
            yield OpenVPNConfigRecord(
                ts=config_path.lstat().st_mtime,
                local=config.get("local", "0.0.0.0"),
                port=int(config.get("port", "1194")),
                proto=config.get("proto"),
                dev=config.get("dev"),
                ca=config.get("ca"),
                cert=config.get("cert"),
                key=config.get("key") if export_key else None,
                dh=config.get("dh"),
                auth=config.get("auth"),
                topology=config.get("topology"),
                server=config.get("server"),
                ifconfig_pool_persist=config.get("ifconfig-pool-persist"),
                pushed_options=config.get("push"),
                client_to_client=config.get("client-to-client", False),
                duplicate_cn=config.get("duplicate-cn", False),
                status=config.get("status"),
                log=config.get("log"),
                verb=config.get("verb"),
                tls_auth=config.get("tls-auth"),
                source=config_path,
                _target=self.target,
            )

            # Yield certificate records for each x509 blob in the config
            for cert in config.get("ca"), config.get("cert"), config.get("key"):
                try:
                    crt = parse_x509(cert)
                except (ValueError, TypeError) as e:
                    self.target.log.warning("Unable to parse OpenVPN Server certificate in %s: %s", config_path, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                yield OpenVPNCertificateRecord(
                    ts=crt.not_valid_before,
                    **crt._asdict(),
                    source=config_path,
                    _target=self.target,
                )

    @export(record=[OpenVPNLogRecord])
    def logs(self) -> Iterator[OpenVPNLogRecord]:
        """Yields OpenVPN Server logs."""

        for log_file in self.log_files:
            for line in open_decompress(log_file, "rt"):
                if not (line := line.strip()):
                    continue

                if not (match := RE_LOG_MESSAGE.search(line)):
                    self.target.log.warning("Unable to match OpenVPN log line in %s: %r", log_file, line)
                    continue

                group = match.groupdict()
                ts = parse_datetime(group["normal_ts"], self.target.datetime.tzinfo)

                yield OpenVPNLogRecord(
                    ts=ts,
                    message=group["message"],
                    source=log_file,
                    _target=self.target,
                )

    @export(record=OpenVPNUser)
    def users(self) -> Iterator[OpenVPNUser]:
        """Yield configured users from OpenVPN Server databases."""

        for db_path in self.user_db_files:
            try:
                db = SQLite3(db_path)
            except DBError as e:
                self.target.log.warning("Unable to open SQLite3 database %s: %s", db_path, e)
                continue

            # Connect the profile id and name with the user config
            users = {}
            for row in db.table("profile").rows():
                users[row["id"]] = {"username": row["name"], "type": row["type"]}
            for row in db.table("config").rows():
                if row["profile_id"] in users:
                    users[row["profile_id"]][row["name"]] = row["value"]

            for user_id, user_info in users.items():
                yield OpenVPNUser(
                    user_id=user_id,
                    user_name=user_info.get("username"),
                    user_type=user_info.get("type"),
                    is_superuser=user_info.get("prop_superuser") == "true",
                    password_digest=user_info.get("pvt_password_digest"),
                    user_auth_type=user_info.get("user_auth_type"),
                    source=db_path,
                    _target=self.target,
                )

    @export(record=[OpenVPNLiveConnectionRecord, OpenVPNHistoryConnectionRecord])
    def connections(self) -> Iterator[OpenVPNLiveConnectionRecord | OpenVPNHistoryConnectionRecord]:
        """Yield live and historic OpenVPN Server connections with clients."""

        # TODO: Refactor this function.
        yield from self._live_connections()
        yield from self._history_log_connections()
        yield from self._history_db_connections()

    def _live_connections(self) -> Iterator[OpenVPNLiveConnectionRecord]:
        """Yield live connections from OpenVPN status log files."""
        client_list = []

        for status_path in self.status_files:
            for log_file in open_decompress(status_path, "rt"):
                try:
                    parts = log_file.split(",")
                    if parts[0] == "HEADER" and parts[1] == "CLIENT_LIST":
                        headers = parts[2:]
                    elif parts[0] == "CLIENT_LIST":
                        group = dict(zip(headers, parts[1:], strict=True))

                    if group in client_list:
                        continue

                    ts = parse_datetime(group["Connected Since"], self.target.datetime.tzinfo)
                    client_list.append(group)

                except Exception as e:
                    self.target.log.warning("Unable to parse OpenVPN status log: %s with error: %e", status_path, e)
                    continue

            for group in client_list:
                yield OpenVPNLiveConnectionRecord(
                    client_conn_since=ts,
                    client_common_name=group.get("Common Name"),
                    client_ip=group.get("Real Address", "").split(":")[0],
                    client_port=group.get("Real Address", "").split(":")[-1],
                    client_vpn_ip=[ip for f in ("Virtual Address", "Virtual IPv6 Address") if (ip := group.get(f))],
                    client_username=group.get("Username"),
                    client_id=int(group.get("Client ID", 0)),
                    peer_id=int(group.get("Peer ID", 0)),
                    bytes_received=group.get("Bytes Received"),
                    bytes_sent=group.get("Bytes Sent"),
                    client_ciphers=group.get("Data Channel Cipher\n"),
                    source=status_path,
                    _target=self.target,
                )

    def _history_log_connections(self) -> Iterator[OpenVPNHistoryConnectionRecord]:
        """Yields history connection logs from regular logs."""

        connection = {}

        for record in self.logs():
            if not (match := RE_LOG_CONNECTION.search(record.message)):
                continue

            group = match.groupdict()
            ts = parse_datetime(group.get("acces_server_ts", group.get("normal_ts")), self.target.datetime.tzinfo)

            # Save all the meta info from one connection
            if len(connection) == 0:
                connection.update(
                    {
                        "ip": group["ip"],
                        "ts": ts,
                        "port": int(group["port"]),
                        "connection_id": group["connection_id"],
                        group["key"]: group["value"],
                    }
                )
            else:
                connection.update({group["key"]: group["value"]})

                if group["key"] == "IV_SSO":
                    yield OpenVPNHistoryConnectionRecord(
                        ts=connection.get("ts"),
                        client_id=int(connection.get("connection_id", 0)),
                        client_ip=connection.get("ip"),
                        client_port=int(connection.get("port", 0)),
                        client_proto=connection.get("IV_PROTO"),
                        client_version=connection.get("IV_VER"),
                        client_platform=connection.get("IV_PLAT"),
                        client_plat_rel=connection.get("UV_PLAT_REL"),
                        client_gui_ver=connection.get("IV_GUI_VER"),
                        client_ciphers=connection.get("IV_CIPHERS"),
                        client_ssl=connection.get("IV_SSL"),
                        client_hwaddr=connection.get("IV_HWADDR"),
                        source=record.source,
                        _target=self.target,
                    )
                    connection = {}

    def _history_db_connections(self) -> Iterator[OpenVPNHistoryConnectionRecord]:
        """Yields history connection logs from SQLite3 databases."""

        ts_fmt = "%Y-%m-%d %H:%M:%S%z"

        for db_path in self.connection_db_files:
            try:
                db = SQLite3(db_path)
            except DBError as e:
                self.target.log.warning("Unable to open SQLite3 database %s: %s", db_path, e)
                continue

            for row in db.table("log").rows():
                if row.service != "VPN":
                    continue

                yield OpenVPNHistoryConnectionRecord(
                    ts=datetime.fromtimestamp(row["timestamp"], self.target.datetime.tzinfo).strftime(ts_fmt),
                    client_id=row["node"],
                    client_username=row["username"],
                    client_ip=row["real_ip"],
                    client_port=int(row["port"]),
                    client_vpn_ip=[row["vpn_ip"]],
                    client_proto=row["proto"],
                    client_version=row["version"],
                    client_platform=row["platform"],
                    client_gui_ver=row["gui_version"],
                    client_conn_duration=int(row["duration"]),
                    source=db_path,
                    _target=self.target,
                )


def parse_datetime(datetime_str: str, target_tz: timezone) -> datetime:
    """Convert local system datetime from log and status files to UTC datetime objects.

    OpenVPN Server v2 example::
        2025-10-20 19:20:14

    OpenVPN Access Server example::
        2025-10-09T18:45:25+1000
    """

    fmt = "%Y-%m-%dT%H:%M:%S%z" if "T" in datetime_str else "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(datetime_str, fmt).replace(tzinfo=target_tz).astimezone(timezone.utc)
