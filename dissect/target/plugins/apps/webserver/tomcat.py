from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import defusedxml.ElementTree as ET

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.certificate import parse_x509
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugin import export
from dissect.target.plugins.apps.webserver.webserver import (
    LogFormat,
    WebserverAccessLogRecord,
    WebserverCertificateRecord,
    WebserverHostRecord,
    WebserverPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


# '%h %l %u %t "%r" %s %b'
# Reference: https://tomcat.apache.org/tomcat-9.0-doc/config/valve.html#Access_Logging
LOG_FORMAT_ACCESS_DEFAULT = LogFormat(
    "default",
    re.compile(
        r"""
            (?P<remote_ip>.*?)\s-\s(?P<remote_user>.*?)
            \s
            \[(?P<ts>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s(\+|\-)\d{4})\]
            \s
            \"((?P<method>.*?)\s(?P<uri>.*?)\s?(?P<protocol>HTTP\/.*?)|-)?\"
            \s
            (?P<status_code>\d{3})
            \s
            (?P<bytes_sent>-|\d+)
            (
                \s
                (["](?P<referer>(\-)|(.+))["])
                \s
                \"(?P<useragent>.*?)\"
            )?
        """,
        re.VERBOSE,
    ),
    r"%d/%b/%Y:%H:%M:%S %z",
)


class TomcatPlugin(WebserverPlugin):
    """Tomcat webserver plugin.

    References:
        - https://tomcat.apache.org/
    """

    __namespace__ = "tomcat"

    INSTALL_PATHS_SYSTEM = (
        # Windows
        "/sysvol/Program Files/Apache Software Foundation/Tomcat*",
        "/sysvol/Program Files/Tomcat*",
        "/sysvol/XAMPP/Tomcat*",
        # Linux
        "/var/lib/tomcat*",
        "/etc/tomcat*",  # Handles symlinked conf folders (e.g. /var/lib/tomcat10/conf -> /etc/tomcat10)
        "/usr/local/tomcat*",
        "/opt/bitnami/tomcat*",
        "/opt/tomcat*",
    )

    INSTALL_PATHS_USER = (
        # Windows
        "XAMPP/Tomcat*",
    )

    # Relative to install path. Does not parse WEB-INF dirs.
    DEFAULT_CONFIG_FILES = (
        "conf/server.xml",
        "server.xml",  # For symlinked conf folder installs (e.g. /etc/tomcat10)
    )

    DEFAULT_LOG_PATHS = ("/var/log/tomcat*",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.installs = list(self.find_installs())
        self.configs = list(self.find_configs())
        self.log_files = list(self.find_log_files())

    def check_compatible(self) -> None:
        if not self.installs and not self.configs and not self.log_files:
            raise UnsupportedPluginError("No Tomcat installations found on target")

    def find_installs(self) -> Iterator[Path]:
        """Yield found Tomcat installation directories."""
        seen = set()

        for path in self.INSTALL_PATHS_SYSTEM:
            base, _, glob = path.rpartition("/")
            for dir in self.target.fs.path(base).glob(glob):
                if dir.is_dir() and dir not in seen:
                    seen.add(dir)
                    yield dir

        for user_details in self.target.user_details.all_with_home():
            for path in self.INSTALL_PATHS_USER:
                base, _, glob = path.rpartition("/")  # type: ignore
                for dir in user_details.home_path.joinpath(base).glob(glob):
                    if dir.is_dir() and dir not in seen:
                        seen.add(dir)
                        yield dir

    def find_configs(self) -> Iterator[tuple[Path, Path]]:
        """Yield Tomcat configuration files based on found Tomcat install paths.

        Returns:
            Iterator with tuple of the original install path and the configuration file path.
        """
        seen: set[Path] = set()

        for install in self.installs:
            for conf in self.DEFAULT_CONFIG_FILES:
                if (config := install.joinpath(conf)).is_file() and not any(s.samefile(config) for s in seen):
                    seen.add(config)
                    yield install, config

    def parse_config(self, path: Path) -> Iterator[dict]:
        """Parse the given Tomcat configuration file for host information."""
        config = ET.fromstring(path.read_text())

        # Within a Service, a Connector defines the listen port, protocol and TLS.
        # A Connector can contain multiple Hosts.
        for service in config.findall("./Service"):
            tls_cert = None
            tls_key = None
            tls_port = None
            http_port = None

            for connector in service.findall("./Connector"):
                # Collect the TLS settings for all hosts under this Connector. Does not parse java keystore files.
                # https://tomcat.apache.org/tomcat-9.0-doc/ssl-howto.html
                if "SSLCertificateFile" in connector.keys():  # noqa: SIM118
                    tls_cert = connector.get("SSLCertificateFile")
                if "SSLCertificateKeyFile" in connector.keys():  # noqa: SIM118
                    tls_key = connector.get("SSLCertificateKeyFile")

                # Collect the TLS settings for hosts for Tomcat version >= 9
                for certificate in connector.findall("./SSLHostConfig/Certificate"):
                    if "certificateFile" in certificate.keys():  # noqa: SIM118
                        tls_cert = certificate.get("certificateFile")
                    if "certificateKeyFile" in certificate.keys():  # noqa: SIM118
                        tls_key = certificate.get("certificateKeyFile")

                if "port" in connector.keys() and (  # noqa: SIM118
                    any("certificate" in k.lower() for k in connector.keys())  # noqa: SIM118
                    or connector.find("./SSLHostConfig") is not None
                ):
                    tls_port = connector.get("port")
                else:
                    http_port = connector.get("port")

            for host in service.findall("./Engine/Host"):
                host_conf = {
                    "hostname": host.get("name"),
                    "http_port": http_port,
                    "tls_port": tls_port,
                    "base": host.get("appBase"),
                    "logs": {},
                    "tls_cert": tls_cert,
                    "tls_key": tls_key,
                }

                # Collect defined log configuration for this host by iterating for the AccessLogValve.
                if (valve := host.find("./Valve[@className='org.apache.catalina.valves.AccessLogValve']")) is not None:
                    host_conf["logs"] = {
                        "directory": valve.get("directory"),
                        "prefix": valve.get("prefix"),
                        "suffix": valve.get("suffix"),
                        "pattern": valve.get("pattern"),
                    }

                yield host_conf

    def find_log_files(self) -> Iterator[Path]:
        """Yield Tomcat log files."""
        seen = set()

        # Find log directories from configuration files.
        for install, path in self.configs:
            for config in self.parse_config(path):
                if not (log_config := config.get("logs")):
                    continue

                dir_str = log_config.get("directory")

                # Duck-type if this is already a complete path
                if (log_dir := self.target.fs.path(dir_str)).is_dir() or (
                    log_dir := install.joinpath(dir_str)
                ).is_dir():
                    pass
                else:
                    self.target.log.warning("Unable to infer log directory location for %r in %s", dir_str, path)
                    continue

                prefix = log_config.get("prefix")
                suffix = log_config.get("suffix")
                for log in log_dir.glob(f"{prefix}*{suffix}"):
                    log = log.resolve()
                    if log not in seen:
                        seen.add(log)
                        yield log

        # Find log directories from default (absolute) paths.
        for log_str in self.DEFAULT_LOG_PATHS:
            base, _, glob = log_str.rpartition("/")
            for log_dir in self.target.fs.path(base).glob(glob):
                for log in log_dir.glob("*access_log*"):
                    if log not in seen:
                        seen.add(log)
                        yield log

    @export(record=WebserverHostRecord)
    def hosts(self) -> Iterator[WebserverHostRecord]:
        """Return configured Tomcat hosts in unified ``WebserverHostRecord`` format.

        References:
            - https://tomcat.apache.org/tomcat-9.0-doc/config/host.html
        """
        for install, config_path in self.configs:
            for config in self.parse_config(config_path):
                log_config = config.get("logs", {})
                if log_config:
                    access_log_config = (
                        f"{log_config.get('directory')}/{log_config.get('prefix')}*{log_config.get('suffix')}"
                    )
                else:
                    access_log_config = None

                tls_cert_path = None
                tls_key_path = None

                if (tls_cert := config.get("tls_cert")) and not (
                    (tls_cert_path := self.target.fs.path(tls_cert)).is_file()
                    or (tls_cert_path := install.joinpath(tls_cert)).is_file()
                ):
                    self.target.log.warning("Unable to resolve certificate file location for %r", tls_cert)

                if (tls_key := config.get("tls_key")) and not (
                    (tls_key_path := self.target.fs.path(tls_key)).is_file()
                    or (tls_key_path := install.joinpath(tls_key)).is_file()
                ):
                    self.target.log.warning("Unable to resolve certificate key file location for %r", tls_cert)

                yield WebserverHostRecord(
                    ts=config_path.lstat().st_mtime,
                    webserver=self.__namespace__,
                    server_name=config.get("hostname"),
                    server_port=config.get("tls_port") if tls_cert_path else config.get("http_port"),
                    access_log_config=access_log_config,
                    tls_certificate=tls_cert_path,
                    tls_key=tls_key_path,
                    source=config_path,
                    _target=self.target,
                )

    @export(record=WebserverCertificateRecord)
    def certificates(self) -> Iterator[WebserverCertificateRecord]:
        """Yield TLS certificates from Tomcat hosts."""
        for host in self.hosts():
            if not host.tls_certificate:
                continue

            cert_path = self.target.fs.path(host.tls_certificate)
            try:
                cert = parse_x509(cert_path)
                yield WebserverCertificateRecord(
                    ts=cert_path.lstat().st_mtime,
                    webserver=self.__namespace__,
                    **cert._asdict(),
                    host=host.server_name,
                    source=cert_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Unable to parse certificate %s: %s", cert_path, e)
                self.target.log.debug("", exc_info=e)

    @export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of Tomcat access log files in unified ``WebserverAccessLogRecord`` format.

        References:
            - https://tomcat.apache.org/tomcat-9.0-doc/config/valve.html#Access_logging
        """
        for log_file in self.log_files:
            for line in open_decompress(log_file, "rt"):
                if not (logformat := self.infer_access_log_format(line)):
                    self.target.log.warning("Could not detect Tomcat format for log line in %s: %r", log_file, line)
                    continue

                if not (match := logformat.pattern.match(line)):
                    self.target.log.warning(
                        "Could not match Tomcat format %s for log line in %s: %r", logformat.name, log_file, line
                    )
                    continue

                log = match.groupdict()

                try:
                    bytes_sent = log["bytes_sent"].strip("-") or 0
                except ValueError:
                    bytes_sent = None

                ts = None
                ts_fmts = [logformat.timestamp] if not isinstance(logformat.timestamp, list) else logformat.timestamp

                for fmt in ts_fmts:
                    try:
                        ts = datetime.strptime(log["ts"], fmt or "%d/%b/%Y:%H:%M:%S %z")  # noqa: DTZ007
                        break
                    except ValueError:
                        pass

                if not ts:
                    self.target.log.warning(
                        "Could not match Tomcat timestamp format for log line in %s: %r", log_file, log["ts"]
                    )
                elif not ts.tzinfo:
                    ts.replace(tzinfo=self.target.datetime.tzinfo).astimezone(timezone.utc)

                log.pop("ts")
                log.pop("bytes_sent")

                # Normalize empty '-' values to None
                for key, value in log.items():
                    log[key] = None if value == "-" else value

                yield WebserverAccessLogRecord(
                    ts=ts,
                    webserver=self.__namespace__,
                    bytes_sent=bytes_sent,
                    **log,
                    source=log_file,
                    _target=self.target,
                )

    @staticmethod
    def infer_access_log_format(line: str) -> LogFormat | None:
        """Attempt to infer what LogFormat is used by the log line provided."""
        return LOG_FORMAT_ACCESS_DEFAULT
