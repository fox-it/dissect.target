from __future__ import annotations

import json
import re
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugin import export
from dissect.target.plugins.apps.webserver.webserver import (
    WebserverAccessLogRecord,
    WebserverErrorLogRecord,
    WebserverHostRecord,
    WebserverPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

# Reference: https://nginx/org/en/docs/http/ngx_http_log_module.html#log_format
RE_ACCESS_LOG = re.compile(
    r"""
        (?P<remote_ip>.*?)\s-\s(?P<remote_user>.*?)
        \s
        \[(?P<datetime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s(\+|\-)\d{4})\]
        \s
        \"(?P<method>.*?)\s(?P<uri>.*?)\s?(?P<protocol>HTTP\/.*?)?\"
        \s
        (?P<status_code>\d{3})
        \s
        (?P<bytes_sent>-|\d+)
        \s
        (["](?P<referer>(\-)|(.+))["])
        \s
        \"(?P<useragent>.*?)\"
    """,
    re.VERBOSE,
)

# Reference: https://github.com/nginx/nginx/blob/master/src/core/ngx_log.c
RE_ERROR_LOG = re.compile(
    r"""
        (?P<ts>\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2})      # YYYY/MM/DD HH:MM:SS
        \s
        \[(?P<level>\S+)\]
        \s
        (?P<pid>\d+)\#(?P<tid>\d+)\:                        # 12345#12345:
        \s
        (?P<message>.+)
    """,
    re.VERBOSE,
)

# Reference: https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log
RE_ACCESS_LOG_DIRECTIVE = re.compile(
    r"""
        (?:\#\s+?)?                     # optionally include disabled directives
        access_log\s+
        (?P<path>[^\s\;]+)
        (?:\s(?P<format>[^\s\;]+))?     # capture format and ignore other arguments
    """,
    re.VERBOSE,
)

# Reference: https://nginx.org/en/docs/ngx_core_module.html#error_log
RE_ERROR_LOG_DIRECTIVE = re.compile(
    r"""
        (?:\#\s+?)?                     # optionally include disabled directives
        error_log\s+
        (?P<path>[^\s\;]+)
        (?:\s(?P<level>[^\s\;]+))?      # capture optional level
    """,
    re.VERBOSE,
)

# Reference: https://nginx.org/en/docs/ngx_core_module.html#include
RE_INCLUDE_DIRECTIVE = re.compile(r"[\s#]*include\s+(?P<path>[^\s\;]+)")


class NginxPlugin(WebserverPlugin):
    """NGINX webserver plugin."""

    __namespace__ = "nginx"

    DEFAULT_LOG_DIRS = (
        "/var/log/nginx",
        "/var/log",
    )

    ACCESS_LOG_NAMES = ("access.log",)
    ERROR_LOG_NAMES = ("error.log",)

    DEFAULT_CONFIG_PATHS = (
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-available/*.conf",
        "/etc/nginx/sites-enabled/*.conf",
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.access_paths = set()
        self.error_paths = set()
        self.host_paths = set()

        self.find_logs()

    def check_compatible(self) -> None:
        if not self.access_paths and not self.error_paths and not self.host_paths:
            raise UnsupportedPluginError("No NGINX log or config files found on target")

    def find_logs(self) -> None:
        # Add any well known default NGINX log locations
        for log_dir in self.DEFAULT_LOG_DIRS:
            log_dir = self.target.fs.path(log_dir)
            for log_name in self.ACCESS_LOG_NAMES:
                self.access_paths.update(log_dir.glob(f"{log_name}*"))
            for log_name in self.ERROR_LOG_NAMES:
                self.error_paths.update(log_dir.glob(f"{log_name}*"))

        # Check for custom paths in NGINX install config
        for config_file in self.DEFAULT_CONFIG_PATHS:
            if "*" in config_file:
                base, _, glob = config_file.partition("*")
                for f in self.target.fs.path(base).rglob(f"*{glob}"):
                    self.parse_config(f)

            elif (config_file := self.target.fs.path(config_file)).exists():
                self.parse_config(config_file)

    def parse_config(self, path: Path, seen: set[Path] | None = None) -> None:
        """Parse the given NGINX ``.conf`` file for ``access_log``, ``error_log`` and ``include`` directives."""

        seen = set() if seen is None else seen

        if path in seen:
            self.target.log.warning("Detected recursion in NGINX configuration, file already parsed: %s", path)
            return

        seen.add(path)

        if not path.is_file():
            self.target.log.warning("File %s does not exist on target", path)
            return

        for line in path.open("rt"):
            if not (line := line.strip()):
                continue

            if "access_log " in line:
                if access_log := RE_ACCESS_LOG_DIRECTIVE.search(line):
                    access_log = self.target.fs.path(access_log["path"])
                    self.access_paths.update(access_log.parent.glob(f"{access_log.name}*"))
                else:
                    self.target.log.warning("Unable to parse nginx access_log line %r in %s", line, path)

            elif "error_log " in line:
                if error_log := RE_ERROR_LOG_DIRECTIVE.search(line):
                    error_log = self.target.fs.path(error_log["path"])
                    self.error_paths.update(error_log.parent.glob(f"{error_log.name}*"))
                else:
                    self.target.log.warning("Unable to parse NGINX error_log line %r in %s", line, path)

            elif "server {" in line:
                self.host_paths.add(path)

            elif "include " in line:
                if match := RE_INCLUDE_DIRECTIVE.search(line):
                    path_str: str = match.groupdict().get("path")

                    if "*" in path_str:
                        base, _, glob = path_str.partition("*")
                        include_paths = self.target.fs.path(base).rglob(f"*{glob}")
                    else:
                        include_paths = [self.target.fs.path(path_str)]

                    for include_path in include_paths:
                        if include_path.is_absolute():
                            self.parse_config(include_path)
                        else:
                            include_path = self.target.fs.path(path.parent).joinpath(include_path)
                            self.parse_config(include_path)
                else:
                    self.target.log.warning("Unable to parse NGINX include line %r in %s", line, path)

    @export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of NGINX access log files in unified ``WebserverAccessLogRecord`` format.

        References:
            - https://docs.nginx.com/nginx/admin-guide/monitoring/logging/#access_log
            - http://nginx.org/en/docs/http/ngx_http_log_module.html#log_format
        """
        for path in self.access_paths:
            path = path.resolve(strict=True)
            if not path.is_file():
                self.target.log.warning("NGINX log file configured but could not be found (dead symlink?): %s", path)
                continue

            for line in open_decompress(path, "rt"):
                if not (line := line.strip()):
                    continue

                log: dict[str, str] = {}

                if line[0:2] == '{"':
                    try:
                        log = parse_json_line(line)
                    except ValueError as e:
                        self.target.log.warning("Could not parse NGINX JSON log line %r in %s", line, path)
                        self.target.log.debug("", exc_info=e)
                        continue

                elif match := RE_ACCESS_LOG.search(line):
                    log = match.groupdict()

                else:
                    self.target.log.warning("Could not match NGINX format for log line %r in %s", line, path)
                    continue

                ts = None
                bytes_sent = None

                try:
                    ts = datetime.strptime(log["datetime"], "%d/%b/%Y:%H:%M:%S %z")
                    bytes_sent = log["bytes_sent"].strip("-") or 0
                except ValueError:
                    pass

                log.pop("datetime")
                log.pop("bytes_sent")

                yield WebserverAccessLogRecord(
                    ts=ts,
                    bytes_sent=bytes_sent,
                    **log,
                    source=path,
                    _target=self.target,
                )

    def error(self) -> Iterator[WebserverErrorLogRecord]:
        """Return contents of NGINX error log files in unified ``WebserverErrorLogRecord`` format.

        Resources:
            - https://nginx.org/en/docs/ngx_core_module.html#error_log
            - https://github.com/nginx/nginx/blob/master/src/core/ngx_log.c
        """
        target_tz = self.target.datetime.tzinfo

        for path in self.error_paths:
            path = path.resolve(strict=True)
            if not path.is_file():
                self.target.log.warning("File not found: %s", path)
                continue

            for line in open_decompress(path, "rt"):
                if not (line := line.strip()):
                    continue

                if not (match := RE_ERROR_LOG.search(line)):
                    self.target.log.warning("Unable to match NGINX error log message %r in %s", line, path)
                    continue

                log = match.groupdict()

                try:
                    ts = datetime.strptime(log["ts"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=target_tz)
                except ValueError:
                    ts = None

                log.pop("ts")
                log.pop("tid")

                yield WebserverErrorLogRecord(
                    ts=ts,
                    **log,
                    source=path,
                    _target=self.target,
                )

    def hosts(self) -> Iterator[WebserverHostRecord]:
        """Return found server directives in the NGINX configuration.

        Resources:
            - https://nginx.org/en/docs/http/ngx_http_core_module.html#server
        """

        def yield_record(current_server: dict) -> Iterator[WebserverHostRecord]:
            yield WebserverHostRecord(
                ts=host_path.lstat().st_mtime,
                server_name=current_server.get("server_name") or current_server.get("listen"),
                server_port=current_server.get("listen"),
                root_path=current_server.get("root"),
                access_log_config=current_server.get("access_log"),
                error_log_config=current_server.get("error_log"),
                source=host_path,
                _target=self.target,
            )

        for host_path in self.host_paths:
            current_server = {}
            seen_server_directive = False
            for line in host_path.open("rt"):
                if "server {" in line:
                    if current_server:
                        yield from yield_record(current_server)
                    current_server = {}
                    seen_server_directive = True

                elif seen_server_directive:
                    key, _, value = line.strip().partition(" ")
                    current_server[key] = value.rstrip(";")

            if current_server:
                yield from yield_record(current_server)


def parse_json_line(line: str) -> dict[str, str] | None:
    """Attempt to parse a default NGINX JSON log line.

    We assume the custom ``log_format`` uses the following default NGINX field names:

    .. code-block:: text

        time_local, time, remote_addr, remote_ip, remote_user, request_method, request,
        response, status, body_bytes_sent, request_time, http_referrer, referrer,
        http_user_agent, agent

    Unfortunately NGINX has no official default naming convention for JSON access logs,
    users can configure the JSON ``log_format`` as they see fit.

    Resources:
        - https://nginx.org/en/docs/http/ngx_http_log_module.html
        - https://github.com/elastic/examples/blob/master/Common%20Data%20Formats/nginx_json_logs/README.md
    """

    try:
        json_log = json.loads(line)
        return {
            "datetime": json_log.get("time_local") or json_log.get("time"),
            "remote_ip": json_log.get("remote_addr") or json_log.get("remote_ip"),
            "remote_user": json_log.get("remote_user"),
            "method": json_log.get("request_method"),
            "uri": json_log.get("request_uri") or json_log.get("request"),
            "status": json_log.get("status") or json_log.get("response"),
            "status_code": json_log.get("status") or json_log.get("response"),
            "referer": json_log.get("http_referrer") or json_log.get("referrer"),
            "useragent": json_log.get("http_user_agent") or json_log.get("agent"),
            "response_time_ms": json_log.get("request_time"),
            "bytes_sent": json_log.get("body_bytes_sent") or json_log.get("bytes"),
        }

    except json.JSONDecodeError as e:
        raise ValueError(f"Could not parse NGINX log line {line!r}: {e}") from e
