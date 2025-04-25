from __future__ import annotations

import itertools
import re
from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, NamedTuple

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugin import OperatingSystem, export
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


class LogFormat(NamedTuple):
    name: str
    pattern: re.Pattern


# e.g. ServerRoot "/etc/httpd"
RE_CONFIG_ROOT = re.compile(
    r"""
        [\s#]*                          # Optionally prefixed by space(s) or pound sign(s).
        ServerRoot
        \s
        "?(?P<location>[^"\s]+)"
        $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# e.g. Include conf.modules.d/*.conf and IncludeOptional conf.d/*.conf
RE_CONFIG_INCLUDE = re.compile(
    r"""
        [\s#]*                          # Optionally prefixed by space(s) or pound sign(s).
        (Include|IncludeOptional)       # Directive indicating that additional config files are loaded.
        \s
        ?(?P<location>[^"\s]+)
        $
    """,
    re.VERBOSE | re.IGNORECASE,
)


# e.g. CustomLog "/custom/log/location/access.log" common
RE_CONFIG_CUSTOM_LOG_DIRECTIVE = re.compile(
    r"""
        [\s#]*                          # Optionally prefixed by space(s) or pound sign(s).
        CustomLog                       # Directive indicating that a custom access log location / format is used.
        \s
        "?(?P<location>[^"\s]+)"?       # Location to log to, optionally wrapped in double quotes.
        \s
        (?P<logformat>[^$]+)            # Format to use (can be either a format string or a nickname).
        $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# e.g ErrorLog "/var/log/httpd/error_log"
RE_CONFIG_ERRORLOG_DIRECTIVE = re.compile(
    r"""
        [\s#]*                          # Optionally prefixed by space(s) or pound sign(s).
        ErrorLog                        # Directive indicating that a custom error log location / format is used.
        \s
        "?(?P<location>[^"\s]+)"?       # Location to log to, optionally wrapped in double quotes.
        $
    """,
    re.VERBOSE | re.IGNORECASE,
)

RE_REMOTE_PATTERN = r"""
    (?P<remote_ip>.*?)                  # Client IP address of the request.
    \s
    (?P<remote_logname>.*?)             # Remote logname (from identd, if supplied).
    \s
    (?P<remote_user>.*?)                # Remote user if the request was authenticated.
"""

RE_REFERER_USER_AGENT_PATTERN = r"""
    "(?P<referer>.*?)"                  # Value of the 'Referer' HTTP Header.
    \s
    "(?P<useragent>.*?)"                # Value of the 'User-Agent' HTTP Header.
"""

RE_RESPONSE_TIME_PATTERN = r"""
(
    "
    Time:\s
    (?P<response_time>.*?)              # Time taken to serve the response, including a unit of measurement.
    "
)
"""

RE_ACCESS_COMMON_PATTERN = r"""
    \[(?P<ts>[^\]]*)\]                  # Timestamp including milliseconds.
    \s
    (\[(?P<pid>[0-9]+)\]\s)?            # The process ID of the child that serviced the request (optional).
    "
    (
        -                               # Malformed requests may result in the value "-"
        |
        (
            (?P<method>.*?)             # The HTTP Method used for the request.
            \s
            (?P<uri>.*?)                # The HTTP URI of the request.
            \s
            ?(?P<protocol>HTTP\/.*?)?   # The request protocol.
        )
    )
    "
    \s
    (?P<status_code>\d{3})              # The HTTP Status Code of the response.
    \s
    (?P<bytes_sent>-|\d+)               # Bytes sent, including headers.
"""

RE_ERROR_COMMON_PATTERN = r"""
    \[
        (?P<ts>[^\]]*)                  # Timestamp including milliseconds.
    \]
    \s
    \[
        (?P<module>[^:]*)               # Name of the module logging the message.
        \:
        (?P<level>[^]]*)                # Loglevel of the message.
    \]
    \s
    \[
        pid\s(?P<pid>\d*)               # Process ID of current process.
        (\:tid\s(?P<tid>\d*))?          # Thread ID of current thread (optional).
    \]
    \s
    ((?P<error_source>[^\:]*)\:\s)?     # Source file name and line number of the log call (optional).
    (
        \[
            client\s(?P<client>[^]]+)   # Client IP address and port of the request (optional).
        \]\s
    )?
    ((?P<error_code>\w+)\:\s)?          # APR/OS error status code and string (optional).
    (?P<message>.*)                     # The actual log message.
"""

RE_ENV_VAR_IN_STRING = re.compile(r"\$\{(?P<env_var>[^\"\s$]+)\}", re.VERBOSE)

RE_VIRTUALHOST = re.compile(r"^\<VirtualHost (?P<addr>[^\s:]+)(?:\:(?P<port>\d+))?", re.IGNORECASE)

LOG_FORMAT_ACCESS_COMMON = LogFormat(
    "common",
    re.compile(
        rf"{RE_REMOTE_PATTERN}\s{RE_ACCESS_COMMON_PATTERN}",
        re.VERBOSE,
    ),
)
LOG_FORMAT_ACCESS_VHOST_COMBINED = LogFormat(
    "vhost_combined",
    re.compile(
        rf"""
        (?P<server_name>.*?):(?P<port>.*)
        \s
        {RE_REMOTE_PATTERN}
        \s
        {RE_ACCESS_COMMON_PATTERN}
        \s
        {RE_REFERER_USER_AGENT_PATTERN}
        """,
        re.VERBOSE,
    ),
)
LOG_FORMAT_ACCESS_COMBINED = LogFormat(
    "combined",
    re.compile(
        rf"{RE_REMOTE_PATTERN}\s{RE_ACCESS_COMMON_PATTERN}\s{RE_REFERER_USER_AGENT_PATTERN}",
        re.VERBOSE,
    ),
)
LOG_FORMAT_ERROR_COMMON = LogFormat("error", re.compile(RE_ERROR_COMMON_PATTERN, re.VERBOSE))


def apache_response_time_to_ms(time_str: str) -> int:
    """Convert a string containing amount and measurement (e.g. '10000 microsecs') to milliseconds."""
    amount, _, measurement = time_str.partition(" ")
    amount = int(amount)
    if measurement == "microsecs":
        return amount // 1000
    raise ValueError(f"Could not parse {time_str}")


class ApachePlugin(WebserverPlugin):
    """Apache log parsing plugin.

    Apache has three default access log formats, which this plugin can all parse automatically. These are::

        LogFormat "%v:%p %h %l %u %t \\"%r\\" %>s %O \\"%{Referer}i\\" \\"%{User-Agent}i\\"" vhost_combined
        LogFormat "%h %l %u %t \\"%r\\" %>s %O \\"%{Referer}i\\" \\"%{User-Agent}i\\"" combined
        LogFormat "%h %l %u %t \\"%r\\" %>s %O" common

    For the definitions of each format string, see https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats

    For Apache, the error logs by default follow the following format::

        ErrorLogFormat "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\\ %a] %M% ,\\ referer\\ %{Referer}i"
    """

    __namespace__ = "apache"

    DEFAULT_LOG_DIRS = (
        "/var/log/apache2",
        "/var/log/apache",
        "/var/log/httpd",
        "/var/log",
        "sysvol/xampp/apache/logs",
        "/opt/lampp/logs",
    )
    ACCESS_LOG_NAMES = ("access.log", "access_log", "httpd-access.log")
    ERROR_LOG_NAMES = ("error.log",)
    DEFAULT_CONFIG_PATHS = (
        "/etc/apache2/apache2.conf",
        "/usr/local/etc/apache22/httpd.conf",
        "/usr/local/apache2/httpd.conf",
        "/etc/httpd/conf/httpd.conf",
        "/etc/httpd.conf",
    )
    DEFAULT_ENVVAR_PATHS = ("/etc/apache2/envvars", "/etc/sysconfig/httpd", "/etc/rc.conf")
    DEFAULT_SERVER_ROOTS = ("/etc/apache2", "/usr/local/apache2", "/etc/httpd", "/home/httpd", "/home/apache2")

    def __init__(self, target: Target):
        super().__init__(target)
        self.server_root = None
        self.access_paths = set()
        self.error_paths = set()
        self.virtual_hosts = set()
        self.find_logs()

    def check_compatible(self) -> None:
        if not self.access_paths and not self.error_paths and not self.virtual_hosts:
            raise UnsupportedPluginError("No Apache log files or virtual hosts found")

        if self.target.os == OperatingSystem.CITRIX:
            raise UnsupportedPluginError("Use the 'apps.webserver.citrix' apache plugin instead")

    def find_logs(self) -> None:
        """Discover any present Apache log paths on the target system.
        Populates ``self.access_paths``, ``self.error_paths`` and ``self.virtual_hosts``.

        References:
            - https://httpd.apache.org/docs/2.4/logs.html
            - https://httpd.apache.org/docs/2.4/mod/mod_log_config.html
            - https://www.cyberciti.biz/faq/apache-logs/
            - https://unix.stackexchange.com/a/269090
        """

        # Check if any well known default Apache log locations exist
        for log_dir, log_name in itertools.product(self.DEFAULT_LOG_DIRS, self.ACCESS_LOG_NAMES):
            self.access_paths.update(self.target.fs.path(log_dir).glob(f"*{log_name}*"))

        for log_dir, log_name in itertools.product(self.DEFAULT_LOG_DIRS, self.ERROR_LOG_NAMES):
            self.error_paths.update(self.target.fs.path(log_dir).glob(f"*{log_name}*"))

        seen = set()

        # Check default Apache configs for CustomLog or ErrorLog directives
        for config in self.DEFAULT_CONFIG_PATHS:
            if (path := self.target.fs.path(config)).exists() and path not in seen:
                self._process_conf_file(path, seen)

        # Check all .conf files inside the server root
        if self.server_root:
            for path in self.server_root.rglob("*.conf"):
                if path not in seen:
                    self._process_conf_file(path, seen)

    def _process_conf_file(self, path: Path, seen: set[Path] | None = None) -> None:
        """Process an Apache ``.conf`` file for ``ServerRoot``, ``CustomLog``, ``Include``
        and ``OptionalInclude`` directives. Populates ``self.access_paths`` and ``self.error_paths``.

        Apache / Httpd directives are case-insensitive which is why we convert lines to lowercase for pattern matching.

        Resources:
            - https://httpd.apache.org/docs/2.4/en/configuring.html#syntax
        """
        seen = set() if seen is None else seen

        if path in seen:
            self.target.log.warning("Detected recursion in Apache configuration, file already parsed: %s", path)
            return

        seen.add(path)

        for line in path.open("rt"):
            if not (line := line.strip()):
                continue

            line_lower = line.lower()

            if "serverroot" in line_lower:
                if not (match := RE_CONFIG_ROOT.match(line)):
                    self.target.log.warning("Unable to parse Apache 'ServerRoot' configuration in %s: %r", path, line)
                    continue
                location = match.groupdict().get("location")
                self.server_root = self.target.fs.path(location)

            elif "customlog" in line_lower or "errorlog" in line_lower:
                self._process_conf_line(path, line)

            elif "include" in line_lower:
                if not (match := RE_CONFIG_INCLUDE.match(line)):
                    self.target.log.warning("Unable to parse Apache 'Include' configuration in %s: %r", path, line)
                    continue

                location = match.groupdict().get("location")

                if "*" in location:
                    root, rest = location.split("*", 1)
                    if root.startswith("/"):
                        root = self.target.fs.path(root)
                    elif not root.startswith("/") and self.server_root:
                        root = self.server_root.joinpath(root)
                    elif not self.server_root:
                        self.target.log.warning("Unable to resolve relative Include in %s: %r", path, line)
                        continue

                    for found_conf in root.glob(f"*{rest}"):
                        self._process_conf_file(found_conf, seen)

                elif (
                    # Relative from server root
                    (self.server_root and (include_path := self.server_root.joinpath(location)).exists())
                    or
                    # Absolute path
                    ((include_path := self.target.fs.path(location)).exists())
                ):
                    self._process_conf_file(include_path, seen)

                else:
                    self.target.log.warning("Unable to resolve Apache Include in %s: %r", path, line)

            # While we're at it, see if we can find any VirtualHosts
            elif "<virtualhost" in line_lower:
                self.virtual_hosts.add(path)

    def _process_conf_line(self, path: Path, line: str) -> None:
        """Parse and resolve the given ``CustomLog`` or ``ErrorLog`` directive found in a Apache ``.conf`` file."""
        if "errorlog" in line.lower():
            pattern = RE_CONFIG_ERRORLOG_DIRECTIVE
            set_to_update = self.error_paths
        else:
            pattern = RE_CONFIG_CUSTOM_LOG_DIRECTIVE
            set_to_update = self.access_paths

        if not (match := pattern.match(line)):
            self.target.log.warning("Unexpected Apache 'ErrorLog' or 'CustomLog' configuration in %s: %r", path, line)
            return

        location = match.groupdict().get("location")
        custom_log = self.target.fs.path(location)

        if env_var_match := RE_ENV_VAR_IN_STRING.match(location):
            env_var = env_var_match.groupdict()["env_var"]
            if (apache_log_dir := self.env_vars.get(env_var)) is None:
                self.target.log.warning("%s does not exist, cannot resolve '%s' in %s", env_var, custom_log, path)
                return

            custom_log = self.target.fs.path(location.replace(f"${{{env_var}}}", apache_log_dir.replace("$SUFFIX", "")))

        set_to_update.update(path for path in custom_log.parent.glob(f"*{custom_log.name}*"))

    @cached_property
    def env_vars(self) -> dict[str, str]:
        variables = {}
        for envvar_file in self.DEFAULT_ENVVAR_PATHS:
            if (file := self.target.fs.path(envvar_file)).exists():
                for line in file.read_text().splitlines():
                    key, _, value = line.strip().partition("=")
                    if key:
                        variables[key.replace("export ", "")] = value.strip("\"'")
        return variables

    @export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of Apache access log files in unified ``WebserverAccessLogRecord`` format."""
        for line, path in self._iterate_log_lines(self.access_paths):
            try:
                logformat = self.infer_access_log_format(line)
                if not logformat:
                    self.target.log.warning("Apache log format could not be inferred for log line: %s (%s)", line, path)
                    continue

                match = logformat.pattern.match(line)
                if not match:
                    self.target.log.warning(
                        "Could not match Apache log format %s for log line: %s (%s)", logformat.name, line, path
                    )
                    continue

                log = match.groupdict()
                if response_time := log.get("response_time"):
                    response_time = apache_response_time_to_ms(response_time)

                yield WebserverAccessLogRecord(
                    ts=datetime.strptime(log["ts"], "%d/%b/%Y:%H:%M:%S %z"),
                    remote_user=clean_value(log["remote_user"]),
                    remote_ip=log["remote_ip"],
                    local_ip=clean_value(log.get("local_ip")),
                    method=log["method"],
                    uri=log["uri"],
                    protocol=log["protocol"],
                    status_code=log["status_code"],
                    bytes_sent=clean_value(log["bytes_sent"]) or 0,
                    pid=log.get("pid"),
                    referer=clean_value(log.get("referer")),
                    useragent=clean_value(log.get("useragent")),
                    response_time_ms=response_time,
                    source=path,
                    _target=self.target,
                )

            except Exception as e:
                self.target.log.warning("An error occured parsing Apache log file %s: %s", path, str(e))
                self.target.log.debug("", exc_info=e)

    @export(record=WebserverErrorLogRecord)
    def error(self) -> Iterator[WebserverErrorLogRecord]:
        """Return contents of Apache error log files in unified ``WebserverErrorLogRecord`` format."""
        for line, path in self._iterate_log_lines(self.error_paths):
            try:
                match = LOG_FORMAT_ERROR_COMMON.pattern.match(line)
                if not match:
                    self.target.log.warning("Could not match Apache error log format for log line: %s (%s)", line, path)
                    continue

                log = match.groupdict()
                remote_ip = log.get("client")
                if remote_ip and ":" in remote_ip:
                    remote_ip, _, port = remote_ip.rpartition(":")
                error_source = log.get("error_source")
                error_code = log.get("error_code")

                # Both error_source and error_code follow the same logformat. When both are present, the error source
                # goes before the client and the error code goes after. However, it is also possible that only the error
                # code is available, in which case it is situated *after* the client. In such situations our regex match
                # has assigned the variables wrong, and we need to do a swap.
                if error_source and error_code is None:
                    error_source, error_code = error_code, error_source

                # Unlike with access logs, ErrorLogFormat doesn't log the offset to UTC but insteads logs in local time.
                ts = self.target.datetime.local(datetime.strptime(log["ts"], "%a %b %d %H:%M:%S.%f %Y"))  # noqa: DTZ007

                yield WebserverErrorLogRecord(
                    ts=ts,
                    pid=log.get("pid"),
                    remote_ip=remote_ip,
                    module=log["module"],
                    level=log["level"],
                    error_source=error_source,
                    error_code=error_code,
                    message=log["message"],
                    source=path,
                    _target=self.target,
                )

            except Exception as e:
                self.target.log.warning("An error occured parsing Apache log file %s: %s", path, str(e))
                self.target.log.debug("", exc_info=e)

    def hosts(self) -> Iterator[WebserverHostRecord]:
        """Return found ``VirtualHost`` directives in the Apache configuration.

        Resources:
            - https://httpd.apache.org/docs/2.4/mod/core.html#virtualhost
        """

        for path in self.virtual_hosts:
            # A configuration file can contain multiple VirtualHost directives.
            current_vhost = {}
            for line in path.open("rt"):
                line_lower = line.lower()
                if "<virtualhost" in line_lower:
                    # Currently only supports a single addr:port combination.
                    if match := RE_VIRTUALHOST.match(line.lstrip()):
                        current_vhost = match.groupdict()
                    else:
                        self.target.log.warning("Unable to parse VirtualHost directive %r in %s", line, path)
                        current_vhost = {}

                elif "</virtualhost" in line_lower:
                    yield WebserverHostRecord(
                        ts=path.lstat().st_mtime,
                        server_name=current_vhost.get("servername") or current_vhost.get("addr"),
                        server_port=current_vhost.get("port"),
                        root_path=current_vhost.get("documentroot"),
                        access_log_config=current_vhost.get("customlog", "").rpartition(" ")[0],
                        error_log_config=current_vhost.get("errorlog"),
                        source=path,
                        _target=self.target,
                    )

                else:
                    key, _, value = line.strip().partition(" ")
                    current_vhost[key.lower()] = value

    def _iterate_log_lines(self, paths: list[Path]) -> Iterator[tuple[str, Path]]:
        """Iterate through a list of paths and yield tuples of loglines and the path of the file where they're from."""
        for path in paths:
            try:
                path = path.resolve(strict=True)
                for line in open_decompress(path, "rt"):
                    line = line.strip()
                    if not line:
                        continue
                    yield line, path
            except FileNotFoundError:
                self.target.log.warning("Apache log file configured but could not be found (dead symlink?): %s", path)

    @staticmethod
    def infer_access_log_format(line: str) -> LogFormat | None:
        """Attempt to infer what standard LogFormat is used. Returns None if no known format can be inferred.

        Three default log type examples from Apache (note that the ipv4 could also be ipv6)

        Combined::

            1.2.3.4 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0
                        (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0
                        Safari/537.36\"

        Common::

            1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312
            1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 301 -

        vhost_combined::

            example.com:80 1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 "-"
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko)
            Chrome/108.0.0.0 Safari/537.36\"
        """
        parts = line.split()
        first_part = parts[0]
        if ":" in first_part and "." in first_part:
            # does not start with IP, hence it must be a vhost typed log
            return LOG_FORMAT_ACCESS_VHOST_COMBINED
        if line[-1] == '"':
            # ends with a quotation mark but does not contain a response time, meaning there is only a user agent
            return LOG_FORMAT_ACCESS_COMBINED
        if line[-1].isdigit() or line[-1] == "-":
            # ends with a digit or '-' indicating response size in bytes
            return LOG_FORMAT_ACCESS_COMMON

        return None


def clean_value(value: str | None) -> str | None:
    """Clean the given value by replacing empty strings and ``"-"`` with ``None``."""

    if value in ("-", ""):
        return None

    return value
