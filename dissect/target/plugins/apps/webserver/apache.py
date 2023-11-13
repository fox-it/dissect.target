import enum
import itertools
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Tuple

from dissect.target import plugin
from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webserver.webserver import (
    WebserverAccessLogRecord,
    WebserverErrorLogRecord,
)
from dissect.target.target import Target

REMOTE_REGEX = r"""
    (?P<remote_ip>.*?)                  # Client IP address of the request.
    \s
    (?P<remote_logname>.*?)             # Remote logname (from identd, if supplied).
    \s
    (?P<remote_user>.*?)                # Remote user if the request was authenticated.
"""

REFERER_USER_AGENT_REGEX = r"""
    "(?P<referer>.*?)"                  # Value of the 'Referer' HTTP Header.
    \s
    "(?P<useragent>.*?)"                # Value of the 'User-Agent' HTTP Header.
"""

COMMON_REGEX = r"""
    \[(?P<ts>[^\]]*)\]                  # Timestamp including milliseconds.
    \s
    (\[(?P<pid>[0-9]+)\]\s)?            # The process ID of the child that serviced the request.
    "
    (?P<method>.*?)                     # The HTTP Method used for the request.
    \s
    (?P<uri>.*?)                        # The HTTP URI of the request.
    \s
    ?(?P<protocol>HTTP\/.*?)?           # The request protocol.
    "
    \s
    (?P<status_code>\d{3})              # The HTTP Status Code of the response.
    \s
    (?P<bytes_sent>-|\d+)               # Bytes sent, including headers
"""

RESPONSE_TIME_REGEX = r"""
(
    "
    Time:\s
    (?P<response_time>.*?)              # Time taken to serve the response, including a unit of measurement.
    "
)
"""  #

COMMON_ERROR_REGEX = r"""
    \[
        (?P<ts>[^\]]*)                  # Timestamp including miliseconds.
    \]
    \s
    \[
        (?P<module>[^:]*)               # Name of the module logging the message.
        \:
        (?P<level>[^]]*)                # Loglevel of the message.
    \]
    \s
    \[
        pid\s(?P<pid>\d*)               # Process ID of current process
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


class LogFormat(enum.Enum):
    COMMON = re.compile(rf"{REMOTE_REGEX}\s{COMMON_REGEX}", re.VERBOSE)
    VHOST_COMBINED = re.compile(
        rf"(?P<server_name>.*?):(?P<port>.*)\s{REMOTE_REGEX}\s{COMMON_REGEX}\s{REFERER_USER_AGENT_REGEX}",
        re.VERBOSE,
    )
    COMBINED = re.compile(rf"{REMOTE_REGEX}\s{COMMON_REGEX}\s{REFERER_USER_AGENT_REGEX}", re.VERBOSE)

    CITRIX_NETSCALER_COMBINED_RESPONSE_TIME = re.compile(
        rf"{REMOTE_REGEX}\s{COMMON_REGEX}\s{REFERER_USER_AGENT_REGEX}\s{RESPONSE_TIME_REGEX}",
        re.VERBOSE,
    )
    CITRIX_NETSCALER_COMBINED_RESPONSE_TIME_WITH_HEADERS = re.compile(
        rf"""
        (?P<remote_ip>.*?)          # Client IP address of the request.
        \s
        ->
        \s
        (?P<local_ip>.*?)           # Local IP of the Netscaler.
        \s
        (?P<remote_logname>.*?)     # Remote logname (from identd, if supplied).
        \s
        (?P<remote_user>.*?)        # Remote user if the request was authenticated.
        \s
        {COMMON_REGEX}
        \s
        {REFERER_USER_AGENT_REGEX}
        \s
        {RESPONSE_TIME_REGEX}
        """,
        re.VERBOSE,
    )

    COMMON_ERROR = re.compile(COMMON_ERROR_REGEX, re.VERBOSE)


def infer_access_log_format(line: str) -> Optional[LogFormat]:
    """Attempt to infer what standard LogFormat is used. Returns None if no known format can be inferred.

    Three default log type examples from Apache (note that the ipv4 could also be ipv6)::
        combined       = '1.2.3.4 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0
                          (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0
                          Safari/537.36"'
        common         = '1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312'
        vhost_combined = 'example.com:80 1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 "-"
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko)
                          Chrome/108.0.0.0 Safari/537.36"'

    Two logformats encountered on Citrix Netscalers:
        combined_resptime_with_citrix_hdrs  = '1.2.3.4 -> 192.168.4.20 - - [19/Dec/2022:17:25:12 +0100] [12311]
                                               "GET / HTTP/1.1" 200 712 "-" "Mozilla/5.0
                                               (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko)
                                               Chrome/108.0.0.0 Safari/537.36" "Time: 11264 microsecs"'


        combined_resptime                   = '127.0.0.1 - - [19/Dec/2022:17:25:12 +0100] [69195] "GET / HTTP/1.1" 200
                                               18705 "-" "curl/7.78.0" "Time: 49835 microsecs"'

    """
    splitted_line = line.split(" ")
    first_part = splitted_line[0]
    second_part = splitted_line[1]
    if ":" in first_part and "." in first_part:
        # does not start with IP, hence it must be a vhost typed log
        return LogFormat.VHOST_COMBINED
    elif second_part == "->":
        # Citrix-like
        return LogFormat.CITRIX_NETSCALER_COMBINED_RESPONSE_TIME_WITH_HEADERS
    elif line[-1:] == '"':
        if "Time: " in line:
            return LogFormat.CITRIX_NETSCALER_COMBINED_RESPONSE_TIME
        # ends with a quotation mark but does not contain a response time, meaning there is only a user agent
        return LogFormat.COMBINED
    elif line[-1:].isdigit():
        return LogFormat.COMMON
    return None


def apache_response_time_to_ms(time_str: str) -> int:
    amount, _, measurement = time_str.partition(" ")
    amount = int(amount)
    if measurement == "microsecs":
        return amount / 1000
    raise ValueError(f"Could not parse {time_str}")


class ApachePlugin(plugin.Plugin):
    """Apache log parsing plugin.

    Apache has three default access log formats, which this plugin can all parse automatically. These are::
        LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
        LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
        LogFormat "%h %l %u %t \"%r\" %>s %O" common

    Citrix uses Apache with custom access log formats. These are:
        LogFormat "%{Citrix-ns-orig-srcip}i -> %{Citrix-ns-orig-destip}i %l %u %t [%P] \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"Time: %D microsecs\"" combined_resptime_with_citrix_hdrs
        LogFormat "%a %l %u %t [%P] \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"Time: %D microsecs\"" combined_resptime


    For the definitions of each format string, see https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats

    For Apache, the error logs by default follow the following format:
        ErrorLogFormat "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M% ,\ referer\ %{Referer}i"
    """  # noqa: E501, W605

    __namespace__ = "apache"

    def __init__(self, target: Target):
        super().__init__(target)
        self.access_log_paths, self.error_log_paths = self.get_log_paths()

    def check_compatible(self) -> None:
        if not len(self.access_log_paths) and not len(self.error_log_paths):
            raise UnsupportedPluginError("No Apache directories found")

    @plugin.internal
    def get_log_paths(self) -> Tuple[list[Path], list[Path]]:
        """
        Discover any present Apache log paths on the target system.

        References:
            - https://www.cyberciti.biz/faq/apache-logs/
            - https://unix.stackexchange.com/a/269090
        """

        access_log_paths = []
        error_log_paths = []

        # Check if any well known default Apache log locations exist
        default_log_dirs = ["/var/log/apache2", "/var/log/apache", "/var/log/httpd", "/var/log"]
        access_log_names = ["access.log", "access_log", "httpd-access.log", "httpaccess.log", "httpaccess-vpn.log"]
        error_log_names = ["error.log", "httperror.log", "httperror-vpn.log"]

        for log_dir, log_name in itertools.product(default_log_dirs, access_log_names):
            access_log_paths.extend(self.target.fs.path(log_dir).glob(log_name + "*"))
        for log_dir, log_name in itertools.product(default_log_dirs, error_log_names):
            error_log_paths.extend(self.target.fs.path(log_dir).glob(log_name + "*"))
        # Check default Apache configs for their CustomLog directive
        default_config_paths = [
            "/etc/apache2/apache2.conf",
            "/usr/local/etc/apache22/httpd.conf",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd.conf",
        ]

        for config in default_config_paths:
            if (path := self.target.fs.path(config)).exists():
                for line in path.open("rt"):
                    line = line.strip()

                    if not line or "CustomLog" not in line:
                        continue

                    try:
                        # CustomLog "/custom/log/location/access.log" common
                        log_path = line.split("CustomLog")[1].strip().split(" ")[0].replace('"', "")
                        custom_log = self.target.fs.path(log_path)
                        if "error" in log_path:
                            error_log_paths.extend(
                                path
                                for path in custom_log.parent.glob(f"{custom_log.name}*")
                                if path not in error_log_paths
                            )
                        else:
                            access_log_paths.extend(
                                path
                                for path in custom_log.parent.glob(f"{custom_log.name}*")
                                if path not in access_log_paths
                            )
                    except IndexError:
                        self.target.log.warning("Unexpected Apache log configuration: %s (%s)", line, path)

        return access_log_paths, error_log_paths

    @plugin.export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of Apache access log files in unified WebserverAccessLogRecord format."""
        for line, path in self._iterate_log_lines(self.access_log_paths):
            try:
                fmt = infer_access_log_format(line)
                if not fmt:
                    self.target.log.warning("Apache log format could not be inferred for log line: %s (%s)", line, path)
                    continue

                match = fmt.value.match(line)
                if not match:
                    self.target.log.warning(
                        "Could not match Apache log format %s for log line: %s (%s)", fmt, line, path
                    )
                    continue

                log = match.groupdict()
                response_time = log.get("response_time")
                if response_time:
                    response_time = apache_response_time_to_ms(response_time)
                yield WebserverAccessLogRecord(
                    ts=datetime.strptime(log["ts"], "%d/%b/%Y:%H:%M:%S %z"),
                    remote_user=log["remote_user"],
                    remote_ip=log["remote_ip"],
                    local_ip=log.get("local_ip"),
                    method=log["method"],
                    uri=log["uri"],
                    protocol=log["protocol"],
                    status_code=log["status_code"],
                    bytes_sent=log["bytes_sent"].strip("-") or 0,
                    pid=log.get("pid"),
                    referer=log.get("referer"),
                    useragent=log.get("useragent"),
                    response_time_ms=response_time,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("An error occured parsing Apache log file %s: %s", path, str(e))
                self.target.log.debug("", exc_info=e)

    @plugin.export(record=WebserverAccessLogRecord)
    def error(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of Apache error log files in unified WebserverErrorLogRecord format."""
        for line, path in self._iterate_log_lines(self.error_log_paths):
            try:
                match = LogFormat.COMMON_ERROR.value.match(line)
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

                yield WebserverErrorLogRecord(
                    ts=datetime.strptime(log["ts"], "%a %b %d %H:%M:%S.%f %Y"),
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

    def _iterate_log_lines(self, paths: list[Path]) -> Iterator[Tuple[str, Path]]:
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
