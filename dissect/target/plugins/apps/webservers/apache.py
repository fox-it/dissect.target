import enum
import itertools
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from dissect.target import plugin
from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverAccessLogRecord
from dissect.target.target import Target

COMMON_REGEX = r'(?P<remote_ip>.*?) (?P<remote_logname>.*?) (?P<remote_user>.*?) \[(?P<ts>.*)\] "(?P<method>.*?) (?P<uri>.*?) ?(?P<protocol>HTTP\/.*?)?" (?P<status_code>\d{3}) (?P<bytes_sent>-|\d+)'  # noqa: E501
REFERER_USER_AGENT_REGEX = r'"(?P<referer>.*?)" "(?P<useragent>.*?)"'


class LogFormat(enum.Enum):
    VHOST_COMBINED = re.compile(rf"(?P<server_name>.*?):(?P<port>.*) {COMMON_REGEX} {REFERER_USER_AGENT_REGEX}")
    COMBINED = re.compile(rf"{COMMON_REGEX} {REFERER_USER_AGENT_REGEX}")
    COMMON = re.compile(COMMON_REGEX)


def infer_log_format(line: str) -> Optional[LogFormat]:
    """Attempt to infer what standard LogFormat is used. Returns None if no known format can be inferred.

    Three default log type examples from Apache (note that the ipv4 could also be ipv6)::
        combined       = '1.2.3.4 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0
                          (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0
                          Safari/537.36"'
        common         = '1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312'
        vhost_combined = 'example.com:80 1.2.3.4 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 "-"
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko)
                          Chrome/108.0.0.0 Safari/537.36"'
    """

    first_part = line.split(" ")[0]
    if ":" in first_part and "." in first_part:
        # does not start with IP, hence it must be a vhost typed log
        return LogFormat.VHOST_COMBINED
    elif line[-1:] == '"':
        # ends with a quotation mark, meaning three is a user agent
        return LogFormat.COMBINED
    elif line[-1:].isdigit():
        return LogFormat.COMMON
    return None


class ApachePlugin(plugin.Plugin):
    """Apache log parsing plugin.

    Apache has three default log formats, which this plugin can all parse automatically. These are::
        LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
        LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
        LogFormat "%h %l %u %t \"%r\" %>s %O" common

    For the definitions of each format string, see https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats
    """

    __namespace__ = "apache"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    def check_compatible(self) -> bool:
        return len(self.log_paths) > 0

    @plugin.internal
    def get_log_paths(self) -> list[Path]:
        """
        Discover any present Apache log paths on the target system.

        References:
            - https://www.cyberciti.biz/faq/apache-logs/
            - https://unix.stackexchange.com/a/269090
        """

        log_paths = []

        # Check if any well known default Apache log locations exist
        default_log_dirs = ["/var/log/apache2", "/var/log/apache", "/var/log/httpd", "/var/log"]
        default_log_names = ["access.log", "access_log", "httpd-access.log"]
        for log_dir, log_name in itertools.product(default_log_dirs, default_log_names):
            log_paths.extend(self.target.fs.path(log_dir).glob(log_name + "*"))

        # Check default Apache configs for their CustomLog directive
        default_config_paths = [
            "/etc/apache2/apache2.conf",
            "/usr/local/etc/apache22/httpd.conf",
            "/etc/httpd/conf/httpd.conf",
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
                        log_paths.extend(
                            path for path in custom_log.parent.glob(f"{custom_log.name}*") if path not in log_paths
                        )
                    except IndexError:
                        self.target.log.warning("Unexpected Apache log configuration: %s (%s)", line, path)

        return log_paths

    @plugin.export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return contents of Apache access log files in unified WebserverAccessLogRecord format."""
        for path in self.log_paths:
            try:
                path = path.resolve(strict=True)
                for line in open_decompress(path, "rt"):
                    line = line.strip()
                    if not line:
                        continue

                    fmt = infer_log_format(line)
                    if not fmt:
                        self.target.log.warning(
                            "Apache log format could not be inferred for log line: %s (%s)", line, path
                        )
                        continue

                    match = fmt.value.match(line)
                    if not match:
                        self.target.log.warning(
                            "Could not match Apache log format %s for log line: %s (%s)", fmt, line, path
                        )
                        continue

                    log = match.groupdict()
                    yield WebserverAccessLogRecord(
                        ts=datetime.strptime(log["ts"], "%d/%b/%Y:%H:%M:%S %z"),
                        remote_user=log["remote_user"],
                        remote_ip=log["remote_ip"],
                        method=log["method"],
                        uri=log["uri"],
                        protocol=log["protocol"],
                        status_code=log["status_code"],
                        bytes_sent=log["bytes_sent"].strip("-") or 0,
                        referer=log.get("referer"),
                        useragent=log.get("useragent"),
                        source=path,
                        _target=self.target,
                    )
            except FileNotFoundError:
                self.target.log.warning("Apache log file configured but could not be found (dead symlink?): %s", path)
            except Exception as e:
                self.target.log.warning("An error occured parsing Apache log file %s: %s", path, str(e))
                self.target.log.debug("", exc_info=e)
