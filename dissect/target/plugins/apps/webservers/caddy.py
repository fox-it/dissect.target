import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dissect.util.ts import from_unix

from dissect.target import plugin
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverAccessLogRecord
from dissect.target.target import Target

LOG_FILE_REGEX = re.compile(r"(log|output file) (?P<log_file>.*)( \{)?$")
LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - - \[(?P<ts>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<request>.*?)" (?P<status_code>\d{3}) (?P<bytes_sent>\d+)'  # noqa: E501
)


class CaddyPlugin(plugin.Plugin):
    __namespace__ = "caddy"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    @plugin.internal
    def get_log_paths(self) -> list[Path]:
        log_paths = []
        default_log_file = self.target.fs.path("/var/log/caddy_access.log")
        if default_log_file.exists():
            log_paths.append(default_log_file)

        # Check for custom paths in Caddy config
        if (config_file := self.target.fs.path("/etc/caddy/Caddyfile")).exists():
            found_roots = []
            for line in config_file.open("rt"):
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if "root " in line:
                    found_roots.append(line.split("root ")[1].strip())

                if "log " in line or "output file " in line:
                    if line.strip() == "log {":
                        continue

                    match = LOG_FILE_REGEX.match(line)
                    if not match:
                        self.target.log.warning("Could not determine log path in line %s", line)
                        continue

                    match = match.groupdict()
                    p = match["log_file"].replace(" {", "").split(" ")[-1]

                    if not p.startswith("/"):
                        for root in found_roots:
                            root_parent = self.target.fs.path(root).parent
                            abs_log_path = self.target.fs.path(root_parent).joinpath(p).parent
                            if abs_log_path.exists() and abs_log_path not in log_paths:
                                log_paths.append(abs_log_path)
                    else:
                        if (path := self.target.fs.path(p).parent).exists():
                            if path not in log_paths:
                                log_paths.append(path)

        return log_paths

    def check_compatible(self) -> bool:
        return len(self.log_paths) > 0

    @plugin.export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Parses Caddy V1 CRF and Caddy V2 JSON logs.

        Resources:
            - https://caddyserver.com/docs/caddyfile/directives/log#format-modules
        """
        tzinfo = self.target.datetime.tzinfo

        for path in self.log_paths:
            for line in open_decompress(path, "rt"):
                line = line.strip()
                if not line:
                    continue

                # Parse a JSON log line
                if line.startswith('{"'):
                    try:
                        log = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        self.target.log.warning("Could not decode Caddy JSON log line in file %s", path)
                        continue

                    yield WebserverAccessLogRecord(
                        ts=from_unix(log["ts"]).replace(tzinfo=tzinfo),
                        remote_ip=log["request"]["remote_ip"],
                        request=f"{log['request']['method']} {log['request']['uri']} {log['request']['proto']}",
                        status_code=log["status"],
                        bytes_sent=log["size"],
                        source=path.resolve(),
                        _target=self.target,
                    )

                # Try to parse a CLF log line
                else:
                    match = LOG_REGEX.match(line)
                    if not match:
                        self.target.log.warning(
                            "Could not match Caddy webserver log line with regex format for log line '%s'", line
                        )
                        continue
                    log = match.groupdict()

                    yield WebserverAccessLogRecord(
                        ts=datetime.strptime(log["ts"], "%d/%b/%Y:%H:%M:%S %z"),
                        remote_ip=log["remote_ip"],
                        request=log["request"],
                        status_code=log["status_code"],
                        bytes_sent=log["bytes_sent"],
                        source=path.resolve(),
                        _target=self.target,
                    )
