import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dissect.util.ts import from_unix

from dissect.target import plugin
from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.fsutil import basename, open_decompress
from dissect.target.plugins.apps.webservers.webservers import WebserverAccessLogRecord
from dissect.target.target import Target

LOG_FILE_REGEX = re.compile(r"(log|output file) (?P<log_file>.*)( \{)?$")
LOG_REGEX = re.compile(
    r'(?P<remote_ip>.*?) - - \[(?P<ts>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] "(?P<method>.*?) (?P<uri>.*?) ?(?P<protocol>HTTP\/.*?)?" (?P<status_code>\d{3}) (?P<bytes_sent>-|\d+)'  # noqa: E501
)


class CaddyPlugin(plugin.Plugin):
    __namespace__ = "caddy"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_paths = self.get_log_paths()

    def check_compatible(self) -> bool:
        return len(self.log_paths) > 0

    @plugin.internal
    def get_log_paths(self) -> list[Path]:
        log_paths = []

        # Add any well known default Caddy log locations
        log_paths.extend(self.target.fs.path("/var/log").glob("caddy_access.log*"))

        # Check for custom paths in Caddy config
        if (config_file := self.target.fs.path("/etc/caddy/Caddyfile")).exists():
            found_roots = []
            for line in config_file.open("rt"):
                line = line.strip()
                if not line:
                    continue

                if line.startswith("#"):
                    line = line[1:].strip()

                if "root " in line:
                    found_roots.append(line.split("root ")[1].strip())

                if "log " in line or "output file " in line:
                    if line == "log {":
                        continue

                    match = LOG_FILE_REGEX.match(line)
                    if not match:
                        self.target.log.warning("Could not determine log path in %s: %s", config_file, line)
                        continue

                    match = match.groupdict()
                    log_path = match["log_file"].replace(" {", "").split(" ")[-1]

                    parent_folders = []
                    # Search all root folders we found earlier with the current relative log path we found.
                    if log_path.startswith("/"):
                        parent_folders.append(self.target.fs.path(log_path).parent)
                    else:
                        if len(found_roots) == 0:
                            self.target.log.warning(
                                "Can not infer absolute log path from relative path: Caddyfile root is not configured."
                            )
                            continue

                        for root in found_roots:
                            # Logs will be located one folder higher than the defined root.
                            root_parent = self.target.fs.path(root).parent
                            parent_folders.append(root_parent.joinpath(log_path).parent)

                    for parent_folder in parent_folders:
                        log_paths.extend(
                            path for path in parent_folder.glob(f"{basename(log_path)}*") if path not in log_paths
                        )

        return log_paths

    @plugin.export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Parses Caddy V1 CRF and Caddy V2 JSON access logs.

        Resources:
            - https://caddyserver.com/docs/caddyfile/directives/log#format-modules
        """
        for path in self.log_paths:
            try:
                path = path.resolve(strict=True)
                for line in open_decompress(path, "rt"):
                    line = line.strip()
                    if not line:
                        continue

                    # Parse a JSON log line
                    if line.startswith('{"'):
                        try:
                            log = json.loads(line)
                        except json.decoder.JSONDecodeError:
                            self.target.log.warning("Could not decode Caddy JSON log line: %s (%s)", line, path)
                            continue

                        yield WebserverAccessLogRecord(
                            ts=from_unix(log["ts"]),
                            remote_ip=log["request"]["remote_ip"],
                            method=log["request"]["method"],
                            uri=log["request"]["uri"],
                            protocol=log["request"]["proto"],
                            status_code=log["status"],
                            bytes_sent=log["size"],
                            source=path,
                            _target=self.target,
                        )

                    # Try to parse a CLF log line
                    else:
                        match = LOG_REGEX.match(line)
                        if not match:
                            self.target.log.warning(
                                "Could not match Caddy regex format for log line: %s (%s)", line, path
                            )
                            continue

                        log = match.groupdict()
                        yield WebserverAccessLogRecord(
                            ts=datetime.strptime(log["ts"], "%d/%b/%Y:%H:%M:%S %z"),
                            remote_ip=log["remote_ip"],
                            method=log["method"],
                            uri=log["uri"],
                            protocol=log["protocol"],
                            status_code=log["status_code"],
                            bytes_sent=log["bytes_sent"].strip("-") or 0,
                            source=path,
                            _target=self.target,
                        )
            except FileNotFoundError:
                self.target.log.warning("Caddy log file configured but could not be found (dead symlink?): %s", path)
            except Exception as e:
                self.target.log.warning("An error occured parsing Caddy log file %s: %s", path, str(e))
                self.target.log.debug("", exc_info=e)
