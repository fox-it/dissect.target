from __future__ import annotations

import itertools
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import Iterator

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath, open_decompress
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, alias, export

log = logging.getLogger(__name__)

_RE_TS = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
_RE_TS_ISO = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2}"

RE_TS = re.compile(_RE_TS)
RE_TS_ISO = re.compile(_RE_TS_ISO)
RE_LINE = re.compile(
    rf"(?P<ts>{_RE_TS}|{_RE_TS_ISO})\s(?P<hostname>\S+)\s(?P<service>\S+?)(\[(?P<pid>\d+)\])?:\s(?P<message>.+)$"
)

# Generic regular expressions
IPV4_ADDRESS_REGEX = re.compile(
    r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"  # First three octets
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"  # Last octet
)
PAM_UNIX_REGEX = re.compile(
    r"pam_unix\([^\s]+:session\):\s(?P<action>session\s\w+) "  # Session action, usually opened or closed
    r"for\suser\s(?P<user>[^\s\(]+)(?:\(uid=(?P<user_uid>\d+)\))?"  # User may contain uid like: root(uid=0)
    r"(?:\sby\s\(uid=(?P<by_uid>\d+)\))?$"  # Opened action also contains this "by" addition
)
USER_REGEX = re.compile(r"for ([^\s]+)")


class BaseService(ABC):
    @classmethod
    @abstractmethod
    def parse_message(cls, message: str) -> dict[str, any]:
        pass


class SudoService(BaseService):
    """Class for parsing sudo service messages in the auth log"""

    SUDO_COMMAND_REGEX = re.compile(
        r"TTY=(?P<tty>\w+\/\w+)\s;\s"  # The TTY -> TTY=pts/0 ;
        r"PWD=(?P<pwd>[\/\w]+)\s;\s"  # The current working directory -> PWD="/home/user" ;
        r"USER=(?P<effective_user>\w+)\s;\s"  # The effective user -> USER=root ;
        r"COMMAND=(?P<command>.+)$"  # The command -> COMMAND=/usr/bin/whoami
    )

    @classmethod
    def parse_message(cls, message: str) -> dict[str, str]:
        """Parse auth log message from sudo"""
        if not (match := cls.SUDO_COMMAND_REGEX.search(message)):
            return {}

        additional_fields = {}
        for key, value in match.groupdict().items():
            additional_fields[key] = value

        return additional_fields


class SshdService(BaseService):
    """Class for parsing sshd messages in the auth log"""

    SSHD_PORT_REGEX = re.compile(r"port\s(\d+)")
    USER_REGEX = re.compile(r"for\s([^\s]+)")

    @classmethod
    def parse_message(cls, message: str) -> dict[str, str | int]:
        """Parse message from sshd"""
        additional_fields = {}
        if ip_address := IPV4_ADDRESS_REGEX.search(message):
            field_name = "host_ip" if "listening" in message else "remote_ip"
            additional_fields[field_name] = ip_address.group(0)
        if port := cls.SSHD_PORT_REGEX.search(message):
            additional_fields["port"] = int(port.group(1))
        if user := cls.USER_REGEX.search(message):
            additional_fields["user"] = user.group(1)
        # Accepted publickey for test_user from 8.8.8.8 IP port 12345 ssh2: RSA SHA256:123456789asdfghjklertzuio
        if "Accepted publickey" in message:
            ssh_protocol, encryption_algo, key_info = message.split()[-3:]
            hash_algo, key_hash = key_info.split(":")
            additional_fields["ssh_protocol"] = ssh_protocol.strip(":")
            additional_fields["encryption_algorithm"] = encryption_algo
            additional_fields["hash_algorithm"] = hash_algo
            additional_fields["key_hash"] = key_hash
        if (failed := "Failed" in message) or "Accepted" in message:
            action_type = "failed" if failed else "accepted"
            additional_fields["action"] = f"{action_type} authentication"
            additional_fields["authentication_type"] = "password" if "password" in message else "publickey"

        return additional_fields


class SystemdLogindService(BaseService):
    """Class for parsing systemd-logind messages in the auth log"""

    SYSTEMD_LOGIND_WATCHING_REGEX = re.compile(
        r"(?P<action>Watching\ssystem\sbuttons)\s"  # Action is "Watching system buttons"
        r"on\s(?P<device>[^\s]+)\s"  # The device the button is related to -> /dev/input/event0
        r"\((?P<device_name>.*?)\)"  # The device (button) name -> "(Power button)"
    )

    @classmethod
    def parse_message(cls, message: str):
        """Parse auth log message from systemd-logind"""
        additional_fields = {}
        # Example: Nov 14 07:14:09 ubuntu-1 systemd-logind[4]: Removed session 4.
        if "Removed" in message:
            additional_fields["action"] = "removed session"
            additional_fields["session"] = message.split()[-1].strip(".")
        elif "Watching" in message and (match := cls.SYSTEMD_LOGIND_WATCHING_REGEX.search(message)):
            for key, value in match.groupdict().items():
                additional_fields[key] = value
        # Example: New session 4 of user sampleuser.
        elif "New session" in message:
            parts = message.removeprefix("New session ").split()
            additional_fields["action"] = "new session"
            additional_fields["session"] = parts[0]
            additional_fields["user"] = parts[-1].strip(".")
        # Example: Session 4 logged out. Waiting for processes to exit.
        elif "logged out" in message:
            session = message.removeprefix("Session ").split(maxsplit=1)[0]
            additional_fields["action"] = "logged out session"
            additional_fields["session"] = session
        # Example: New seat seat0.
        elif "New seat" in message:
            seat = message.split()[-1].strip(".")
            additional_fields["action"] = "new seat"
            additional_fields["seat"] = seat

        return additional_fields


class SuService(BaseService):
    """Class for parsing su messages in the auth log"""

    SU_BY_REGEX = re.compile(r"by\s([^\s]+)")
    SU_ON_REGEX = re.compile(r"on\s([^\s]+)")
    SU_COMMAND_REGEX = re.compile(r"'(.*?)'")

    @classmethod
    def parse_message(cls, message: str) -> dict[str, str]:
        additional_fields = {}
        if user := USER_REGEX.search(message):
            additional_fields["user"] = user.group(1)
        if by := cls.SU_BY_REGEX.search(message):
            additional_fields["by"] = by.group(1)
        if on := cls.SU_ON_REGEX.search(message):
            additional_fields["device"] = on.group(1)
        if command := cls.SU_COMMAND_REGEX.search(message):
            additional_fields["command"] = command.group(1)
        if (failed := "failed" in message) or "Successful" in message:
            additional_fields["su_result"] = "failed" if failed else "success"

        return additional_fields


class PkexecService(BaseService):
    """Class for parsing pkexec messages in the auth log"""

    PKEXEC_COMMAND_REGEX = re.compile(
        r"(?P<user>\S+?):\sExecuting\scommand\s"  # Starts with actual user -> user:
        r"\[USER=(?P<effective_user>[^\]]+)\]\s"  # The impersonated user -> [USER=root]
        r"\[TTY=(?P<tty>[^\]]+)\]\s"  # The tty -> [TTY=unknown]
        r"\[CWD=(?P<cwd>[^\]]+)\]\s"  # Current working directory -> [CWD=/home/user]
        r"\[COMMAND=(?P<command>[^\]]+)\]"  # Command performed -> [COMMAND=/usr/lib/example]
    )

    @classmethod
    def parse_message(cls, message: str) -> dict[str, str]:
        """Parse auth log message from pkexec"""
        additional_fields = {}
        if exec_cmd := cls.PKEXEC_COMMAND_REGEX.search(message):
            additional_fields["action"] = "executing command"
            for key, value in exec_cmd.groupdict().items():
                if value and value.isdigit():
                    value = int(value)
                additional_fields[key] = value

        return additional_fields


class AuthLogRecordBuilder:
    """Class for dynamically creating auth log records"""

    RECORD_NAME = "linux/log/auth"
    SERVICES: dict[str, BaseService] = {
        "su": SuService,
        "sudo": SudoService,
        "sshd": SshdService,
        "systemd-logind": SystemdLogindService,
        "pkexec": PkexecService,
    }

    def __init__(self, target: Target):
        self._create_event_descriptor = lru_cache(4096)(self._create_event_descriptor)
        self.target = target

    def _parse_pam_unix_message(self, message: str) -> dict[str, str]:
        """Parse auth log message from pluggable authentication modules (PAM)"""
        if not (match := PAM_UNIX_REGEX.search(message)):
            return {}

        additional_fields = {}
        for key, value in match.groupdict().items():
            if value and value.isdigit():
                value = int(value)
            additional_fields[key] = value

        return additional_fields

    def _parse_additional_fields(self, service: str, message: str) -> dict[str, any]:
        """Parse additional fields in the message based on the service"""
        if "pam_unix(" in message:
            return self._parse_pam_unix_message(message)

        if service not in self.SERVICES:
            self.target.log.debug("Service %s is not recognised, no additional fields could be parsed", service)
            return {}

        try:
            service_class = self.SERVICES[service]
            return service_class.parse_message(message)
        except Exception as e:
            self.target.log.warning(
                "Parsing additional fields in message '%s' for service %s failed", message, service, exc_info=e
            )
            self.target.log.debug("", exc_info=e)
            raise e

    def build_record(self, ts: datetime, source: Path, line: str) -> TargetRecordDescriptor:
        """Builds an AuthLog event record"""

        record_fields = [
            ("datetime", "ts"),
            ("path", "source"),
            ("string", "service"),
            # PID should be string, since it can be "None"
            ("string", "pid"),
            ("string", "message"),
        ]

        record_values = {
            "ts": ts,
            "message": line,
            "service": None,
            "pid": None,
            "source": source,
            "_target": self.target,
        }

        match = RE_LINE.match(line)
        if match:
            values = match.groupdict()
            del values["ts"]
            values["message"] = values["message"].strip()
            record_values.update(values)

        for key, value in self._parse_additional_fields(record_values["service"], line).items():
            record_type = "string"
            if isinstance(value, int):
                record_type = "varint"

            record_fields.append((record_type, key))
            record_values[key] = value

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    def _create_event_descriptor(self, record_fields) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(self.RECORD_NAME, record_fields)


class AuthPlugin(Plugin):
    """Unix authentication log plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._auth_log_builder = AuthLogRecordBuilder(target)

    def check_compatible(self) -> None:
        var_log = self.target.fs.path("/var/log")
        if not any(var_log.glob("auth.log*")) and not any(var_log.glob("secure*")):
            raise UnsupportedPluginError("No auth log files found")

    @alias("securelog")
    @export(record=DynamicDescriptor(["datetime", "path", "string"]))
    def authlog(self) -> Iterator[any]:
        """Yield contents of ``/var/log/auth.log*`` and ``/var/log/secure*`` files.

        Order of returned events is not guaranteed to be chronological because of year
        rollover detection efforts for log files without a year in the timestamp.

        The following timestamp formats are recognised automatically. This plugin
        assumes that no custom ``date_format`` template is set in ``syslog-ng`` or ``systemd``
        configuration (defaults to ``M d H:M:S``).

        ISO formatted authlog entries are parsed as can be found in Ubuntu 24.04 and later.

        .. code-block:: text

            CentOS format: Jan 12 13:37:00 hostname daemon: message
            Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message
            Ubuntu  24.04: 2024-01-12T13:37:00.000000+02:00 hostname daemon[pid]: pam_unix(daemon:session): message

        Resources:
            - https://help.ubuntu.com/community/LinuxLogFiles
        """

        tzinfo = self.target.datetime.tzinfo

        var_log = self.target.fs.path("/var/log")
        for auth_file in chain(var_log.glob("auth.log*"), var_log.glob("secure*")):
            if is_iso_fmt(auth_file):
                iterable = iso_readlines(auth_file)

            else:
                iterable = year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", tzinfo)

            for ts, line in iterable:
                yield self._auth_log_builder.build_record(ts, auth_file, line)


def iso_readlines(file: TargetPath) -> Iterator[tuple[datetime, str]]:
    """Iterator reading the provided auth log file in ISO format. Mimics ``year_rollover_helper`` behaviour."""

    with open_decompress(file, "rt") as fh:
        for line in fh:
            if not (match := RE_TS_ISO.match(line)):
                log.warning("No timestamp found in one of the lines in %s!", file)
                log.debug("Skipping line: %s", line)
                continue

            try:
                ts = datetime.strptime(match[0], "%Y-%m-%dT%H:%M:%S.%f%z")

            except ValueError as e:
                log.warning("Unable to parse ISO timestamp in line: %s", line)
                log.debug("", exc_info=e)
                continue

            yield ts, line


def is_iso_fmt(file: TargetPath) -> bool:
    """Determine if the provided auth log file uses new ISO format logging or not."""
    return any(itertools.islice(iso_readlines(file), 0, 2))
