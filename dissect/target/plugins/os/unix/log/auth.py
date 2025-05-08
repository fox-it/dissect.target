from __future__ import annotations

import re
from abc import ABC, abstractmethod
from functools import lru_cache
from itertools import chain
from typing import TYPE_CHECKING, Any, Final

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.helpers.regex.ipaddress import extract_ips
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, alias, export
from dissect.target.plugins.os.unix.log.helpers import (
    RE_LINE,
    RE_TS,
    is_iso_fmt,
    iso_readlines,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from pathlib import Path

    from dissect.target.target import Target


RE_USER = re.compile(r"for ([^\s]+)")


class BaseService(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, message: str) -> dict[str, any]:
        pass


class SudoService(BaseService):
    """Parsing of sudo service messages in the auth log."""

    RE_SUDO_COMMAND = re.compile(
        r"""
        TTY=(?P<tty>\w+\/\w+)\s;\s          # The TTY -> TTY=pts/0 ;
        PWD=(?P<pwd>[\/\w]+)\s;\s           # The current working directory -> PWD="/home/user" ;
        USER=(?P<effective_user>\w+)\s;\s   # The effective user -> USER=root ;
        COMMAND=(?P<command>.+)$            # The command -> COMMAND=/usr/bin/whoami
        """,
        re.VERBOSE,
    )

    @classmethod
    def parse(cls, message: str) -> dict[str, str]:
        """Parse auth log message from sudo."""
        if not (match := cls.RE_SUDO_COMMAND.search(message)):
            return {}

        return match.groupdict()


class SshdService(BaseService):
    """Class for parsing sshd messages in the auth log."""

    RE_SSHD_PORTREGEX = re.compile(r"port\s(\d+)")
    RE_USER = re.compile(r"for\s([^\s]+)")

    @classmethod
    def parse(cls, message: str) -> dict[str, str | int]:
        """Parse message from sshd."""
        additional_fields = {}
        if ip_address := extract_ips(message):
            field_name = "host_ip" if "listening" in message else "remote_ip"

            if len(ip_address) > 1:
                field_name += "s"

            additional_fields[field_name] = ip_address[0] if len(ip_address) == 1 else ip_address

        if port := cls.RE_SSHD_PORTREGEX.search(message):
            additional_fields["port"] = int(port.group(1))
        if user := cls.RE_USER.search(message):
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
    """Class for parsing systemd-logind messages in the auth log."""

    RE_SYSTEMD_LOGIND_WATCHING = re.compile(
        r"""
        (?P<action>Watching\ssystem\sbuttons)\s # Action is "Watching system buttons"
        on\s(?P<device>[^\s]+)\s                # The device the button is related to -> /dev/input/event0
        \((?P<device_name>.*?)\)                # The device (button) name -> (Power button)
        """,
        re.VERBOSE,
    )

    @classmethod
    def parse(cls, message: str) -> dict[str, str]:
        """Parse auth log message from systemd-logind."""
        additional_fields = {}
        # Example: Nov 14 07:14:09 ubuntu-1 systemd-logind[4]: Removed session 4.
        if "Removed" in message:
            additional_fields["action"] = "removed session"
            additional_fields["session"] = message.split()[-1].strip(".")
        elif "Watching" in message and (match := cls.RE_SYSTEMD_LOGIND_WATCHING.search(message)):
            additional_fields.update(match.groupdict())
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
    """Class for parsing su messages in the auth log."""

    RE_SU_BY = re.compile(r"by\s([^\s]+)")
    RE_SU_ON = re.compile(r"on\s([^\s]+)")
    RE_SU_COMMAND = re.compile(r"'(.*?)'")

    @classmethod
    def parse(cls, message: str) -> dict[str, str]:
        additional_fields = {}
        if user := RE_USER.search(message):
            additional_fields["user"] = user.group(1)
        if by := cls.RE_SU_BY.search(message):
            additional_fields["by"] = by.group(1)
        if on := cls.RE_SU_ON.search(message):
            additional_fields["device"] = on.group(1)
        if command := cls.RE_SU_COMMAND.search(message):
            additional_fields["command"] = command.group(1)
        if (failed := "failed" in message) or "Successful" in message:
            additional_fields["su_result"] = "failed" if failed else "success"

        return additional_fields


class PkexecService(BaseService):
    """Class for parsing pkexec messages in the auth log."""

    RE_PKEXEC_COMMAND = re.compile(
        r"""
        (?P<user>\S+?):\sExecuting\scommand\s   # Starts with actual user -> user:
        \[USER=(?P<effective_user>[^\]]+)\]\s   # The impersonated user -> [USER=root]
        \[TTY=(?P<tty>[^\]]+)\]\s               # The tty -> [TTY=unknown]
        \[CWD=(?P<cwd>[^\]]+)\]\s               # Current working directory -> [CWD=/home/user]
        \[COMMAND=(?P<command>[^\]]+)\]         # Command -> [COMMAND=/usr/lib/example]
        """,
        re.VERBOSE,
    )

    @classmethod
    def parse(cls, message: str) -> dict[str, str]:
        """Parse auth log message from pkexec."""
        additional_fields = {}
        if exec_cmd := cls.RE_PKEXEC_COMMAND.search(message):
            additional_fields["action"] = "executing command"
            for key, value in exec_cmd.groupdict().items():
                if value and value.isdigit():
                    value = int(value)
                additional_fields[key] = value

        return additional_fields


class PamUnixService(BaseService):
    RE_PAM_UNIX = re.compile(
        r"""
        pam_unix\([^\s]+:session\):\s(?P<action>session\s\w+)\s     # Session action, usually opened or closed
        for\suser\s(?P<user>[^\s\(]+)(?:\(uid=(?P<user_uid>\d+)\))? # User may contain uid like: root(uid=0)
        (?:\sby\s\(uid=(?P<by_uid>\d+)\))?$                         # Opened action also contains by
        """,
        re.VERBOSE,
    )

    @classmethod
    def parse(cls, message: str) -> dict[str, str | int]:
        """Parse auth log message from pluggable authentication modules (PAM)."""
        if not (match := cls.RE_PAM_UNIX.search(message)):
            return {}

        additional_fields = {}
        for key, value in match.groupdict().items():
            if value and value.isdigit():
                value = int(value)
            additional_fields[key] = value

        return additional_fields


class AuthLogRecordBuilder:
    """Class for dynamically creating auth log records."""

    RECORD_NAME = "linux/log/auth"
    SERVICES: Final[dict[str, BaseService]] = {
        "su": SuService,
        "sudo": SudoService,
        "sshd": SshdService,
        "systemd-logind": SystemdLogindService,
        "pkexec": PkexecService,
    }

    def __init__(self, target: Target):
        self._create_event_descriptor = lru_cache(4096)(self._create_event_descriptor)
        self.target = target

    def _parse_additional_fields(self, service: str | None, message: str) -> dict[str, Any]:
        """Parse additional fields in the message based on the service."""
        if "pam_unix(" in message:
            return PamUnixService.parse(message)

        if service not in self.SERVICES:
            self.target.log.debug("Service %s is not recognised, no additional fields could be parsed", service)
            return {}

        try:
            return self.SERVICES[service].parse(message)
        except Exception as e:
            self.target.log.warning("Parsing additional fields in message '%s' for service %s failed", message, service)
            self.target.log.debug("", exc_info=e)
            raise

    def build_record(self, ts: datetime, source: Path, line: str) -> TargetRecordDescriptor:
        """Builds an ``AuthLog`` event record."""

        record_fields = [
            ("datetime", "ts"),
            ("path", "source"),
            ("string", "service"),
            ("varint", "pid"),
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

        match = RE_LINE.search(line)
        if match:
            record_values.update(match.groupdict())

        for key, value in self._parse_additional_fields(record_values["service"], line).items():
            record_type = "string"

            if isinstance(value, int):
                record_type = "varint"

            elif key.startswith(("remote_ip", "host_ip")):
                record_type = "net.ipaddress"

            if isinstance(value, list):
                record_type += "[]"

            record_fields.append((record_type, key))
            record_values[key] = value

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    def _create_event_descriptor(self, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(self.RECORD_NAME, record_fields)


class AuthPlugin(Plugin):
    """Unix authentication log plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._auth_log_builder = AuthLogRecordBuilder(target)

    def check_compatible(self) -> None:
        if not any(self._get_paths()):
            raise UnsupportedPluginError("No auth log files found")

    def _get_paths(self) -> Iterator[Path]:
        var_log = self.target.fs.path("/var/log")
        return chain(var_log.glob("auth.log*"), var_log.glob("secure*"))

    @alias("securelog")
    @export(record=DynamicDescriptor(["datetime", "path", "string"]))
    def authlog(self) -> Iterator[Any]:
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
        target_tz = self.target.datetime.tzinfo

        for auth_file in self.get_paths():
            if is_iso_fmt(auth_file):
                iterable = iso_readlines(auth_file)
            else:
                iterable = year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", target_tz)

            for ts, line in iterable:
                yield self._auth_log_builder.build_record(ts, auth_file, line)
