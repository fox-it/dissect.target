import re
from datetime import datetime
from enum import Enum
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import Iterator, Union

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export

_TS_REGEX = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
RE_TS = re.compile(_TS_REGEX)
RE_TS_AND_HOSTNAME = re.compile(_TS_REGEX + r"\s\S+\s")


class AuthLogServicesEnum(str, Enum):
    cron = "CRON"
    su = "su"
    sudo = "sudo"
    sshd = "sshd"
    systemd = "systemd"
    systemd_logind = "systemd-logind"
    pkexec = "pkexec"


class AuthLogRecordBuilder:
    RECORD_NAME = "linux/log/auth"
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
    # sudo regular expressions
    SUDO_COMMAND_REGEX = re.compile(
        r"TTY=(?P<tty>\w+\/\w+)\s;\s"  # The TTY -> TTY=pts/0 ;
        r"PWD=(?P<pwd>[\/\w]+)\s;\s"  # The current working directory -> PWD="/home/user" ;
        r"USER=(?P<effective_user>\w+)\s;\s"  # The effective user -> USER=root ;
        r"COMMAND=(?P<command>.+)$"  # The command -> COMMAND=/usr/bin/whoami
    )
    # su regular expressions
    SU_BY_REGEX = re.compile(r"by\s([^\s]+)")
    SU_ON_REGEX = re.compile(r"on\s([^\s]+)")
    SU_COMMAND_REGEX = re.compile(r"'(.*?)'")
    # pkexec regular expressions
    PKEXEC_COMMAND_REGEX = re.compile(
        r"(?P<user>.*?):\sExecuting\scommand\s"  # Starts with actual user -> user:
        r"\[USER=(?P<effective_user>[^\]]+)\]\s"  # The impersonated user -> [USER=root]
        r"\[TTY=(?P<tty>[^\]]+)\]\s"  # The tty -> [TTY=unknown]
        r"\[CWD=(?P<cwd>[^\]]+)\]\s"  # Current working directory -> [CWD=/home/user]
        r"\[COMMAND=(?P<command>[^\]]+)\]"  # Command performed -> [COMMAND=/usr/lib/example]
    )
    # sshd regular expressions
    SSHD_PORT_REGEX = re.compile(r"port\s(\d+)")
    USER_REGEX = re.compile(r"for\s([^\s]+)")
    # systemd-logind regular expressions
    SYSTEMD_LOGIND_WATCHING_REGEX = re.compile(
        r"(?P<action>Watching\ssystem\sbuttons)\s"  # Action is "Watching system buttons"
        r"on\s(?P<device>[^\s]+)\s"  # The device the button is related to -> /dev/input/event0
        r"\((?P<device_name>.*?)\)"  # The device (button) name -> "(Power button)"
    )

    def __init__(self, target: Target):
        self._create_event_descriptor = lru_cache(4096)(self._create_event_descriptor)
        self.target = target

    def _parse_sshd_message(self, message: str) -> dict[str, Union[str, int]]:
        """Parse message from sshd"""
        additional_fields = {}
        if ip_address := self.IPV4_ADDRESS_REGEX.search(message):
            field_name = "host_ip" if "listening" in message else "remote_ip"
            additional_fields[field_name] = ip_address.group(0)
        if port := self.SSHD_PORT_REGEX.search(message):
            additional_fields["port"] = int(port.group(1))
        if user := self.USER_REGEX.search(message):
            additional_fields["user"] = user.group(1)
        # Accepted publickey for test_user from 8.8.8.8 IP port 12345 ssh2: RSA SHA256:123456789asdfghjklöertzuio
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

    def _parse_systemd_logind_message(self, message: str) -> dict[str, str]:
        """Parse auth log message from systemd-logind"""
        additional_fields = {}
        # Example: Nov 14 07:14:09 ubuntu-1 systemd-logind[4]: Removed session 4.
        if "Removed" in message:
            additional_fields["action"] = "removed session"
            additional_fields["session"] = message.split()[-1].strip(".")
        elif "Watching" in message and (match := self.SYSTEMD_LOGIND_WATCHING_REGEX.search(message)):
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

    def _parse_sudo_message(self, message: str) -> dict[str, str]:
        """Parse auth log message from sudo"""
        if not (match := self.SUDO_COMMAND_REGEX.search(message)):
            return {}

        additional_fields = {}
        for key, value in match.groupdict().items():
            additional_fields[key] = value

        return additional_fields

    def _parse_su_message(self, message: str) -> dict[str, str]:
        additional_fields = {}
        if user := self.USER_REGEX.search(message):
            additional_fields["user"] = user.group(1)
        if by := self.SU_BY_REGEX.search(message):
            additional_fields["by"] = by.group(1)
        if on := self.SU_ON_REGEX.search(message):
            additional_fields["device"] = on.group(1)
        if command := self.SU_COMMAND_REGEX.search(message):
            additional_fields["command"] = command.group(1)
        if (failed := "failed" in message) or "Successful" in message:
            additional_fields["su_result"] = "failed" if failed else "success"

        return additional_fields

    def _parse_pkexec_message(self, message: str) -> dict[str, str]:
        """Parse auth log message from pkexec"""
        additional_fields = {}
        if exec_cmd := self.PKEXEC_COMMAND_REGEX.search(message):
            additional_fields["action"] = "executing command"
            for key, value in exec_cmd.groupdict().items():
                if value and value.isdigit():
                    value = int(value)
                additional_fields[key] = value

        return additional_fields

    def _parse_pam_unix_message(self, message: str) -> dict[str, str]:
        """Parse auth log message from pluggable authentication modules (PAM)"""
        if not (match := self.PAM_UNIX_REGEX.search(message)):
            return {}

        additional_fields = {}
        for key, value in match.groupdict().items():
            if value and value.isdigit():
                value = int(value)
            additional_fields[key] = value

        return additional_fields

    def _parse_additional_fields(self, service: str, message: str) -> dict[str, any]:
        """Parse additional fields in the message based on the service"""
        if service not in [item.value for item in AuthLogServicesEnum] and "pam_unix(" not in message:
            self.target.log.debug("Service %s is not recognised, no additional fields could be parsed", service)
            return {}

        additional_fields = {}
        try:
            if "pam_unix(" in message:
                additional_fields.update(self._parse_pam_unix_message(message))
            elif service == AuthLogServicesEnum.sshd:
                additional_fields.update(self._parse_sshd_message(message))
            elif service == AuthLogServicesEnum.sudo:
                additional_fields.update(self._parse_sudo_message(message))
            elif service == AuthLogServicesEnum.su:
                additional_fields.update(self._parse_su_message(message))
            elif service == AuthLogServicesEnum.systemd_logind:
                additional_fields.update(self._parse_systemd_logind_message(message))
            elif service == AuthLogServicesEnum.pkexec:
                additional_fields.update(self._parse_pkexec_message(message))
        except Exception as e:
            self.target.log.warning(
                "Parsing additional fields in message '%s' for service %s failed", message, service, exc_info=e
            )
            self.target.log.debug("", exc_info=e)

        return additional_fields

    def build_record(self, ts: datetime, source: Path, service: str, pid: int, message: str) -> TargetRecordDescriptor:
        """Builds an AuthLog event record"""
        record_fields = [
            ("datetime", "ts"),
            ("path", "source"),
            ("string", "service"),
            # PID should be string, since it can be "None"
            ("string", "pid"),
            ("string", "message"),
        ]

        record_values = {}
        record_values["ts"] = ts
        record_values["source"] = source
        record_values["service"] = service
        record_values["pid"] = pid
        record_values["message"] = message
        record_values["_target"] = self.target

        for key, value in self._parse_additional_fields(service, message).items():
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
    def __init__(self, target: Target):
        super().__init__(target)
        self.target
        self._auth_log_builder = AuthLogRecordBuilder(target)

    def check_compatible(self) -> None:
        var_log = self.target.fs.path("/var/log")
        if not any(var_log.glob("auth.log*")) and not any(var_log.glob("secure*")):
            raise UnsupportedPluginError("No auth log files found")

    @export(record=DynamicDescriptor(["datetime", "path", "string"]))
    def securelog(self) -> Iterator[any]:
        """Return contents of /var/log/auth.log* and /var/log/secure*."""
        return self.authlog()

    @export(record=DynamicDescriptor(["datetime", "path", "string"]))
    def authlog(self) -> Iterator[any]:
        """Return contents of /var/log/auth.log* and /var/log/secure*."""

        # Assuming no custom date_format template is set in syslog-ng or systemd (M d H:M:S)
        # CentOS format: Jan 12 13:37:00 hostname daemon: message
        # Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message

        tzinfo = self.target.datetime.tzinfo

        var_log = self.target.fs.path("/var/log")
        for auth_file in chain(var_log.glob("auth.log*"), var_log.glob("secure*")):
            for idx, (ts, line) in enumerate(year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", tzinfo)):
                ts_and_hostname = re.search(RE_TS_AND_HOSTNAME, line)
                if not ts_and_hostname:
                    self.target.log.warning("No timestamp and hostname found on line %d for file %s.", idx, auth_file)
                    self.target.log.debug("Skipping line %d: %s", idx, line)
                    continue

                info = line.replace(ts_and_hostname.group(0), "").strip()
                service, _message = info.split(":", maxsplit=1)
                message = _message.strip()
                # Get the PID, if present. Example: CRON[1] --> pid=1
                pid = None
                if "[" in service:
                    service, _pid = service.split("[")[:2]
                    pid = _pid.strip("]")

                yield self._auth_log_builder.build_record(ts, auth_file, service, pid, message)
