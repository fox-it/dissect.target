import re
from itertools import chain
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export

AuthLogRecord = TargetRecordDescriptor(
    "linux/log/auth",
    [
        ("datetime", "ts"),
        ("string", "service"),
        ("string", "processid"),
        ("string", "message"),
        ("string", "user"),
        ("string", "remoteip"),
        ("string", "port"),
        ("string", "authservice"),
        ("string", "protocol"),
        ("string", "encryption"),
        ("string", "method"),
        ("string", "key"),
        ("string", "misc"),
        ("string", "sessionmode"),
        ("string", "userid"),
        ("string", "useridassociate"),
        ("string", "tty"),
        ("string", "pwd"),
        ("string", "usereffective"),
        ("string", "command"),
        ("string", "cron"),
        ("string", "conectionmode"),
        ("path", "source"),
    ],
)

# Timestamp Regex
_TS_REGEX = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
RE_TS = re.compile(_TS_REGEX)
RE_TS_AND_HOSTNAME = re.compile(_TS_REGEX + r"\s\S+\s")


# New regex pattern for getting the log entries
# Mar 29 10:43:01 my_unix_host ...
RE_ENTRY = re.compile(r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(?P<service>[0-9A-Za-z\-\-\(\)=]*)?\[?(?P<processid>\w*)?\]?:\s+(?P<message>.+)')

# New regex pattern for interpreting the SSH message "Accepted password"
# Mar 29 10:43:01 my_unix_host sshd[1193]: Accepted password for test_user from 127.0.0.1 port 52942 ssh2
RE_SSH_ACCEPTED_PASSWORD = re.compile(r'^Accepted\spassword\sfor\s(?P<user>[\S\_]+)\sfrom\s(?P<remoteip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4})\sport\s(?P<port>[0-9]{1,5})\s(?P<authservice>\w+)$')

# New regex pattern for interpreting the SSH message "Accepted publickey"
# Accepted publickey for test_user from 123.123.123.123 port 12345 ssh2: RSA SHA256:123456789asdfghjklöertzuio
RE_SSH_ACCEPTED_PUBLICKEY = re.compile(r'^Accepted\spublickey\sfor\s(?P<user>\S+)\sfrom\s(?P<remoteip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4})\sport\s(?P<port>[0-9]{1,5})\s(?P<protocol>\w+):\s(?P<encryption>[\w\-]+)\s(?P<method>[\w]+):(?P<key>[\w:]+)(?P<misc>.*)$')

# New regex pattern for interpreting the PAM UNIX message "ssh"
# Jul  5 13:20:15 test-VirtualBox sudo: pam_unix(sudo:session): session opened for user root(uid=0) by test(uid=0)
RE_SSH_PAM_UNIX = re.compile(r'pam_unix\((?P<authservice>sshd):.*\): +session +(?P<sessionmode>closed|opened)\sfor\suser\s(?P<user>\w+)(?:\(uid=(?P<useridassociate>\w+)\))?(?:\sby\s)?(?:\(uid=(?P<userid>\w+)\))?$')

# New regex pattern for interpreting the connection mode on close message "ssh"
# Mar 29 17:07:19 my_unix_host sshd[4649]: Connection closed by 85.245.107.41 port 54790 [preauth]
RE_SSH_CONNECTION = re.compile(r'^Connection\s(?P<conectionmode>closed)\sby\s(?P<remoteip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4}:[0-9a-zA-Z]{0,4})\sport\s(?P<port>[0-9]{1,5})$(?P<misc>.*)$')

# New regex pattern for interpreting the command from message "sudo"
# Jul  4 17:10:18 my_unix_host sudo:     test : TTY=pts/0 ; PWD=/home/test ; USER=root ; COMMAND=/usr/bin/apt update
RE_SUDO_COMMAND = re.compile(r'^(?P<user>\w+)\s:\sTTY=(?P<tty>\w+\/\w+)\s;\sPWD=(?P<pwd>[\/\w]+)\s;\sUSER=(?P<usereffective>\w+)\s;\sCOMMAND=(?P<command>.+)$')

# New regex pattern for interpreting the session message "cron"
# Mar 29 17:07:25 my_unix_host sshd[4651]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
RE_CRON_PAM_UNIX = re.compile(r'^pam_unix\(cron:(?P<cron>.*)\): +session +(?P<sessionmode>closed|opened)\sfor\suser\s(?P<user>\w+)(?:\(uid=(?P<useridassociate>\w+)\))?(?:\sby\s)?(?:\(uid=(?P<userid>\w+)\))?$')

class AuthPlugin(Plugin):
    def check_compatible(self) -> None:
        var_log = self.target.fs.path("/var/log")
        if not any(var_log.glob("auth.log*")) and not any(var_log.glob("secure*")):
            raise UnsupportedPluginError("No auth log files found")

    def apply_regex_on_message(self, pattern, messsage):
        """Return a data object with the data from the group dict regex"""
        data = {}
        
        message_data = re.match(pattern, messsage)
        if message_data:
            data.update(message_data.groupdict())

        return data

    @export(record=[AuthLogRecord])
    def securelog(self) -> Iterator[AuthLogRecord]:
        """Return contents of /var/log/auth.log* and /var/log/secure*."""
        return self.authlog()

    @export(record=[AuthLogRecord])
    def authlog(self) -> Iterator[AuthLogRecord]:
        """Return contents of /var/log/auth.log* and /var/log/secure*."""

        # Assuming no custom date_format template is set in syslog-ng or systemd (M d H:M:S)
        # CentOS format: Jan 12 13:37:00 hostname daemon: message
        # Debian format: Jan 12 13:37:00 hostname daemon[pid]: pam_unix(daemon:session): message

        tzinfo = self.target.datetime.tzinfo

        var_log = self.target.fs.path("/var/log")
        for auth_file in chain(var_log.glob("auth.log*"), var_log.glob("secure*")):
            for ts, line in year_rollover_helper(auth_file, RE_TS, "%b %d %H:%M:%S", tzinfo):
                data = {
                    'ts': ts,
                }

                log_entry = re.match(RE_ENTRY, line)
                if not log_entry:
                    self.target.log.warning("Log entry does not match with pattern %s.", auth_file)
                    self.target.log.warning("Skipping this line: %s", line)
                    continue
                
                data.update(log_entry.groupdict())

                data.update(self.apply_regex_on_message(RE_SSH_ACCEPTED_PASSWORD, log_entry["message"]))
                data.update(self.apply_regex_on_message(RE_SSH_ACCEPTED_PUBLICKEY, log_entry["message"]))
                data.update(self.apply_regex_on_message(RE_SSH_PAM_UNIX, log_entry["message"]))
                data.update(self.apply_regex_on_message(RE_SSH_CONNECTION, log_entry["message"]))
                data.update(self.apply_regex_on_message(RE_SUDO_COMMAND, log_entry["message"]))
                data.update(self.apply_regex_on_message(RE_CRON_PAM_UNIX, log_entry["message"]))

                data.update({
                    'source': auth_file,
                    '_target': self.target
                })
                yield AuthLogRecord(
                    **data
                    )

