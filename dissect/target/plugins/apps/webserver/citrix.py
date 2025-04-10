from __future__ import annotations

import re

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.apps.webserver.apache import (
    RE_ACCESS_COMMON_PATTERN,
    RE_REFERER_USER_AGENT_PATTERN,
    RE_REMOTE_PATTERN,
    RE_RESPONSE_TIME_PATTERN,
    ApachePlugin,
    LogFormat,
)

LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME = LogFormat(
    "combined_resptime",
    re.compile(
        rf"""
        {RE_REMOTE_PATTERN}                  # remote_ip, remote_logname, remote_user
        \s
        {RE_ACCESS_COMMON_PATTERN}           # Timestamp, pid, method, uri, protocol, status code, bytes_sent
        \s
        {RE_REFERER_USER_AGENT_PATTERN}      # Referer, user_agent
        \s
        {RE_RESPONSE_TIME_PATTERN}           # Response time
        """,
        re.VERBOSE,
    ),
)

LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME_WITH_HEADERS = LogFormat(
    "combined_resptime_with_citrix_hdrs",
    re.compile(
        rf"""
        (?P<remote_ip>.*?)                   # Client IP address of the request.
        \s
        ->
        \s
        (?P<local_ip>.*?)                    # Local IP of the Netscaler.
        \s
        (?P<remote_logname>.*?)              # Remote logname (from identd, if supplied).
        \s
        (?P<remote_user>.*?)                 # Remote user if the request was authenticated.
        \s
        {RE_ACCESS_COMMON_PATTERN}           # Timestamp, pid, method, uri, protocol, status code, bytes_sent
        \s
        {RE_REFERER_USER_AGENT_PATTERN}      # Referer, user_agent
        \s
        {RE_RESPONSE_TIME_PATTERN}           # Response time
        """,
        re.VERBOSE,
    ),
)


class CitrixWebserverPlugin(ApachePlugin):
    """Apache log parsing plugin for Citrix specific logs.

    Citrix uses Apache with custom access log formats. These are::

        LogFormat "%{Citrix-ns-orig-srcip}i -> %{Citrix-ns-orig-destip}i %l %u %t [%P] \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"Time: %D microsecs\"" combined_resptime_with_citrix_hdrs
        LogFormat "%a %l %u %t [%P] \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"Time: %D microsecs\"" combined_resptime
    """  # noqa: E501

    __namespace__ = "citrix"

    ACCESS_LOG_NAMES = (*ApachePlugin.ACCESS_LOG_NAMES, "httpaccess.log", "httpaccess-vpn.log")
    ERROR_LOG_NAMES = (*ApachePlugin.ERROR_LOG_NAMES, "httperror.log", "httperror-vpn.log")

    def check_compatible(self) -> None:
        if not self.target.os == OperatingSystem.CITRIX:
            raise UnsupportedPluginError("Target is not a Citrix Netscaler")

    @staticmethod
    def infer_access_log_format(line: str) -> LogFormat:
        splitted_line = line.split()
        second_part = splitted_line[1]
        if second_part == "->":
            return LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME_WITH_HEADERS
        if "Time: " in line:
            return LOG_FORMAT_CITRIX_NETSCALER_ACCESS_COMBINED_RESPONSE_TIME

        return ApachePlugin.infer_access_log_format(line)
