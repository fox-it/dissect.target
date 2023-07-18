from __future__ import annotations

import functools
import ssl
import time
import urllib
from pathlib import Path
from platform import os
from typing import Union

from dissect.util.stream import AlignedStream
from flow.record import Record

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import FatalError, LoaderError
from dissect.target.loader import Loader
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

TARGETD_AVAILABLE = False
try:
    from flow import remoting
    from targetd.clients import Client

    TARGETD_AVAILABLE = True
except Exception:
    pass


class TargetdStream(AlignedStream):
    def _read(self, offset: int, length: int) -> bytes:
        return b""


# Marker interface to indicate this loader loads targets from remote machines
class ProxyLoader(Loader):
    pass


class TargetdInvalidStateError(FatalError):
    pass


class TargetdLoader(ProxyLoader):
    instance = None

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)
        self._plugin_func = None
        self.client = None
        self.output = None
        self.peers = 1
        self.cacert = None
        self.adapter = "Flow.Remoting"
        self.host = "localhost"
        self.port = 1883
        self.local_link = "unix:///tmp/targetd" if os.name == "posix" else "pipe:///tmp/targetd"
        # @todo Add these options to loader help (when available)
        self.configurables = [
            ["cacert", Path, "SSL: cacert file"],
            ["host", str, "IP-address of targetd broker"],
            ["port", int, "Port for connecting to targetd broker"],
            ["local_link", str, "Domain socket or named pipe"],
            ["adapter", str, "Adapter to use"],
            ["peers", int, "Minimum number of hosts to wait for before executing query"],
        ]
        uri = kwargs.get("parsed_path")
        if uri is None:
            raise LoaderError("No URI connection details have been passed.")
        self.uri = uri.path
        self.options = dict(urllib.parse.parse_qsl(uri.query, keep_blank_values=True))
        TargetdLoader.instance = self

    def _process_options(self, target: Target) -> None:
        for configurable_details in self.configurables:
            configurable, value_type, description = configurable_details
            configuration = self.options.get(configurable)
            if not configuration:
                default_value = getattr(self, configurable)
                target.log.warning("%s not configured, using: %s=%s", description, configurable, default_value)
            else:
                setattr(self, configurable, value_type(configuration))

    @export(output="record", cache=False)
    def plugin_bridge(self, plugin_func: str) -> list[Record]:
        """Command Execution Bridge Plugin for Targetd.

        This is a generic plugin interceptor that becomes active only if using
        the targetd loader. This plugin acts as a bridge to connect to the Targetd broker
        and will translate the requested plugin-operation into Targetd-commands using the selected
        adapter (i.e. Flow.Remoting).
        """

        if not TARGETD_AVAILABLE:
            raise ImportError("This loader requires the targetd package to be installed.")

        self.output = None
        self.has_output = False

        if self.client is None:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            if self.cacert and not self.cacert.exists():
                raise LoaderError(f"file not found: {self.cacert}")
            if self.cacert:
                ssl_context.load_verify_locations(self.cacert)
            else:
                ssl_context.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)
            self.client = Client(self.host, self.port, ssl_context, [self.uri], self.local_link, "targetd")
            self.client.module_fullname = "dissect.target.loaders"
            self.client.module_fromlist = ["command_runner"]
            self.client.command = plugin_func
            self.peers = self.peers
            try:
                self.client.start()
            except Exception:
                # If something happens that prevents targetd from properly closing/resetting the
                # connection, this exception is thrown during the next connection and the connection
                # is closed properly after all so that the next time the loader will be able to
                # use a new connection with a new session.
                self.client.close()
                raise TargetdInvalidStateError("Targetd connection is in invalid state, retry.")
        else:
            self.client.command = plugin_func
            self.client.exec_command()

        while not self.has_output:
            time.sleep(1)
        return self.output

    def _get_command(self, func: str) -> tuple[Loader, functools.partial]:
        """For target API"""
        curried_plugin_bridge = functools.update_wrapper(
            functools.partial(self.plugin_bridge, plugin_func=func), self.plugin_bridge
        )
        return (self, curried_plugin_bridge)

    def _add_plugin(self, plugin: Plugin):
        plugin.check_compatibe = lambda: True

    def map(self, target: Target) -> None:
        self._process_options(target)
        target.disks.add(RawContainer(TargetdStream()))
        target.get_function = self._get_command
        target.add_plugin = self._add_plugin

    @staticmethod
    def detect(path: Path) -> bool:
        # You can only activate this loader by URI-scheme "targetd://"
        return False

    def __del__(self) -> None:
        self.client.close()


if TARGETD_AVAILABLE:

    def command_runner(link: str, targetd: Client) -> None:
        caller = TargetdLoader.instance
        if not targetd.rpcs:
            targetd.easy_connect_remoting(remoting, link, caller.peers)
        func = getattr(targetd.rpcs, targetd.command)
        caller.has_output = True
        caller.output = list(func())
        targetd.reset()
