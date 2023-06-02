from __future__ import annotations

import functools
import time
from pathlib import Path
from typing import Union

from dissect.util.stream import AlignedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.loader import Loader
from dissect.target.plugin import Plugin, arg, export
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


class TargetdLoader(Loader):
    instance = None

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)
        self._plugin_func = None
        self.client = None
        self.output = None
        self.peers = 0
        uri = kwargs.get("parsed_path")
        if uri is None:
            raise LoaderError("No URI connection details have been passed.")
        self.uri = uri.path
        TargetdLoader.instance = self

    @export(output="record", cache=False)
    @arg(
        "--host",
        dest="host",
        type=str,
        default="localhost",
        action="store",
        help="IP-address of targetd broker",
    )
    @arg(
        "--link",
        dest="local_link",
        type=str,
        default="unix:///tmp/targetd",
        action="store",
        help="Domain socket or named pipe ('unix:///tmp/targetd')",
    )
    @arg(
        "--port",
        dest="port",
        type=int,
        default=1883,
        action="store",
        help="Port for connecting to targetd broker (1883)",
    )
    @arg(
        "--adapter",
        dest="adapter",
        type=str,
        default="Flow.Remoting",
        action="store",
        help="Adapter to use (default is 'Flow.Remoting')",
    )
    @arg(
        "--peers",
        dest="peers",
        type=int,
        action="store",
        required=True,
        help="Minimum number of hosts to wait for before executing query",
    )
    @arg("--help-targetd", action="help", help="Show help message for special targetd loader and exit")
    @arg("-h", "--help", action="help", help="Show help message for plugin and exit")
    def plugin_bridge(self, plugin_func: str, peers: int, host: str, local_link: str, port: int, adapter: str):
        """Command Execution Bridge Plugin for Targetd.

        This is a generic plugin interceptor that becomes active only if using
        the targetd loader. This plugin acts as a bridge to connect to the Targetd broker
        and will translate the requested plugin-operation into Targetd-commands using the selected
        adapter (i.e. Flow.Remoting).
        """

        if not TARGETD_AVAILABLE:
            raise ImportError("This loader requires the targetd package to be installed.")

        self.output = None

        if self.client is None:
            self.client = Client(host, port, [self.uri], local_link, "targetd")
            self.client.module_fullname = "dissect.target.loaders"
            self.client.module_fromlist = ["command_runner"]
            self.client.command = plugin_func
            self.peers = peers
            self.client.start()

        while not self.output:
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
        target.disks.add(RawContainer(TargetdStream()))
        target.get_function = self._get_command
        target.add_plugin = self._add_plugin

    @staticmethod
    def detect(path: Path) -> bool:
        # You can only activate this loader by URI-scheme "targetd://"
        return False


if TARGETD_AVAILABLE:

    def command_runner(link: str, targetd: Client):
        caller = TargetdLoader.instance
        targetd.easy_connect_remoting(remoting, link, caller.peers)
        func = getattr(targetd.rpcs, targetd.command)
        caller.output = list(func())
        targetd.close()
