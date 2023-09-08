from __future__ import annotations

import functools
import ssl
import time
import urllib
from pathlib import Path
from platform import os
from typing import Any, Callable, Union

from dissect.util.stream import AlignedStream

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


class CommandProxy:
    def __init__(self, loader: TargetdLoader, func: Callable, namespace=None):
        self._loader = loader
        self._func = func
        self._namespace = namespace or func

    def __getattr__(self, func: Callable) -> CommandProxy:
        if func == "func":
            return self._func.func
        self._func = func
        return self

    def command(self) -> Callable:
        namespace = None if self._func == self._namespace else self._namespace
        return self._get(namespace, self._func)

    def _get(self, namespace: str, plugin_func: Callable) -> Callable:
        if namespace:
            func = functools.update_wrapper(
                functools.partial(self._loader.plugin_bridge, plugin_func=self._func, namespace=self._namespace),
                self._loader.plugin_bridge,
            )
        else:
            func = functools.update_wrapper(
                functools.partial(self._loader.plugin_bridge, plugin_func=plugin_func), self._loader.plugin_bridge
            )
        return func

    def __call__(self, *args, **kwargs) -> Any:
        return self.command()(*args, **kwargs)

    def __repr__(self) -> str:
        return str(self._get(None, "get")(**{"property_name": self._func}))


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
    def plugin_bridge(self, *args, **kwargs) -> list[Any]:
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

        plugin_func = kwargs.get("plugin_func")
        del kwargs["plugin_func"]

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
                self.client.start(*args, **kwargs)
            except Exception:
                # If something happens that prevents targetd from properly closing/resetting the
                # connection, this exception is thrown during the next connection and the connection
                # is closed properly after all so that the next time the loader will be able to
                # use a new connection with a new session.
                self.client.close()
                raise TargetdInvalidStateError("Targetd connection is in invalid state, retry.")
        else:
            self.client.command = plugin_func
            self.client.exec_command(*args, **kwargs)

        while not self.has_output:
            time.sleep(1)
        return self.output

    def _get_command(self, func: str, namespace: str = None) -> tuple[Loader, functools.partial]:
        return (self, CommandProxy(self, func, namespace=namespace))

    def each(self, func: Callable, target: Target = None) -> Any:
        result = None
        for peer in self.client.peers:
            target.select(peer)
            try:
                if result is None:
                    result = func(target)
                else:
                    result += func(target)
            except Exception as failure:
                target.log.warning("Exception while applying function to target: %s: %s", peer, failure)
            target.select(peer)
        return result

    def _add_plugin(self, plugin: Plugin):
        plugin.check_compatibe = lambda: True

    def map(self, target: Target) -> None:
        if TargetdLoader.instance:
            raise Exception("You can only initiated 1 targetd control connection per session.")
        self._process_options(target)
        target.disks.add(RawContainer(TargetdStream()))
        target.get_function = self._get_command
        target.add_plugin = self._add_plugin
        target.each = functools.update_wrapper(functools.partial(self.each, target=target), self.each)
        TargetdLoader.instance = self

    @staticmethod
    def detect(path: Path) -> bool:
        # You can only activate this loader by URI-scheme "targetd://"
        return False

    def __del__(self) -> None:
        if self.client:
            self.client.close()


if TARGETD_AVAILABLE:
    # Loader has to provide the control script for targetd in this case
    def command_runner(link: str, targetd: Client, *args, **kwargs) -> None:
        caller = TargetdLoader.instance
        if not targetd.rpcs:
            targetd.easy_connect_remoting(remoting, link, caller.peers)

        obj = targetd.rpcs
        if namespace := kwargs.get("namespace", None):
            obj = getattr(obj, namespace)

        func = getattr(obj, targetd.command)
        caller.has_output = True
        result = func(*args, **kwargs)
        if result is not None:
            result = list(result)
            if targetd.command == "get" and len(result) == 1:
                result = result[0]
        caller.output = result
        targetd.reset()
