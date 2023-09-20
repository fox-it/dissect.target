from __future__ import annotations

import functools
from typing import Any, Callable, Optional, Union

from dissect.util.stream import AlignedStream

from dissect.target.exceptions import FatalError
from dissect.target.loader import Loader


class TargetdStream(AlignedStream):
    def _read(self, offset: int, length: int) -> bytes:
        return b""


# Marker interface to indicate this loader loads targets from remote machines
class ProxyLoader(Loader):
    pass


class TargetdInvalidStateError(FatalError):
    pass


class CommandProxy:
    def __init__(self, loader: Loader, func: Callable, namespace: Optional[str] = None):
        self._loader = loader
        self._func = func
        self._namespace = namespace or func

    def __getattr__(self, func: Union[Callable, str]) -> CommandProxy:
        if func == "func":
            return self._func.func
        self._func = func
        return self

    def command(self) -> Callable:
        namespace = None if self._func == self._namespace else self._namespace
        return self._get(namespace, self._func)

    def _get(self, namespace: Optional[str], plugin_func: Callable) -> Callable:
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
