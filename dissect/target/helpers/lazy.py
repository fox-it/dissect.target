from __future__ import annotations

import importlib
from typing import Any


class LazyImport:
    def __init__(self, module_name: str):
        self._module_name = module_name
        self._module = None

    def __repr__(self) -> str:
        return (
            f"<lazy {self._module_name} loaded={self._module is not None} "
            f"failed={isinstance(self._module, FailedImport)}>"
        )

    def __getattr__(self, attr: str) -> LazyAttr:
        return LazyAttr(attr, self)

    def _import(self) -> None:
        if not self._module:
            try:
                self._module = importlib.import_module(self._module_name)
            except Exception as e:
                self._module = FailedImport(e, self)


class FailedImport:
    def __init__(self, exc: Exception, module: LazyImport):
        self.exc = exc
        self.module = module

    def __getattr__(self, attr: str) -> None:
        self._error()

    def __call__(self, *args, **kwargs) -> None:
        self._error()

    def _error(self) -> None:
        raise ImportError(f"Failed to lazily import {self.module._module_name}: {self.exc}")


class LazyAttr:
    def __init__(self, attr: str, module: LazyImport):
        self.attr = attr
        self.module = module
        self._realattr = None

    def __repr__(self) -> str:
        return f"<lazyattr {self.module._module_name}.{self.attr} loaded={self.realattr is not None}>"

    @property
    def __doc__(self) -> str:
        return self.realattr.__doc__

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.realattr, attr)

    def __call__(self, *args, **kwargs) -> Any:
        return self.realattr(*args, **kwargs)

    @property
    def realattr(self) -> Any:
        if not self._realattr:
            self.module._import()
            self._realattr = getattr(self.module._module, self.attr)

        return self._realattr


def import_lazy(module_name: str) -> LazyImport:
    return LazyImport(module_name)
