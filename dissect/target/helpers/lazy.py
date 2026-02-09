from __future__ import annotations

import importlib
from typing import Any


class LazyImport:
    def __init__(self, module_name: str):
        self._module_name = module_name
        self._module = None
        self._loaded = False

    def __repr__(self) -> str:
        return f"<lazy {self._module_name} loaded={self._loaded} failed={isinstance(self._module, FailedImport)}>"

    def __getattr__(self, attr: str) -> LazyAttr:
        return LazyAttr(self, attr)

    def _import(self) -> None:
        if not self._module:
            try:
                self._module = importlib.import_module(self._module_name)
            except Exception as e:
                self._module = FailedImport(self, e)
            finally:
                self._loaded = True


class FailedImport:
    def __init__(self, module: LazyImport, exc: Exception):
        self._module = module
        self._exc = exc

    def __getattr__(self, attr: str) -> None:
        self._error()

    def __call__(self, *args, **kwargs) -> None:
        self._error()

    def _error(self) -> None:
        raise ImportError(f"Failed to lazily import {self._module._module_name}: {self._exc}")


class LazyAttr:
    def __init__(self, module: LazyImport, attr: str):
        self._module = module
        self._attr = attr
        self._realattr = None
        self._loaded = False
        self._exc = None

    def __repr__(self) -> str:
        return (
            f"<lazyattr {self._module._module_name}.{self._attr} loaded={self._loaded} failed={self._exc is not None}>"
        )

    @property
    def __doc__(self) -> str:
        try:
            return self._load().__doc__
        except Exception as e:
            return f"Failed to load docstring: {e}"

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._load(), attr)

    def __call__(self, *args, **kwargs) -> Any:
        return self._load()(*args, **kwargs)

    def _load(self) -> Any:
        if not self._loaded:
            self._module._import()
            try:
                self._realattr = getattr(self._module._module, self._attr)
            except Exception as e:
                self._exc = e
                raise
            finally:
                self._loaded = True

        if self._exc:
            raise self._exc

        return self._realattr


def import_lazy(module_name: str) -> LazyImport:
    return LazyImport(module_name)
