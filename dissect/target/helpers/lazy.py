import importlib


class LazyImport:
    def __init__(self, module_name):
        self._module_name = module_name
        self._module = None

    def _import(self):
        if not self._module:
            try:
                self._module = importlib.import_module(self._module_name)
            except ImportError as e:
                self._module = FailedImport(e, self)

    def __getattr__(self, attr):
        return LazyAttr(attr, self)

    def __repr__(self):
        return (
            f"<lazy {self._module_name} loaded={self._module is not None} "
            f"failed={isinstance(self._module, FailedImport)}>"
        )


class FailedImport:
    def __init__(self, exc, module):
        self.exc = exc
        self.module = module

    def _error(self):
        raise ImportError(f"Failed to lazily import {self.module._module_name}: {self.exc}")  # noqa

    def __call__(self, *args, **kwargs):
        self._error()

    def __getattr__(self, attr):
        self._error()


class LazyAttr:
    def __init__(self, attr, module):
        self.attr = attr
        self.module = module
        self._realattr = None

    def __call__(self, *args, **kwargs):
        if not self._realattr:
            self.module._import()  # noqa
            self._realattr = getattr(self.module._module, self.attr)  # noqa

        return self._realattr(*args, **kwargs)

    def __getattr__(self, attr):
        if not self._realattr:
            self.module._import()  # noqa
            self._realattr = getattr(self.module._module, self.attr)  # noqa

        return getattr(self._realattr, attr)

    def __repr__(self):
        return f"<lazyattr {self.module._module_name}.{self.attr} loaded={self._realattr is not None}>"


def import_lazy(module_name):
    return LazyImport(module_name)
