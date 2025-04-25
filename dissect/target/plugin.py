"""Dissect plugin system.

See ``dissect/target/plugins/general/example.py`` for an example plugin.
"""

from __future__ import annotations

import fnmatch
import functools
import importlib
import importlib.util
import logging
import os
import sys
import traceback
from dataclasses import dataclass, field
from itertools import zip_longest
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

try:
    from typing import TypeAlias  # novermin
except ImportError:
    # COMPAT: Remove this when we drop Python 3.9
    TypeAlias = Any

from flow.record import Record, RecordDescriptor

import dissect.target.plugins.os.default as default
from dissect.target.exceptions import PluginError, UnsupportedPluginError
from dissect.target.helpers import cache
from dissect.target.helpers.fsutil import has_glob_magic
from dissect.target.helpers.record import EmptyRecord
from dissect.target.helpers.utils import StrEnum

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.helpers.record import ChildTargetRecord
    from dissect.target.target import Target

log = logging.getLogger(__name__)

MODULE_PATH = "dissect.target.plugins"
"""The base module path to the in-tree plugins."""

OS_MODULE_PATH = "dissect.target.plugins.os"

OUTPUTS = (
    "default",
    "record",
    "yield",
    "none",
)
"""The different output types supported by ``@export``."""


class OperatingSystem(StrEnum):
    ANDROID = "android"
    BSD = "bsd"
    CITRIX = "citrix-netscaler"
    ESXI = "esxi"
    FORTIOS = "fortios"
    IOS = "ios"
    LINUX = "linux"
    MACOS = "macos"
    OSX = "osx"  # legacy
    PROXMOX = "proxmox"
    UNIX = "unix"
    VYOS = "vyos"
    WINDOWS = "windows"


@dataclass(frozen=True, eq=True)
class PluginDescriptor:
    # COMPAT: Replace with slots=True when we drop Python 3.9
    __slots__ = ("exports", "findable", "functions", "module", "namespace", "path", "qualname")

    module: str
    qualname: str
    namespace: str
    path: str
    findable: bool
    functions: list[str]
    exports: list[str]

    @property
    def cls(self) -> type[Plugin]:
        return load(self)


@dataclass(frozen=True, eq=True)
class FunctionDescriptor:
    # COMPAT: Replace with slots=True when we drop Python 3.9
    __slots__ = (
        "alias",
        "exported",
        "findable",
        "internal",
        "method_name",
        "module",
        "name",
        "namespace",
        "output",
        "path",
        "qualname",
    )

    name: str
    namespace: str
    path: str
    exported: bool
    internal: bool
    findable: bool
    alias: bool
    output: str | None
    method_name: str
    module: str
    qualname: str

    @property
    def cls(self) -> type[Plugin]:
        return load(self)

    @property
    def func(self) -> Callable[..., Any]:
        return getattr(self.cls, self.method_name)

    @property
    def record(self) -> RecordDescriptor | list[RecordDescriptor] | None:
        return getattr(self.func, "__record__", None)

    @property
    def args(self) -> list[tuple[list[str], dict[str, Any]]]:
        return getattr(self.func, "__args__", [])


@dataclass(frozen=True, eq=True)
class FailureDescriptor:
    # COMPAT: Replace with slots=True when we drop Python 3.9
    __slots__ = ("module", "stacktrace")

    module: str
    stacktrace: list[str]


# COMPAT: Add slots=True when we drop Python 3.9
# We can't manually define __slots__ here because we use have to use field() for the default_factory
@dataclass(frozen=True)
class PluginDescriptorLookup:
    # All regular plugins
    # {"<module_path>": PluginDescriptor}
    __regular__: dict[str, PluginDescriptor] = field(default_factory=dict)
    # All OS plugins
    # {"<module_path>": PluginDescriptor}
    __os__: dict[str, PluginDescriptor] = field(default_factory=dict)
    # All child plugins
    # {"<module_path>": PluginDescriptor}
    __child__: dict[str, PluginDescriptor] = field(default_factory=dict)


# COMPAT: Add slots=True when we drop Python 3.9
# We can't manually define __slots__ here because we use have to use field() for the default_factory
@dataclass(frozen=True)
class FunctionDescriptorLookup:
    # All regular plugins
    # {"<function_name>": {"<module_path>": FunctionDescriptor}}
    __regular__: dict[str, dict[str, FunctionDescriptor]] = field(default_factory=dict)
    # All OS plugins
    # {"<function_name>": {"<module_path>": FunctionDescriptor}}
    __os__: dict[str, dict[str, FunctionDescriptor]] = field(default_factory=dict)
    # All child plugins
    # {"<function_name>": {"<module_path>": FunctionDescriptor}}
    __child__: dict[str, dict[str, FunctionDescriptor]] = field(default_factory=dict)


_OSTree: TypeAlias = dict[str, "_OSTree"]


# COMPAT: Add slots=True when we drop Python 3.9
# We can't manually define __slots__ here because we use have to use field() for the default_factory
@dataclass(frozen=True)
class PluginRegistry:
    # Plugin descriptor lookup
    __plugins__: PluginDescriptorLookup = field(default_factory=PluginDescriptorLookup)
    # Function descriptor lookup
    __functions__: FunctionDescriptorLookup = field(default_factory=FunctionDescriptorLookup)
    # OS plugin tree
    # {"<module_part>": {"<module_part>": {}}}
    __ostree__: _OSTree = field(default_factory=dict)
    # Failures
    __failed__: list[FailureDescriptor] = field(default_factory=list)


PLUGINS: PluginRegistry = PluginRegistry()
"""The plugin registry.

Note: It's very important that all values in this dictionary are serializable.
The plugin registry can be stored in a file and loaded later. Plain Python syntax is used to store the registry.
An exception is made for :class:`FailureDescriptor`, :class:`FunctionDescriptor` and :class:`PluginDescriptor`.
"""

GENERATED = False


def export(*args, **kwargs) -> Callable[..., Any]:
    """Decorator to be used on Plugin functions that should be exported.

    Supported keyword arguments:
        property (bool): Whether this export should be regarded as a property.
            Properties are implicitly cached.

        cache (bool): Whether the result of this function should be cached.

        record (RecordDescriptor): The :class:`flow.record.RecordDescriptor` for the records that this function yields.
            If multiple record types are yielded, specificy each descriptor in a list or tuple.
            If the records are dynamically made, use :func:`dissect.target.helpers.record.DynamicDescriptor` instead.

        output (str): The output type of this function. Must be one of:
        - default: Single return value
        - record: Yields records. Implicit when record argument is given.
        - yield: Yields printable values.
        - none: No return value. Plugin is responsible for output formatting and should return ``None``.

    The ``export`` decorator adds some additional private attributes to an exported method or property:
    - ``__output__``: The output type to expect for this function, this is the same as ``output``.
    - ``__record__``: The type of record to expect, this value is the same as ``record``.
    - ``__exported__``: set to ``True`` to indicate the method or property is exported.

    Raises:
        ValueError: if there was an invalid output type.

    Returns:
        An exported function from a plugin.
    """

    def decorator(obj: Callable[..., Any]) -> Callable[..., Any] | property:
        # Properties are implicitly cached
        # Important! Currently it's crucial that this is *always* called
        # See the comment in Plugin.__init_subclass__ for more detail regarding Plugin.__call__
        obj = cache.wrap(obj, no_cache=not kwargs.get("cache", True), cls=kwargs.get("cls"))

        output = kwargs.get("output", "default")
        if output not in OUTPUTS:
            options = ", ".join(OUTPUTS)
            raise ValueError(f'Invalid output method "{output}", must be one of {options}')

        record = kwargs.get("record")
        if record is not None:
            output = "record"

            if not isinstance(record, (list, RecordDescriptor)) and not (
                isinstance(record, (list, tuple)) and all(isinstance(r, RecordDescriptor) for r in record)
            ):
                raise TypeError("record must be an instance of RecordDescriptor or a list of RecordDescriptor")

        obj.__output__ = output
        obj.__record__ = list(record) if isinstance(record, tuple) else record
        obj.__exported__ = True

        if kwargs.get("property", False):
            obj = property(obj)

        return obj

    if len(args) == 1:
        return decorator(args[0])
    return decorator


def internal(*args, **kwargs) -> Callable[..., Any]:
    """Decorator to be used on plugin functions that should be internal only.

    Making a plugin internal means that it's only callable from the Python API and not through ``target-query``.

    This decorator adds the ``__internal__`` private attribute to a method or property.
    The attribute is always set to ``True``, to tell :func:`register` that it is an internal
    method or property.
    """

    def decorator(obj: Callable[..., Any]) -> Callable[..., Any] | property:
        obj.__internal__ = True
        if kwargs.get("property", False):
            obj = property(obj)
        return obj

    if len(args) == 1:
        return decorator(args[0])
    return decorator


def arg(*args, **kwargs) -> Callable[..., Any]:
    """Decorator to be used on Plugin functions that accept additional command line arguments.

    Command line arguments can be added using the ``@arg`` decorator.
    Arguments to this decorator are directly forwarded to the ``ArgumentParser.add_argument`` function of ``argparse``.
    Resulting arguments are passed to the function using kwargs.
    The keyword argument name must match the argparse argument name.

    This decorator adds the ``__args__`` private attribute to a method or property.
    This attribute holds all the command line arguments that were added to the plugin function.
    """

    def decorator(obj: Callable[..., Any]) -> Callable[..., Any]:
        if not hasattr(obj, "__args__"):
            obj.__args__ = []

        obj.__args__.insert(0, (args, kwargs))

        return obj

    return decorator


def alias(*args, **kwargs: dict[str, Any]) -> Callable[..., Any]:
    """Decorator to be used on :class:`Plugin` functions to register an alias of that function."""

    if not kwargs.get("name") and not args:
        raise ValueError("Missing argument 'name'")

    def decorator(obj: Callable[..., Any]) -> Callable[..., Any]:
        if not hasattr(obj, "__aliases__"):
            obj.__aliases__ = []

        if name := (kwargs.get("name") or args[0]):
            obj.__aliases__.append(name)

        return obj

    return decorator


def clone_alias(cls: type, attr: Callable[..., Any], alias: str) -> None:
    """Clone the given attribute to an alias in the provided class."""

    # Clone the function object
    clone = type(attr)(attr.__code__, attr.__globals__, alias, attr.__defaults__, attr.__closure__)
    clone.__kwdefaults__ = attr.__kwdefaults__

    # Copy some attributes
    functools.update_wrapper(clone, attr)
    if wrapped := getattr(attr, "__wrapped__", None):
        # update_wrapper sets a new wrapper, we want the original
        clone.__wrapped__ = wrapped

    # Update module path so we can fool inspect.getmodule with subclassed Plugin classes
    clone.__module__ = cls.__module__

    # Update the names
    clone.__name__ = alias
    clone.__qualname__ = f"{cls.__name__}.{alias}"

    setattr(cls, alias, clone)


class Plugin:
    """Base class for plugins.

    Plugins can optionally be namespaced by specifying the ``__namespace__``
    class attribute. Namespacing results in your plugin needing to be prefixed
    with this namespace when being called. For example, if your plugin has
    specified ``test`` as namespace and a function called ``example``, you must
    call your plugin with ``test.example``.

    A ``Plugin`` class has the following private class attributes:

    - ``__namespace__``
    - ``__record_descriptors__``

    With the following two being assigned in :func:`register`:

    - ``__functions__``
    - ``__exports__``

    Additionally, the methods and attributes of :class:`Plugin` receive more private attributes
    by using decorators.

    The :func:`export` decorator adds the following private attributes

    - ``__exported__``
    - ``__output__``: Set with the :func:`export` decorator.
    - ``__record__``: Set with the :func:`export` decorator.

    The :func:`internal` decorator and :class:`InternalPlugin` set the ``__internal__`` attribute.
    Finally. :func:`args` decorator sets the ``__args__`` attribute.

    The :func:`alias` decorator populates the ``__aliases__`` private attribute of :class:`Plugin` methods.
    Resulting clones of the :class:`Plugin` are populated with the boolean ``__alias__`` attribute set to ``True``.

    Args:
        target: The :class:`~dissect.target.target.Target` object to load the plugin for.
    """

    __namespace__: str = None
    """Defines the plugin namespace."""
    __record_descriptors__: list[RecordDescriptor] = None
    """Defines a list of :class:`~flow.record.RecordDescriptor` of the exported plugin functions."""
    __register__: bool = True
    """Determines whether this plugin will be registered."""
    __findable__: bool = True
    """Determines whether this plugin will be revealed when using search patterns.

    Some (meta)-plugins are not very suitable for wild cards on CLI or
    plugin searches, because they will produce duplicate records or results.
    For instance a plugin that offers the same functions as subplugins will
    produce redundant results when used with a wild card
    (browser.* -> browser.history + browser.*.history).
    """
    __functions__: list[str]
    """Internal. A list of all method names decorated with ``@internal`` or ``@export``."""
    __exports__: list[str]
    """Internal. A list of all method names decorated with ``@export``."""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Do not register the "base" subclasses defined in this file
        if cls.__module__ != Plugin.__module__:
            register(cls)

        record_descriptors = _get_descriptors_on_nonprivate_methods(cls)
        cls.__record_descriptors__ = record_descriptors
        # This is a bit tricky currently
        # cls.__call__ is the *function* Plugin.__call__, not from the subclass
        # export() currently will _always_ return a new object because it always calls ``cache.wrap(obj)``
        # This allows this to work, otherwise the Plugin.__call__ would get all the plugin attributes set on it
        cls.__call__ = export(output="record", record=record_descriptors, cache=False, cls=cls)(cls.__call__)

    def __init__(self, target: Target):
        self.target = target

    def is_compatible(self) -> bool:
        """Perform a compatibility check with the target."""
        try:
            self.check_compatible()
        except UnsupportedPluginError:
            return False

        return True

    def check_compatible(self) -> None:
        """Perform a compatibility check with the target.

        This function should return ``None`` if the plugin is compatible with the current target (``self.target``).
        For example, check if a certain file exists. Otherwise it should raise an
        :class:`UnsupportedPluginError`.

        Raises:
            UnsupportedPluginError: If the plugin could not be loaded.
        """
        raise NotImplementedError

    def __call__(self, *args, **kwargs) -> Iterator[Record | Any]:
        """Return the records of all exported methods.

        Raises:
            PluginError: If the subclass is not a namespace plugin.
        """
        if not self.__namespace__:
            raise PluginError(f"Plugin {self.__class__.__name__} is not a callable")

        for method_name in self.__exports__:
            if method_name == "__call__":
                continue

            method = getattr(self, method_name)
            if getattr(method, "__output__", None) not in ("record", "yield"):
                continue

            try:
                yield from method()
            except Exception as e:
                self.target.log.error("Error while executing `%s.%s`", self.__namespace__, method_name)  # noqa: TRY400
                self.target.log.debug("", exc_info=e)

    def get_paths(self) -> Iterator[Path]:
        if self.target.is_direct:
            yield from self._get_paths_direct()
        else:
            yield from self._get_paths()

    def _get_paths_direct(self) -> Iterator[Path]:
        """Return all paths as given by the user."""
        for path in self.target._loader.paths:
            yield self.target.fs.path(str(path))

    def _get_paths(self) -> Iterator[Path]:
        """Return all files of interest to the plugin.

        To be implemented by the plugin subclass.
        """
        raise NotImplementedError


def register(plugincls: type[Plugin]) -> None:
    """Register a plugin, and put related data inside :attr:`PLUGINS`.

    This function uses the following private attributes that are set using decorators:
        - ``__exported__``: Set in :func:`export`.
        - ``__internal__``: Set in :func:`internal`.

    Additionally, ``register`` sets the following private attributes on the `plugincls`:
        - ``__functions__``: A list of all the methods and properties that are ``__internal__`` or ``__exported__``.
        - ``__exports__``: A list of all the methods or properties that were explicitly exported.

    If a plugincls ``__register__`` attribute is set to ``False``, the plugin will not be registered, but the
    plugin will still be processed for the private attributes mentioned above.

    Args:
        plugincls: A plugin class to register.

    Raises:
        ValueError: If ``plugincls`` is not a subclass of :class:`Plugin`.
    """
    if not issubclass(plugincls, Plugin):
        raise TypeError("Not a subclass of Plugin")

    # Register the plugin in the correct tree
    __plugins__ = PLUGINS.__plugins__
    __functions__ = PLUGINS.__functions__
    if issubclass(plugincls, OSPlugin):
        plugin_index = __plugins__.__os__
        function_index = __functions__.__os__
    elif issubclass(plugincls, ChildTargetPlugin):
        plugin_index = __plugins__.__child__
        function_index = __functions__.__child__
    else:
        plugin_index = __plugins__.__regular__
        function_index = __functions__.__regular__

    exports = []
    functions = []
    module_path = _module_path(plugincls)

    # This enables plugin directories, e.g.:
    # <plugin>/_plugin.py
    # <plugin>/helpers.py
    module_path = module_path.removesuffix("._plugin")

    module_key = f"{module_path}.{plugincls.__qualname__}"

    if not issubclass(plugincls, ChildTargetPlugin):
        # First pass to resolve aliases
        for attr in _get_nonprivate_attributes(plugincls):
            for alias in getattr(attr, "__aliases__", []):
                clone_alias(plugincls, attr, alias)

        for attr in _get_nonprivate_attributes(plugincls):
            if isinstance(attr, property):
                attr = attr.fget

            if getattr(attr, "__generated__", False) and plugincls != plugincls.__nsplugin__:
                continue

            exported = getattr(attr, "__exported__", False)
            internal = getattr(attr, "__internal__", False)

            if exported or internal:
                functions.append(attr.__name__)
                if exported:
                    exports.append(attr.__name__)

                if plugincls.__register__:
                    name = attr.__name__
                    if plugincls.__namespace__:
                        name = f"{plugincls.__namespace__}.{name}"

                    path = f"{module_path}.{attr.__name__}"

                    descriptor = FunctionDescriptor(
                        name=name,
                        namespace=plugincls.__namespace__,
                        path=path,
                        exported=exported,
                        internal=internal,
                        findable=plugincls.__findable__,
                        alias=name in getattr(attr, "__aliases__", []),
                        output=getattr(attr, "__output__", None),
                        method_name=attr.__name__,
                        module=plugincls.__module__,
                        qualname=plugincls.__qualname__,
                    )

                    # Register the functions in the lookup
                    function_index.setdefault(name, {})[module_key] = descriptor

    if plugincls.__namespace__:
        # Namespaces are also callable, so register the namespace itself as well
        # NamespacePlugin needs to register itself for every additional subclass, so allow overwrites here
        functions.append("__call__")
        if exports:
            exports.append("__call__")

        if plugincls.__register__:
            descriptor = FunctionDescriptor(
                name=plugincls.__namespace__,
                namespace=plugincls.__namespace__,
                path=module_path,
                exported=len(exports) != 0,
                internal=len(functions) != 0 and len(exports) == 0,
                findable=plugincls.__findable__,
                alias=False,
                output=getattr(plugincls.__call__, "__output__", None),
                method_name="__call__",
                module=plugincls.__module__,
                qualname=plugincls.__qualname__,
            )

            function_index.setdefault(plugincls.__namespace__, {})[module_key] = descriptor

    # Update the class with the plugin attributes
    plugincls.__functions__ = functions
    plugincls.__exports__ = exports

    if plugincls.__register__:
        plugin_index[module_key] = PluginDescriptor(
            module=plugincls.__module__,
            qualname=plugincls.__qualname__,
            namespace=plugincls.__namespace__,
            path=module_path,
            findable=plugincls.__findable__,
            functions=functions,
            exports=exports,
        )

        if issubclass(plugincls, OSPlugin):
            # Also store the OS plugins in a tree by module path
            # This is used to filter plugins based on the OSPlugin subclass
            # We don't store anything at the end of the tree, as we only use the tree to check if a plugin is compatible

            # Also slightly modify the module key to allow for more efficient filtering later
            # This is done by removing the last two parts of the module key, which are the file name and the class name
            module_parts = module_key.split(".")
            if module_parts[-2] != "_os":
                log.warning("OS plugin modules should be named as <os>/_os.py: %s", module_key)

            obj = PLUGINS.__ostree__
            for part in module_parts[:-2]:
                obj = obj.setdefault(part, {})

        log.debug("Plugin registered: %s", module_key)


def _get_plugins() -> PluginRegistry:
    """Load the plugin registry, or generate it if it doesn't exist yet."""
    global PLUGINS, GENERATED

    if not GENERATED:
        try:
            from dissect.target.plugins._pluginlist import PLUGINS
        except ImportError:
            PLUGINS = generate()

        GENERATED = True

    return PLUGINS


def _module_path(cls: type[Plugin] | str) -> str:
    """Returns the module path relative to ``dissect.target.plugins``."""
    if issubclass(cls, Plugin):
        module = getattr(cls, "__module__", "")
    elif isinstance(cls, str):
        module = cls
    else:
        raise TypeError(f"Invalid argument type: {cls}")

    return module.replace(MODULE_PATH, "").lstrip(".")


def _os_match(osfilter: type[OSPlugin], module_path: str) -> bool:
    """Check if the a plugin is compatible with the given OS filter."""
    if issubclass(osfilter, default._os.DefaultOSPlugin):
        return True

    os_parts = _module_path(osfilter).split(".")[:-1]

    obj = _get_plugins().__ostree__
    for plugin_part, os_part in zip_longest(module_path.split("."), os_parts):
        if plugin_part not in obj:
            break

        if plugin_part != os_part:
            return False

        obj = obj[plugin_part]

    return True


def plugins(osfilter: type[OSPlugin] | None = None, *, index: str = "__regular__") -> Iterator[PluginDescriptor]:
    """Walk the plugin registry and return plugin descriptors.

    If ``osfilter`` is specified, only plugins related to the provided OSPlugin, or plugins
    with no OS relation are returned. If ``osfilter`` is ``None``, all plugins will be returned.

    One exception to this is if the ``osfilter`` is a (sub-)class of ``DefaultOSPlugin``, then plugins
    are returned as if no ``osfilter`` was specified.

    The ``index`` parameter can be used to specify the index to return plugins from. By default,
    this is set to return regular plugins. Other possible values are ``__os__`` and ``__child__``.
    These return :class:`OSPlugin` and :class:`ChildTargetPlugin` respectively.

    Args:
        osfilter: The optional :class:`OSPlugin` to filter the returned plugins on.
        index: The plugin index to return plugins from. Defaults to regular plugins.

    Yields:
        Plugin descriptors in the plugin registry based on the given filter criteria.
    """

    plugin_index: dict[str, PluginDescriptor] = getattr(_get_plugins().__plugins__, index, {})

    # This is implemented as a list comprehension for performance reasons!
    yield from (
        descriptor
        for module_path, descriptor in plugin_index.items()
        if (index != "__os__" and (osfilter is None or _os_match(osfilter, module_path)))
        or (index == "__os__" and (osfilter is None or osfilter.__module__ == descriptor.module))
    )


def os_plugins() -> Iterator[PluginDescriptor]:
    """Retrieve all OS plugin descriptors."""
    yield from plugins(index="__os__")


def child_plugins() -> Iterator[PluginDescriptor]:
    """Retrieve all child plugin descriptors."""
    yield from plugins(index="__child__")


def functions(osfilter: type[OSPlugin] | None = None, *, index: str = "__regular__") -> Iterator[FunctionDescriptor]:
    """Retrieve all function descriptors.

    Args:
        osfilter: The optional :class:`OSPlugin` to filter the returned functions on.
        index: The plugin index to return functions from. Defaults to regular functions.

    Yields:
        Function descriptors in the plugin registry based on the given filter criteria.
    """

    function_index: dict[str, dict[str, FunctionDescriptor]] = getattr(_get_plugins().__functions__, index, {})

    # This is implemented as a list comprehension for performance reasons!
    yield from (
        descriptor
        for function_index in function_index.values()
        for module_path, descriptor in function_index.items()
        if osfilter is None or _os_match(osfilter, module_path)
    )


def lookup(
    function_name: str, osfilter: type[OSPlugin] | None = None, *, index: str = "__regular__"
) -> Iterator[FunctionDescriptor]:
    """Lookup a function descriptor by function name.

    Args:
        func_name: Function name to lookup.
        osfilter: The optional ``OSPlugin`` to filter results with for compatibility.
        index: The plugin index to return plugins from. Defaults to regular functions.

    Yields:
        Function descriptors that match the given function name and filter criteria.
    """

    function_index: dict[str, FunctionDescriptor] = getattr(_get_plugins().__functions__, index, {}).get(
        function_name, {}
    )

    # This is implemented as a list comprehension for performance reasons!
    entries: Iterator[FunctionDescriptor] = (
        value for key, value in function_index.items() if osfilter is None or _os_match(osfilter, key)
    )

    yield from sorted(entries, key=lambda x: x.module.count("."), reverse=True)


def load(desc: FunctionDescriptor | PluginDescriptor) -> type[Plugin]:
    """Helper function that loads a plugin from a given function or plugin descriptor.

    Args:
        desc: Function descriptor as returned by :func:`plugin.lookup` or plugin descriptor
              as returned by :func:`plugin.plugins`.

    Returns:
        The plugin class.

    Raises:
        PluginError: Raised when any other exception occurs while trying to load the plugin.
    """
    module = desc.module

    try:
        obj = importlib.import_module(module)
        for part in desc.qualname.split("."):
            obj = getattr(obj, part)
    except Exception as e:
        raise PluginError(f"An exception occurred while trying to load a plugin: {module}") from e
    else:
        return obj


def os_match(target: Target, descriptor: PluginDescriptor) -> bool:
    """Check if a plugin descriptor is compatible with the target OS.

    Args:
        target: The target to check compatibility with.
        descriptor: The plugin descriptor to check compatibility for.
    """
    return _os_match(target._os_plugin, f"{descriptor.module}.{descriptor.qualname}")


def failed() -> list[FailureDescriptor]:
    """Return all plugins that failed to load."""
    return _get_plugins().__failed__


@functools.cache
def _generate_long_paths() -> dict[str, list[FunctionDescriptor]]:
    """Generate a dictionary of all long paths to their function descriptors."""
    paths = {}
    for value in _get_plugins().__functions__.__regular__.values():
        for descriptor in value.values():
            # Namespace plugins are callable so exclude the explicit __call__ method
            if descriptor.method_name == "__call__":
                continue

            paths.setdefault(descriptor.path, []).append(descriptor)

    return paths


def find_functions(
    patterns: str,
    target: Target | None = None,
    compatibility: bool = False,
    ignore_load_errors: bool = False,
    show_hidden: bool = False,
) -> tuple[list[FunctionDescriptor], set[str]]:
    """Finds exported plugin functions that match the target and the patterns.

    Given a target, a comma separated list of patterns and an optional compatibility flag,
    this function finds matching plugins, optionally checking compatibility.

    Returns:
        A tuple containing a list of matching function descriptors and a set of invalid patterns.
    """
    found = []

    __functions__ = _get_plugins().__functions__

    regular_functions = __functions__.__regular__
    os_functions = __functions__.__os__

    os_filter = target._os_plugin if target is not None else None

    invalid_functions = set()

    for pattern in patterns.split(","):
        if not pattern:
            continue

        exact_match = pattern in regular_functions
        exact_os_match = pattern in os_functions

        if exact_match or exact_os_match:
            if matches := list(_filter_exact_match(pattern, os_filter, exact_match, exact_os_match)):
                found.extend(matches)
            else:
                invalid_functions.add(pattern)
        else:
            # If we don't have an exact function match, do a slower treematch
            if matches := list(_filter_tree_match(pattern, os_filter, show_hidden=show_hidden)):
                found.extend(matches)
            else:
                invalid_functions.add(pattern)

    if compatibility and target is not None:
        result = list(_filter_compatible(found, target, ignore_load_errors))
    else:
        result = found

    return result, invalid_functions


def find_functions_by_record_field_type(
    field_types: str | list[str],
    target: Target | None = None,
    compatibility: bool = False,
    ignore_load_errors: bool = False,
) -> Iterator[FunctionDescriptor]:
    """Find functions that yield records with a specific field type.

    Args:
        field_types: The field type to search for.
        target: The target to check compatibility with.
        compatibility: Whether to check compatibility with the target.
        ignore_load_errors: Whether to ignore load errors.
    """

    def _search(search_types: list[str]) -> Iterator[FunctionDescriptor]:
        for descriptor in functions():
            try:
                if descriptor.output != "record" or (record_descriptors := descriptor.record) is None:
                    continue
            except Exception:
                if ignore_load_errors:
                    continue
                raise

            for rd in record_descriptors if isinstance(record_descriptors, list) else [record_descriptors]:
                if any(type_name in search_types for type_name, _ in rd._field_tuples):
                    yield descriptor
                    break

    search_types = field_types if isinstance(field_types, list) else [field_types]
    if compatibility and target is not None:
        yield from _filter_compatible(_search(search_types), target, ignore_load_errors)
    else:
        yield from _search(search_types)


def _filter_exact_match(
    pattern: str, os_filter: str, exact_match: bool, exact_os_match: bool
) -> Iterator[FunctionDescriptor]:
    if exact_match:
        descriptors = lookup(pattern, os_filter)
    elif exact_os_match:
        descriptors = lookup(pattern, os_filter, index="__os__")

    for descriptor in descriptors:
        if not descriptor.exported:
            continue

        yield descriptor


def _filter_tree_match(pattern: str, os_filter: str, show_hidden: bool = False) -> Iterator[FunctionDescriptor]:
    path_lookup = _generate_long_paths()

    # Change the treematch pattern into an fnmatch-able pattern to give back all functions from the sub-tree
    # (if there is a subtree).
    #
    # Examples:
    #     -f apps.webservers.iis -> apps.webservers.iis* (logs etc)
    #     -f apps.webservers.iis.logs -> apps.webservers.iis.logs* (only the logs, there is no subtree)
    # We do not include a dot because that does not work if the full path is given:
    #     -f apps.webservers.iis.logs != apps.webservers.iis.logs.* (does not work)
    search_pattern = pattern
    if not has_glob_magic(pattern):
        search_pattern += "*"

    for path in fnmatch.filter(path_lookup.keys(), search_pattern):
        for descriptor in path_lookup[path]:
            # Skip plugins that don't want to be found by wildcards
            if not descriptor.exported or (not show_hidden and not descriptor.findable):
                continue

            # Skip plugins that do not match our OS
            if os_filter and not _os_match(os_filter, descriptor.path):
                continue

            yield descriptor


def _filter_compatible(
    descriptors: list[FunctionDescriptor], target: Target, ignore_load_errors: bool = False
) -> Iterator[FunctionDescriptor]:
    """Filter a list of function descriptors based on compatibility with a target."""
    compatible = set()
    incompatible = set()

    for descriptor in descriptors:
        if descriptor.qualname in compatible:
            yield descriptor
            continue

        if descriptor.qualname in incompatible:
            continue

        try:
            plugincls = load(descriptor)
        except Exception:
            if ignore_load_errors:
                incompatible.add(descriptor.qualname)
                continue
            raise

        try:
            if plugincls(target).is_compatible():
                compatible.add(descriptor.qualname)
                yield descriptor
        except Exception:
            incompatible.add(descriptor.qualname)
            continue


def generate() -> dict[str, Any]:
    """Internal function to generate the list of available plugins.

    Walks the plugins directory and imports any ``.py`` files in there.
    Plugins will be automatically registered.

    Returns:
        The global ``PLUGINS`` dictionary.
    """
    plugins_dir = Path(__file__).parent / "plugins"
    for path in _find_py_files(plugins_dir):
        relative_path = path.relative_to(plugins_dir)
        module_tuple = (MODULE_PATH, *relative_path.parent.parts, relative_path.stem)
        load_module_from_name(".".join(module_tuple))

    return PLUGINS


def _find_py_files(path: Path) -> Iterator[Path]:
    """Walk all the files and directories in ``path`` and return all files ending in ``.py``.

    Do not walk or yield paths containing the following names:

    - __pycache__
    - __init__

    Furthermore, it logs an error if ``path`` does not exist.

    Args:
        path: The path to a directory or file to walk and filter.
    """
    if not path.exists():
        log.error("Path %s does not exist", path)
        return

    it = [path] if path.is_file() else path.glob("**/*.py")

    for entry in it:
        if not entry.is_file() or entry.name == "__init__.py":
            continue

        yield entry


def load_module_from_name(module_path: str) -> None:
    """Load a module from ``module_path``."""
    try:
        # This will trigger the __init__subclass__() of the Plugin subclasses in the module.
        importlib.import_module(module_path)
    except Exception as e:
        log.info("Unable to import %s", module_path)
        log.debug("Error while trying to import module %s", module_path, exc_info=e)
        _save_plugin_import_failure(module_path)


def load_module_from_file(path: Path, base_path: Path) -> None:
    """Loads a module from a file indicated by ``path`` relative to ``base_path``.

    The module is added to ``sys.modules`` so it can be found everywhere.

    Args:
        path: The file to load as module.
        base_path: The base directory of the module.
    """
    try:
        relative_path = path.relative_to(base_path)
        module_tuple = (*relative_path.parent.parts, relative_path.stem)
        spec = importlib.util.spec_from_file_location(".".join(module_tuple), path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[module.__name__] = module
    except Exception as e:
        log.error("Unable to import %s", path)  # noqa: TRY400
        log.debug("Error while trying to import module %s", path, exc_info=e)
        _save_plugin_import_failure(str(path))


def load_modules_from_paths(paths: list[Path]) -> None:
    """Iterate over the ``paths`` and load all ``.py`` files."""
    for path in paths:
        for file in _find_py_files(path):
            base_path = path.parent if file == path else path
            load_module_from_file(file, base_path)


def get_external_module_paths(path_list: list[Path]) -> list[Path]:
    """Return a list of external plugin directories."""
    output_list = environment_variable_paths() + path_list

    return list(set(output_list))


def environment_variable_paths() -> list[Path]:
    """Return additional plugin directories specified by the ``DISSECT_PLUGINS`` environment variable."""
    env_var = os.environ.get("DISSECT_PLUGINS")

    plugin_dirs = env_var.split(":") if env_var else []

    return [Path(directory) for directory in plugin_dirs]


def _save_plugin_import_failure(module: str) -> None:
    """Store errors that occurred during plugin import."""
    stacktrace = traceback.format_exception(*sys.exc_info())
    PLUGINS.__failed__.append(FailureDescriptor(module, stacktrace))


def _get_nonprivate_attribute_names(cls: type[Plugin]) -> list[str]:
    """Retrieve all attributes that do not start with ``_``."""
    return [attr for attr in dir(cls) if not attr.startswith("_")]


def _get_nonprivate_attributes(cls: type[Plugin]) -> list[Any]:
    """Retrieve all public attributes of a :class:`Plugin`."""
    # Note: `dir()` might return attributes from parent class
    return [getattr(cls, attr) for attr in _get_nonprivate_attribute_names(cls)]


def _get_nonprivate_methods(cls: type[Plugin]) -> list[Callable]:
    """Retrieve all public methods of a :class:`Plugin`."""
    return [attr for attr in _get_nonprivate_attributes(cls) if not isinstance(attr, property) and callable(attr)]


def _get_descriptors_on_nonprivate_methods(cls: type[Plugin]) -> list[RecordDescriptor]:
    """Return record descriptors set on nonprivate methods in ``cls`` class."""
    descriptors = set()

    for m in _get_nonprivate_methods(cls):
        descriptors.update(_get_descriptors_on_method(m))

    return list(descriptors)


def _get_descriptors_on_method(method: Callable) -> list[RecordDescriptor]:
    """Return record descriptors set on a method."""
    if not (record := getattr(method, "__record__", None)):
        return []

    try:
        # check if __record__ value is iterable (for example, a list)
        return list(record)
    except TypeError:
        return [record]


# Classes for specific types of plugins
# These need to be at the bottom of the module because __init_subclass__ requires everything
# in the parent class Plugin to be defined and resolved.
class OSPlugin(Plugin):
    """Base class for OS plugins.

    This provides a base class for certain common functions of OS's, which each OS plugin has to implement separately.

    For example, it provides an interface for retrieving the hostname and users of a target.

    All derived classes MUST implement ALL the classmethods and exported
    methods with the same ``@classmethod`` or ``@export(...)`` annotation.
    """

    def __init_subclass__(cls, **kwargs):
        # Note that cls is the subclass
        super().__init_subclass__(**kwargs)

        for os_method in _get_nonprivate_attributes(OSPlugin):
            if isinstance(os_method, property):
                os_method = os_method.fget
            os_docstring = os_method.__doc__

            method = getattr(cls, os_method.__name__, None)
            if isinstance(method, property):
                method = method.fget
            # This works as None has a __doc__ property (which is None).
            docstring = method.__doc__

            if method and not docstring:
                if hasattr(method, "__func__"):
                    method = method.__func__
                method.__doc__ = os_docstring

    def check_compatible(self) -> bool:
        """OSPlugin's use a different compatibility check, override the one from the :class:`Plugin` class.

        Returns:
            This function always returns ``True``.
        """
        return True

    @classmethod
    def detect(cls, fs: Filesystem) -> Filesystem | None:
        """Provide detection of this OSPlugin on a given filesystem.

        Args:
            fs: :class:`~dissect.target.filesystem.Filesystem` to detect the OS on.

        Returns:
            The root filesystem / sysvol when found.
        """
        raise NotImplementedError

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        """Initiate this OSPlugin with the given target and detected filesystem.

        Args:
            target: The :class:`~dissect.target.target.Target` object.
            sysvol: The filesystem that was detected in the ``detect()`` function.

        Returns:
            An instantiated version of the OSPlugin.
        """
        raise NotImplementedError

    @export(property=True)
    def hostname(self) -> str | None:
        """Return the target's hostname.

        Returns:
            The hostname as string.
        """
        raise NotImplementedError

    @export(property=True)
    def ips(self) -> list[str]:
        """Return the IP addresses configured in the target.

        Returns:
            The IPs as list.
        """
        raise NotImplementedError

    @export(property=True)
    def version(self) -> str | None:
        """Return the target's OS version.

        Returns:
            The OS version as string.
        """
        raise NotImplementedError

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        """Return the users available in the target.

        Returns:
            A list of user records.
        """
        raise NotImplementedError

    @export(property=True)
    def os(self) -> str:
        """Return a slug of the target's OS name.

        Returns:
            A slug of the OS name, e.g. 'windows' or 'linux'.
        """
        raise NotImplementedError

    @export(property=True)
    def architecture(self) -> str | None:
        """Return a slug of the target's OS architecture.

        Returns:
            A slug of the OS architecture, e.g. 'x86_32-unix', 'MIPS-linux' or
            'AMD64-win32', or 'unknown' if the architecture is unknown.
        """
        raise NotImplementedError


class ChildTargetPlugin(Plugin):
    """A Child target is a special plugin that can list more Targets.

    For example, :class:`~dissect.target.plugins.child.esxi.ESXiChildTargetPlugin` can
    list all of the Virtual Machines on the host.
    """

    __type__ = None

    def list_children(self) -> Iterator[ChildTargetRecord]:
        """Yield :class:`~dissect.target.helpers.record.ChildTargetRecord` records of all
        possible child targets on this target.
        """
        raise NotImplementedError


class NamespacePlugin(Plugin):
    """A namespace plugin provides services to access functionality from a group of subplugins.

    Support is currently limited to shared exported functions with output type ``record`` and ``yield``.
    """

    def __init_subclass__(cls, **kwargs):
        # Upon subclassing, decide whether this is a direct subclass of NamespacePlugin
        # If this is not the case, autogenerate aggregate methods for methods record output.

        # Do not process the "base" subclasses defined in this file
        if cls.__module__ == NamespacePlugin.__module__:
            super().__init_subclass__(**kwargs)
            return

        if cls.__bases__[0] not in (NamespacePlugin, InternalNamespacePlugin):
            # This is a subclass of a subclass of (Internal)NamespacePlugin
            # We need to aggregate the methods of this subclass
            cls.__findable__ = True
            # Run the normal subclass initialization first so the plugin gets all its exports registered
            super().__init_subclass__(**kwargs)
            cls.__init_subclass_subplugin__(cls, **kwargs)
            cls.__nsplugin__.__init_subclass__(**kwargs)
        else:
            # This is a direct subclass of (Internal)NamespacePlugin
            # Not much to do here, just do some initialization and register the plugin
            cls.__findable__ = False
            super().__init_subclass__(**kwargs)

            cls.__nsplugin__ = cls
            if not hasattr(cls, "__subplugins__"):
                cls.__subplugins__ = set()

    def __init_subclass_subplugin__(cls, **kwargs) -> None:
        # Register the current plugin class as a subplugin with
        # the direct subclass of NamespacePlugin
        cls.__nsplugin__.__subplugins__.add(cls.__namespace__)

        # Generate a tuple of class names for which we do not want to add subplugin functions, which is the
        # NamespacePlugin and all of its superclasses (minus the base object)
        reserved_cls = tuple({klass.__name__ for klass in cls.__nsplugin__.mro() if klass is not object})

        # Collect the public exports of the subplugin
        for export_name in cls.__exports__:
            export_attr = getattr(cls, export_name)

            # The export need to be callable and may not be part of a parent class
            if not isinstance(export_attr, Callable) or export_attr.__qualname__.startswith(reserved_cls):
                continue

            # The export needs to output records or yield something else
            if (output_type := export_attr.__output__) not in ["record", "yield"]:
                continue

            if aggregator := getattr(cls.__nsplugin__, export_name, None):
                # If we already have an aggregate method, update some fields
                if not hasattr(aggregator, "__subplugins__"):
                    # This is not an aggregator, but a re-implementation of a subclass method by the subplugin
                    continue

                if aggregator.__output__ != output_type:
                    # The output type of the existing aggregator is different, so we can't merge them
                    raise PluginError(
                        "Cannot merge namespace methods with different output types"
                        f" ({aggregator.__output__} != {output_type} in {cls.__namespace__}.{export_name})"
                    )

                # Update record descriptors
                if (export_attr.__record__, aggregator.__record__) != (None, None):
                    aggregator.__record__ = list(
                        set(_get_descriptors_on_method(export_attr) + _get_descriptors_on_method(aggregator))
                    )
            else:
                # Generate a method for the parent namespace class
                aggregator = export(
                    output=output_type,
                    record=export_attr.__record__,
                    cache=False,
                    cls=cls.__nsplugin__,
                )(cls.__generate_aggregator(cls.__nsplugin__, export_name))

                # Add to the parent namespace class
                setattr(cls.__nsplugin__, export_name, aggregator)

            # Add subplugin to aggregator
            aggregator.__subplugins__.append(cls.__namespace__)
            cls.__update_aggregator_docs(aggregator)

    def check_compatible(self) -> None:
        at_least_one = False
        for entry in self.__subplugins__:
            try:
                self.target.get_function(entry)
                at_least_one = True
            except UnsupportedPluginError:  # noqa: PERF203
                self.target.log.warning("Subplugin %s is not compatible with target", entry)
            except Exception as e:
                self.target.log.error("Failed to load subplugin: %s", entry)  # noqa: TRY400
                self.target.log.debug("", exc_info=e)

        if not at_least_one:
            raise UnsupportedPluginError("No compatible subplugins found")

    @staticmethod
    def __generate_aggregator(nsklass: type[NamespacePlugin], method_name: str) -> Callable:
        def aggregator(self: NamespacePlugin) -> Iterator[Record]:
            for ns in aggregator.__subplugins__:
                try:
                    yield from self.target.get_function(f"{ns}.{method_name}")[1]()
                except UnsupportedPluginError:  # noqa: PERF203
                    continue
                except Exception as e:
                    self.target.log.error("Subplugin %s.%s raised an exception", ns, method_name)  # noqa: TRY400
                    self.target.log.debug("", exc_info=e)

        # Holds the subplugins that share this method
        aggregator.__subplugins__ = []
        aggregator.__generated__ = True

        # Clone some names and attributes
        aggregator.__module__ = nsklass.__module__
        aggregator.__name__ = method_name
        aggregator.__qualname__ = f"{nsklass.__name__}.{method_name}"

        return aggregator

    @staticmethod
    def __update_aggregator_docs(aggregator: Callable) -> None:
        aggregator.__doc__ = f"Return {aggregator.__name__} for: {', '.join(aggregator.__subplugins__)}"


__INTERNAL_PLUGIN_METHOD_NAMES__ = {attr.__name__ for attr in _get_nonprivate_methods(Plugin)}


class InternalPlugin(Plugin):
    """Parent class for internal plugins.

    InternalPlugin marks all non-private methods internal by default
    (same as ``@internal`` decorator).
    """

    def __init_subclass__(cls, **kwargs):
        for method in _get_nonprivate_methods(cls):
            if callable(method) and method.__name__ not in __INTERNAL_PLUGIN_METHOD_NAMES__:
                method.__internal__ = True

        super().__init_subclass__(**kwargs)
        return cls


class InternalNamespacePlugin(NamespacePlugin, InternalPlugin):
    pass
