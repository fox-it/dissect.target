""" Dissect plugin system.

See dissect/target/plugins/general/example.py for an example plugin.
"""
from __future__ import annotations

import functools
import importlib
import logging
import os
import sys
import traceback
from itertools import tee
from types import FunctionType, GeneratorType
from typing import TYPE_CHECKING, Any, Callable, Iterator, Type

from dissect.target.exceptions import PluginError
from dissect.target.helpers import cache

try:
    from dissect.target.plugins._pluginlist import PLUGINS

    GENERATED = True
except Exception:
    PLUGINS = {}
    GENERATED = False

if TYPE_CHECKING:
    from dissect.target import Target
    from dissect.target.filesystem import Filesystem
    from flow.record import Record, RecordDescriptor

Tee = tee([], 1)[0].__class__
PluginDescriptor = dict[str, Any]

MODULE_PATH = "dissect.target.plugins"
OUTPUTS = (
    "default",
    "record",
    "yield",
    "none",
)
CLASS_ATTRIBUTES = (
    "__plugin__",
    "__exported__",
    "__internal__",
    "__functions__",
    "__exports__",
)
METHOD_ATTRIBUTES = (
    "__exported__",
    "__internal__",
    "__output__",
    "__record__",
    "__args__",
)


log = logging.getLogger(__name__)


class Category:
    PERSISTENCE = "persistence"


def export(*args, **kwargs) -> Callable:
    """Decorator to be used on Plugin functions that should be exported.

    Supported keyword arguments:
        property (bool): Whether this export should be regarded as a property.
            Properties are implicitly cached.
        cache (bool): Whether the result of this function should be cached.
        record (RecordDescriptor): The ``RecordDescriptor`` for the records that this function yields.
            If the records are dynamically made, use DynamicRecord instead.
        output (str): The output type of this function. Can be one of:

        - default: Single return value
        - record: Yields records. Implicit when record argument is given.
        - yield: Yields printable values.
        - none: No return value.

    Raises:
        ValueError: if there was an invalid output type.

    Returns:
        An exported function from a plugin.
    """

    def decorator(obj):
        # Properties are implicitly cached
        obj = cache.wrap(obj)

        output = kwargs.get("output", "default")
        if output not in OUTPUTS:
            options = ", ".join(OUTPUTS)
            raise ValueError(f'Invalid output method "{output}", must be one of {options}')

        record = kwargs.get("record", None)
        if record is not None:
            output = "record"

        obj.__output__ = output
        obj.__record__ = record
        obj.__exported__ = True

        if kwargs.get("property", False):
            obj = property(obj)

        return obj

    if len(args) == 1:
        return decorator(args[0])
    else:
        return decorator


def get_nonprivate_attribute_names(cls: Type[Plugin]) -> list[str]:
    """Retrieve all attributes that do not start with ``_``."""
    return [attr for attr in dir(cls) if not attr.startswith("_")]


def get_nonprivate_attributes(cls: Type[Plugin]) -> list[Any]:
    """Retrieve all attributes from a :class:`Plugin`."""
    # Note: `dir()` might return attributes from parent class
    return [getattr(cls, attr) for attr in get_nonprivate_attribute_names(cls)]


def get_nonprivate_methods(cls: Type[Plugin]) -> list[Callable]:
    """Retrieve all methods from a :class:`Plugin`."""
    return [attr for attr in get_nonprivate_attributes(cls) if not isinstance(attr, property)]


def get_descriptors_on_nonprivate_methods(cls: Type[Plugin]) -> list[RecordDescriptor]:
    """Return record descriptors set on nonprivate methods in `cls` class."""
    descriptors = set()
    methods = get_nonprivate_methods(cls)

    for m in methods:
        if not hasattr(m, "__record__"):
            continue

        record = m.__record__
        if not record:
            continue

        try:
            # check if __record__ value is iterable (for example, a list)
            descriptors.update(record)
        except TypeError:
            descriptors.add(record)
    return list(descriptors)


class Plugin:
    """Base class for plugins.

    Plugins can optionally be namespaced by specifying the __namespace__
    class attribute. Namespacing results in your plugin needing to be prefixed
    with this namespace when being called. For example, if your plugin has
    specified "test" as namespace and a function called "example", you must
    call your plugin with "test.example".

    Example:
        __namespace__ = 'test'

    Plugins can also specify one or more categories they belong to. They can do
    this by importing the Category enum from dissect.target.plugin and specifying
    them in a list in the __categories__ class attribute.

    Example:
        __categories__ = [Category.PERSISTENCE]

    Args:
        target: The :class:`~dissect.target.target.Target` object to load the plugin for.

    """

    __namespace__ = None
    __categories__ = None

    __record_descriptors__ = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Do not register the "base" subclassess `OSPlugin` and `ChildTargetPlugin`
        if cls.__name__ not in ("OSPlugin", "ChildTargetPlugin"):
            register(cls)

        record_descriptors = get_descriptors_on_nonprivate_methods(cls)
        cls.__record_descriptors__ = record_descriptors
        cls.get_all_records = export(output="record", record=record_descriptors)(cls.get_all_records)

    def __init__(self, target: Target):
        self.target = target

    def check_compatible(self) -> None:
        """Perform a compatibility check with the target.

        This function should return True or False on whether it's compatible
        with the current target (self.target). For example, check if a certain
        file exists.

        Should either return None or raise an exception.
        """
        raise NotImplementedError

    def get_all_records(self) -> Iterator[Record]:
        """Return the records from all exported methods."""
        if not self.__namespace__:
            raise PluginError(f"Plugin {self.__class__.__name__} is not a namespace plugin")

        for method_name in self.__exports__:
            method = getattr(self, method_name)

            try:
                yield from method()
            except Exception:
                full_name = f"{self.__namespace__}.{method_name}" if self.__namespace__ else method_name
                self.target.log.error("Error while executing `%s`", full_name, exc_info=True)

    def __call__(self, *args, **kwargs):
        """A shortcut to :func:`get_all_records`."""
        if not self.__namespace__:
            raise PluginError(f"Plugin {self.__class__.__name__} is not a callable")
        return self.get_all_records()


class OSPlugin(Plugin):
    """Base class for OS plugins.

    This provides a baseclass for certain common functions of OS's.
    Which each OS plugin has to implement seperately.

    As an example, it provides an interface for retrieving the hostname, and its users.
    """

    def check_compatible(self) -> bool:
        """OSPlugin's use a different compatibility check, override the default one."""
        return True

    def detect(cls, fs: Filesystem) -> bool:
        """Provide detection of this OSPlugin on a given filesystem.

        Note: must be implemented as a classmethod.

        Args:
            fs: :class:`~dissect.target.filesystem.Filesystem` to detect the OS on.

        Returns:
            ``True`` if the OS was detected on the filesystem, else ``False``.
        """
        raise NotImplementedError

    def create(cls, target: Target, sysvol: Filesystem) -> None:
        """Initiate this OSPlugin with the given target and detected filesystem.

        Note: must be implemented as a classmethod.

        Args:
            target: The Target object.
            sysvol: The filesystem that was detected in the detect() function.
        """
        raise NotImplementedError

    def hostname(self) -> str:
        """Required OS function.

        Implementations must be decorated with @export(property=True)

        Returns:
            The hostname as string.
        """
        raise NotImplementedError

    def ips(self) -> list[str]:
        """Required OS function.

        Implementations must be decorated with @export(property=True)

        Returns:
            The IPs as list.
        """
        raise NotImplementedError

    def version(self) -> str:
        """Required OS function.

        Implementations must be decorated with @export(property=True)

        Returns:
            The OS version as string.
        """
        raise NotImplementedError

    def users(self) -> list[Record]:
        """Required OS function.

        Implementations must be decorated with @export

        Returns:
            A list of user records.
        """
        raise NotImplementedError

    def os(self) -> str:
        """Required OS function.

        Implementations must be decorated with export(property=True)

        Returns:
            A slug of the OS name, e.g. 'windows' or 'linux'.
        """
        raise NotImplementedError


class ChildTargetPlugin(Plugin):
    """A Child target is a special plugin that can list more Targets.

    Take :class:`~dissect.target.plugins.child.esxi.ESXiChildTargetPlugin` as an example.
    It can list all of the Virtual Machines on the host, so dissect can open them on that host.
    """

    __type__ = None

    def list_children(self) -> list[Target]:
        """List all the additional ``Targets`` available on the image."""
        raise NotImplementedError


def register(plugincls: Type[Plugin]) -> None:
    """Register a plugin, and put related data inside :attr:`PLUGINS`.

    Args:
        plugincls: A plugin to register.
    """
    if not issubclass(plugincls, Plugin):
        raise ValueError("Not a subclass of Plugin")

    exports = []
    functions = []

    for attr in get_nonprivate_attributes(plugincls):
        if isinstance(attr, property):
            attr = attr.fget

        if getattr(attr, "__exported__", False):
            exports.append(attr.__name__)
            functions.append(attr.__name__)

        if getattr(attr, "__internal__", False):
            functions.append(attr.__name__)

    plugincls.__plugin__ = True
    plugincls.__functions__ = functions
    plugincls.__exports__ = exports

    modpath = _modulepath(plugincls)
    lookup_path = modpath
    if modpath.endswith("._os"):
        lookup_path, _, _ = modpath.rpartition(".")

    root = _traverse(lookup_path, PLUGINS)

    log.debug("Plugin registered: %s.%s", plugincls.__module__, plugincls.__qualname__)

    if issubclass(plugincls, (OSPlugin, ChildTargetPlugin)):
        if issubclass(plugincls, OSPlugin):
            special_key = "_os"
        elif issubclass(plugincls, ChildTargetPlugin):
            special_key = "_child"

        if special_key not in root:
            root[special_key] = []
        else:
            plugins = [obj for obj in root[special_key] if obj["class"] == plugincls.__name__]
            if len(plugins):
                return

        special_root = {}
        root[special_key].append(special_root)
        root = special_root

    # Check if the plugin was already registered
    if "class" in root and root["class"] == plugincls.__name__:
        return

    # Finally register the plugin
    root["class"] = plugincls.__name__
    root["module"] = modpath
    root["functions"] = plugincls.__functions__
    root["exports"] = plugincls.__exports__
    root["namespace"] = plugincls.__namespace__
    root["categories"] = plugincls.__categories__
    root["fullname"] = ".".join((plugincls.__module__, plugincls.__qualname__))


def internal(*args, **kwargs) -> Callable:
    """Decorator to be used on Plugin functions that should be internal only."""

    def decorator(obj):
        obj.__internal__ = True
        if kwargs.get("property", False):
            obj = property(obj)
        return obj

    if len(args) == 1:
        return decorator(args[0])
    else:
        return decorator


def _cache_function(func: FunctionType) -> Callable:
    fname = func.__name__

    @functools.wraps(func)
    def cache_wrapper(*args, **kwargs):
        tcache = args[0].target._cache
        fcache = tcache.get(fname, None)
        if fcache is None:
            fcache = {}
            tcache[fname] = fcache

        key = (args, frozenset(sorted(kwargs.items())))
        if key not in fcache:
            fcache[key] = func(*args, **kwargs)

        if isinstance(fcache[key], (GeneratorType, Tee)):
            # the original can't be used any more,
            # so we need to change the cache as well
            fcache[key], r = tee(fcache[key])
            return r
        return fcache[key]

    return cache_wrapper


def arg(*args, **kwargs) -> Callable:
    """Decorator to be used on Plugin functions that accept additional command line arguments.

    Command line arguments can be added using the @arg decorator.
    Arguments to this decorator are directly forwarded to the ArgumentParser.add_argument functionof argparse.
    Resulting arguments are passed to the function using kwargs.
    The keyword argument name must match the argparse argument name.
    """

    def decorator(obj):
        if not hasattr(obj, "__args__"):
            obj.__args__ = []
        arglist = getattr(obj, "__args__", [])
        arglist.append((args, kwargs))
        return obj

    return decorator


def plugins(osfilter: str = None) -> Iterator[PluginDescriptor]:
    """Retrieve all plugin descriptors.

    Args:
        osfilter: For filtering which os to use.

    Returns:
        An iterator going through plugin descriptors.
    """

    def _walk(osfilter: str = None, root: dict = None) -> Iterator[PluginDescriptor]:
        for key, obj in root.items():
            if key.startswith("_"):
                continue

            if "functions" not in obj:
                for plugin_desc in _walk(osfilter, obj):
                    yield plugin_desc
            else:
                if osfilter and obj["module"].startswith("os") and not obj["module"].startswith(osfilter):
                    continue

                yield obj

    if (
        osfilter
        and isinstance(osfilter, type)
        and issubclass(osfilter, OSPlugin)
        and osfilter.__module__.startswith(MODULE_PATH)
    ):
        osfilter, _, _ = osfilter.__module__.replace(MODULE_PATH, "", 1).strip(".").rpartition(".")
        # NOTE: A dirty fix to ensure OS plugins are filtered by the top level OS name
        # As an example, it uses os.unix instead of os.unix.debian
        osfilter = ".".join(osfilter.split(".")[:2])
    else:
        osfilter = None

    yield from _walk(osfilter, _get_plugins())


def _special_plugins(special_key: str) -> Iterator[PluginDescriptor]:
    """Retrieve plugin descriptors stored under ``special_key``."""

    def _walk(root=None):
        for key, obj in root.items():
            if key == special_key:
                yield from obj

            elif key.startswith("_"):
                continue

            elif "functions" not in obj:
                yield from _walk(obj)

    yield from _walk(_get_plugins())


def os_plugins() -> Iterator[PluginDescriptor]:
    """Retrieve all OS plugin descriptors."""
    yield from _special_plugins("_os")


def child_plugins() -> Iterator[PluginDescriptor]:
    """Retrieve all child plugin descriptors."""
    yield from _special_plugins("_child")


def lookup(func_name: str, osfilter: str = None) -> Iterator[PluginDescriptor]:
    """Lookup a plugin descriptor by function name.

    Args:
        func_name (str): Function name to lookup.
        osfilter (str): OS path the plugin should be from.
    """
    yield from get_plugins_by_func_name(func_name, osfilter=osfilter)
    yield from get_plugins_by_namespace(func_name, osfilter=osfilter)


def get_plugins_by_func_name(func_name: str, osfilter: str = None) -> Iterator[PluginDescriptor]:
    """Get a plugin descriptor by function name.

    Args:
        func_name (str): Function name to lookup.
        osfilter (str): OS path the plugin should be from.
    """
    for plugin_desc in plugins(osfilter):
        if not plugin_desc["namespace"] and func_name in plugin_desc["functions"]:
            yield plugin_desc


def get_plugins_by_namespace(namespace: str, osfilter: str = None) -> Iterator[PluginDescriptor]:
    """Get a plugin descriptor by namespace

    Args:
        func_name: Function name to lookup.
        osfilter: OS path the plugin should be from.
    """
    for plugin_desc in plugins(osfilter):
        if namespace == plugin_desc["namespace"]:
            yield plugin_desc


def load(plugin_desc: dict) -> Type[Plugin]:
    """Helper function that loads a plugin from a given plugin description.

    Args:
        plugin_desc: Plugin description as returned by plugin.lookup().

    Returns:
        The plugin class.

    Raises:
        PluginError: Raised when any other exception occurs while trying to load the plugin.
    """
    module = plugin_desc["module"]
    if module.startswith("dissect.target"):
        name_to_load = module
    else:
        name_to_load = ".".join([MODULE_PATH, module])

    try:
        module = importlib.import_module(name_to_load)
        return getattr(module, plugin_desc["class"])
    except Exception as e:
        raise PluginError(f"An exception occurred while trying to load a plugin: {module}", cause=e)


def failed() -> list[dict[str, Any]]:
    """Return all plugins that failed to load."""
    return _get_plugins().get("_failed", [])


def _get_plugins() -> dict[str, PluginDescriptor]:
    """Load all plugins in global namespace."""
    global PLUGINS, GENERATED
    if not GENERATED:
        PLUGINS = generate()
        GENERATED = True
    return PLUGINS


def save_plugin_import_failure(module: str) -> None:
    """Store errors during plugin import."""
    stacktrace = traceback.format_exception(*sys.exc_info())
    PLUGINS["_failed"].append(
        {
            "module": module,
            "stacktrace": stacktrace,
        }
    )


def generate() -> dict[str, Any]:
    """Internal function to generate the list of available plugins.

    Walks the plugins directory and imports any .py files in there.
    Plugins will be automatically registered due to the decorators on them.

    Returns:
        The global ``PLUGINS`` dictionary.
    """
    global PLUGINS

    if "_failed" not in PLUGINS:
        PLUGINS["_failed"] = []

    plugins_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "plugins")
    for path, _, files in os.walk(plugins_dir):
        path = path.replace(plugins_dir, "").replace(os.sep, ".").lstrip(".")

        if not len(path) or "__pycache__" in path:
            continue

        mod = ".".join([MODULE_PATH, path])

        try:
            importlib.import_module(mod)
        except Exception as e:
            log.error("Unable to import %s", mod)
            log.debug("Error while trying to import module %s", mod, exc_info=e)
            save_plugin_import_failure(mod)

        for f in files:
            if f.endswith(".py") and not f.startswith("__init__"):
                name = f.split(".py")[0]
                modf = ".".join([mod, name])

                try:
                    importlib.import_module(modf)
                except Exception as e:
                    log.error("Unable to import %s", modf)
                    log.debug("Error while trying to import module %s", modf, exc_info=e)
                    save_plugin_import_failure(modf)

    return PLUGINS


def _traverse(key: str, obj: dict[str, Any]) -> dict[str, Any]:
    """Split a module path up in a dictionary."""
    for p in key.split("."):
        if p not in obj:
            obj[p] = {}

        obj = obj[p]

    return obj


def _modulepath(cls) -> str:
    """Returns a modulepath of a :class:`Plugin` relative to ``dissect.target.plugins``."""
    return cls.__module__.replace(MODULE_PATH, "").lstrip(".")


def get_plugin_classes_with_method(method_name: str) -> Iterator[Type[Plugin]]:
    """Returns an iterator of plugin classess that have a method that matches ``method_name``."""
    for desc in get_plugins_by_func_name(method_name):
        try:
            yield load(desc)
        except PluginError:
            pass

    if method_name in get_nonprivate_attribute_names(OSPlugin):
        yield OSPlugin


def get_plugin_classes_by_namespace(namespace: str) -> Iterator[Type[Plugin]]:
    """Returns an iterator of plugin classess that have ``__namespace__`` defined that matches ``namespace``."""
    for desc in get_plugins_by_namespace(namespace):
        try:
            yield load(desc)
        except PluginError:
            pass


# Needs to be at the bottom of the module because __init_subclass__ requires everything
# in the parent class Plugin to be defined and resolved.
class InternalPlugin(Plugin):
    """Parent class for internal plugins.

    InternalPlugin marks all non-private methods internal by default
    (same as @internal decorator).
    """

    def __init_subclass__(cls, **kwargs):

        for method in get_nonprivate_methods(cls):
            if callable(method):
                method.__internal__ = True

        super().__init_subclass__(**kwargs)
        return cls
