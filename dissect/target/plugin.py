""" Dissect plugin system.

See dissect/target/plugins/general/example.py for an example plugin.
"""
import enum
import functools
import importlib
import logging
import os
import sys
import traceback

from itertools import tee
from types import GeneratorType
from typing import Type, List, Callable, Any, Generator

from dissect.target.exceptions import PluginError
from dissect.target.helpers import cache
from dissect.target.helpers.record import RecordDescriptor

try:
    from dissect.target.plugins._pluginlist import PLUGINS

    GENERATED = True
except Exception:
    PLUGINS = {}
    GENERATED = False

Tee = tee([], 1)[0].__class__

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


class OperatingSystem(enum.Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    ESXI = "exsi"
    BSD = "bsd"
    OSX = "osx"
    UNIX = "unix"
    ANDROID = "android"
    VYOS = "vyos"
    IOS = "ios"
    FORTIGATE = "fortigate"


def export(*args, **kwargs):
    """Decorator to be used on Plugin functions that should be exported.

    Supported keyword arguments:
        property (bool): Whether this export should be regarded as a property.
            Properties are implicitly cached.
        cache (bool): Whether the result of this function should be cached.
        record (RecordDescriptor): The RecordDescriptor for the records that this function yields.
            If the records are dynamically made, use DynamicRecord instead.
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


def internal(*args, **kwargs):
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


def get_nonprivate_attribute_names(cls: Type["Plugin"]) -> List[str]:
    return [attr for attr in dir(cls) if not attr.startswith("_")]


def get_nonprivate_attributes(cls: Type["Plugin"]) -> List[Any]:
    # Note: `dir()` might return attributes from parent class
    return [getattr(cls, attr) for attr in get_nonprivate_attribute_names(cls)]


def get_nonprivate_methods(cls: Type["Plugin"]) -> List[Callable]:
    return [attr for attr in get_nonprivate_attributes(cls) if not isinstance(attr, property)]


def get_descriptors_on_nonprivate_methods(cls: Type["Plugin"]):
    """Return record descriptors set on nonprivate methods in `cls` class"""
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
    """Base class for plugins."""

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

    def __init__(self, target):
        self.target = target

    def check_compatible(self):
        """Check for plugin compatibility.

        Should either return None or raise an exception.
        """
        raise NotImplementedError

    def get_all_records(self):
        """Return the records from all exported methods"""
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
        """A shortcut to `get_all_records` method"""
        if not self.__namespace__:
            raise PluginError(f"Plugin {self.__class__.__name__} is not a callable")
        return self.get_all_records()


class OSPlugin(Plugin):
    """Base class for OS plugins."""

    def check_compatible(self):
        """OSPlugin's use a different compatibility check, override the default one."""
        return True

    @internal(property=True)
    def os_all(self) -> list[str]:
        """Walk the OSPlugin MRO and return a list of all detected operating systems.

        Returns:
            A list of static os strings detected, like 'windows', 'linux', 'bsd'
        """
        os_objects = []

        for os_plugin in self.__class__.__mro__:
            if issubclass(os_plugin, OSPlugin) and os_plugin is not OSPlugin:
                os_objects.append(os_plugin.os.__get__(self))
        return os_objects

    def detect(cls, target):
        """Provide detection of this OSPlugin on a given target.

        Note: must be implemented as a classmethod.

        Args:
            target: Target to detect the OS on.

        Returns:
            The filesystem of the OS that was detected, else None
        """
        raise NotImplementedError

    def create(cls, target, sysvol) -> "OSPlugin":
        """Initiate this OSPlugin with the given target and detected filesystem.

        Note: must be implemented as a classmethod.

        Args:
            target: The Target object.
            sysvol: The filesystem that was detected in the detect() function.

        Returns:
            An instance of this OSPlugin class.
        """
        raise NotImplementedError

    def hostname(self) -> str:
        """Required OS function. Returns the hostname as string.

        Implementations must be decorated with @export(property=True)
        """
        raise NotImplementedError

    def ips(self) -> list[str]:
        """Required OS function. Returns the IPs as list.

        Implementations must be decorated with @export(property=True)
        """
        raise NotImplementedError

    def version(self) -> str:
        """Required OS function. Returns the OS version as string.

        Implementations must be decorated with @export(property=True)
        """
        raise NotImplementedError

    def users(self) -> RecordDescriptor:
        """Required OS function. Returns the available users as Records

        Implementations must be decorated with @export
        """
        raise NotImplementedError

    def os(self) -> str:
        """Required OS function. Returns a slug of the OS name, e.g. 'windows' or 'linux'.

        Implementations must be decorated with @export(property=True)
        """
        raise NotImplementedError

    def architecture(self) -> str:
        """Required OS function. Return the target triples of a system as a string. Of which the vendor can be optional.

        Implementations must be decorated with @export(property=True)

        Returns:
            String: machine-vendor-os
        """
        raise NotImplementedError

    def distribution(self) -> str:
        """Required OS function. Return a slug of the distribution name of the system, e.g. 'Debian' or 'Gentoo'

        Implementations must be decorated with @export(property=True)
        """
        raise NotImplementedError


class ChildTargetPlugin(Plugin):
    __type__ = None

    def list_children(self):
        raise NotImplementedError


def register(plugincls):
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


def _cache_function(func):
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


def arg(*args, **kwargs):
    """Decorator to be used on Plugin functions that accept additional command line arguments.

    Any arguments passed to this decorator are passed directly into ArgumentParser.add_argument.
    """

    def decorator(obj):
        if not hasattr(obj, "__args__"):
            obj.__args__ = []
        arglist = getattr(obj, "__args__", [])
        arglist.append((args, kwargs))
        return obj

    return decorator


def plugins(osfilter=None):
    """Retrieve all plugin descriptors."""

    def _walk(osfilter=None, root=None):
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

    for plugin_desc in _walk(osfilter, _get_plugins()):
        yield plugin_desc


def _special_plugins(special_key):
    """Retrieve plugin descriptors stored under a special key."""

    def _walk(root=None):
        for key, obj in root.items():
            if key == special_key:
                yield from obj

            elif key.startswith("_"):
                continue

            elif "functions" not in obj:
                yield from _walk(obj)

    yield from _walk(_get_plugins())


def os_plugins():
    """Retrieve all OS plugin descriptors."""
    yield from _special_plugins("_os")


def child_plugins():
    """Retrieve all child plugin descriptors."""
    yield from _special_plugins("_child")


def lookup(func_name, osfilter=None):
    """Lookup a plugin descriptor by function name.

    Args:
        func_name (str): Function name to lookup.
        osfilter (str): OS path the plugin should be from.
    """
    yield from get_plugins_by_func_name(func_name, osfilter=osfilter)
    yield from get_plugins_by_namespace(func_name, osfilter=osfilter)


def get_plugins_by_func_name(func_name, osfilter=None):
    """Get a plugin descriptor by function name.

    Args:
        func_name (str): Function name to lookup.
        osfilter (str): OS path the plugin should be from.
    """
    for plugin_desc in plugins(osfilter):
        if not plugin_desc["namespace"] and func_name in plugin_desc["functions"]:
            yield plugin_desc


def get_plugins_by_namespace(namespace, osfilter=None):
    """Get a plugin descriptor by namespace

    Args:
        func_name (str): Function name to lookup.
        osfilter (str): OS path the plugin should be from.
    """
    for plugin_desc in plugins(osfilter):
        if namespace == plugin_desc["namespace"]:
            yield plugin_desc


def load(plugin_desc):
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


def failed():
    """Return all plugins that failed to load."""
    return _get_plugins().get("_failed", [])


def _get_plugins():
    global PLUGINS, GENERATED
    if not GENERATED:
        PLUGINS = generate()
        GENERATED = True
    return PLUGINS


def save_plugin_import_failure(module: str) -> None:
    stacktrace = traceback.format_exception(*sys.exc_info())
    PLUGINS["_failed"].append(
        {
            "module": module,
            "stacktrace": stacktrace,
        }
    )


def generate():
    """Internal function to generate the list of available plugins.

    Walks the plugins directory and imports any .py files in there.
    Plugins will be automatically registered due to the decorators on them.
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


def _traverse(key, obj):
    for p in key.split("."):
        if p not in obj:
            obj[p] = {}

        obj = obj[p]

    return obj


def _modulepath(cls):
    return cls.__module__.replace(MODULE_PATH, "").lstrip(".")


def get_plugin_classes_with_method(method_name: str) -> Generator[Type[Plugin], None, None]:
    """Yield plugin classess that have a method that matches value in `method_name`"""
    for desc in get_plugins_by_func_name(method_name):
        try:
            yield load(desc)
        except PluginError:
            pass

    if method_name in get_nonprivate_attribute_names(OSPlugin):
        yield OSPlugin


def get_plugin_classes_by_namespace(namespace: str) -> Generator[Type[Plugin], None, None]:
    """Yield plugin classess that have __namespace__ defined that matches provided namespace"""
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
