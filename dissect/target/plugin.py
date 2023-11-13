"""Dissect plugin system.

See dissect/target/plugins/general/example.py for an example plugin.
"""
from __future__ import annotations

import fnmatch
import importlib
import importlib.util
import inspect
import logging
import os
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterator, Optional, Type

from flow.record import Record, RecordDescriptor

import dissect.target.plugins.general as general
from dissect.target.exceptions import PluginError, UnsupportedPluginError
from dissect.target.helpers import cache
from dissect.target.helpers.record import EmptyRecord
from dissect.target.helpers.utils import StrEnum

try:
    from dissect.target.plugins._pluginlist import PLUGINS

    GENERATED = True
except Exception:
    PLUGINS = {}
    GENERATED = False

if TYPE_CHECKING:
    from dissect.target import Target
    from dissect.target.filesystem import Filesystem
    from dissect.target.helpers.record import ChildTargetRecord

PluginDescriptor = dict[str, Any]
"""A dictionary type, for what the plugin descriptor looks like."""

MODULE_PATH = "dissect.target.plugins"
"""The base module path to the in-tree plugins."""
OUTPUTS = (
    "default",
    "record",
    "yield",
    "none",
)
"""The different output types supported by ``@export``."""

log = logging.getLogger(__name__)


class OperatingSystem(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    ESXI = "esxi"
    BSD = "bsd"
    OSX = "osx"
    UNIX = "unix"
    ANDROID = "android"
    VYOS = "vyos"
    IOS = "ios"
    FORTIGATE = "fortigate"
    CITRIX = "citrix-netscaler"


def export(*args, **kwargs) -> Callable:
    """Decorator to be used on Plugin functions that should be exported.

    Supported keyword arguments:
        property (bool): Whether this export should be regarded as a property.
            Properties are implicitly cached.
        cache (bool): Whether the result of this function should be cached.
        record (RecordDescriptor): The :class:`flow.record.RecordDescriptor` for the records that this function yields.
            If the records are dynamically made, use DynamicRecord instead.
        output (str): The output type of this function. Can be one of:

        - default: Single return value
        - record: Yields records. Implicit when record argument is given.
        - yield: Yields printable values.
        - none: No return value.

    The ``export`` decorator adds some additional private attributes to an exported method or property:

    - ``__output__``: The output type to expect for this function, this is the same as ``output``.
    - ``__record__``: The type of record to expect, this value is the same as ``record``.
    - ``__exported__``: set to ``True`` to indicate the method or property is exported.

    Raises:
        ValueError: if there was an invalid output type.

    Returns:
        An exported function from a plugin.
    """

    def decorator(obj):
        # Properties are implicitly cached
        # Important! Currently it's crucial that this is *always* called
        # See the comment in Plugin.__init_subclass__ for more detail regarding Plugin.get_all_records
        obj = cache.wrap(obj, no_cache=not kwargs.get("cache", True), cls=kwargs.get("cls", None))

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
    """Retrieve all public attributes of a :class:`Plugin`."""
    # Note: `dir()` might return attributes from parent class
    return [getattr(cls, attr) for attr in get_nonprivate_attribute_names(cls)]


def get_nonprivate_methods(cls: Type[Plugin]) -> list[Callable]:
    """Retrieve all public methods of a :class:`Plugin`."""
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

    Plugins can optionally be namespaced by specifying the ``__namespace__``
    class attribute. Namespacing results in your plugin needing to be prefixed
    with this namespace when being called. For example, if your plugin has
    specified ``test`` as namespace and a function called ``example``, you must
    call your plugin with ``test.example``::

    A ``Plugin`` class has the following private class attributes:

    - ``__namespace__``
    - ``__record_descriptors__``

    With the following three being assigned in :func:`register`:

    - ``__plugin__``
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
    __skip__: bool = False
    """Prevents plugin functions from indexing this plugin at all."""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Do not register the "base" subclassess `OSPlugin` and `ChildTargetPlugin`
        if cls.__name__ not in ("OSPlugin", "ChildTargetPlugin") and cls.__register__:
            register(cls)

        record_descriptors = get_descriptors_on_nonprivate_methods(cls)
        cls.__record_descriptors__ = record_descriptors
        # This is a bit tricky currently
        # cls.get_all_records is the *function* Plugin.get_all_records, not from the subclass
        # export() currently will _always_ return a new object because it always calls ``cache.wrap(obj)``
        # This allows this to work, otherwise the Plugin.get_all_records would get all the plugin attributes set on it
        cls.get_all_records = export(output="record", record=record_descriptors, cache=False, cls=cls)(
            cls.get_all_records
        )

    def __init__(self, target: Target):
        self.target = target

    def is_compatible(self) -> bool:
        """Perform a compatibility check with the target."""
        try:
            self.check_compatible()
        except Exception:
            return False

        return True

    def check_compatible(self) -> None:
        """Perform a compatibility check with the target.

        This function should return ``None`` if the plugin is compatible with
        the current target (``self.target``). For example, check if a certain
        file exists.
        Otherwise it should raise an ``UnsupportedPluginError``.

        Raises:
            UnsupportedPluginError: If the plugin could not be loaded.
        """
        raise NotImplementedError

    def get_all_records(self) -> Iterator[Record]:
        """Return the records of all exported methods.

        Raises:
            PluginError: If the subclass is not a namespace plugin.
        """
        if not self.__namespace__:
            raise PluginError(f"Plugin {self.__class__.__name__} is not a namespace plugin")

        for method_name in self.__exports__:
            method = getattr(self, method_name)

            try:
                yield from method()
            except Exception:
                self.target.log.error("Error while executing `%s.%s`", self.__namespace__, method_name, exc_info=True)

    def __call__(self, *args, **kwargs):
        """A shortcut to :func:`get_all_records`.

        Raises:
            PluginError: If the subclass is not a namespace plugin.
        """
        if not self.__namespace__:
            raise PluginError(f"Plugin {self.__class__.__name__} is not a callable")
        return self.get_all_records()


class OSPlugin(Plugin):
    """Base class for OS plugins.

    This provides a base class for certain common functions of OS's, which each OS plugin has to implement separately.

    For example, it provides an interface for retrieving the hostname and users of a target.
    """

    def check_compatible(self) -> bool:
        """OSPlugin's use a different compatibility check, override the default one."""
        return True

    @classmethod
    def detect(cls, fs: Filesystem) -> Optional[Filesystem]:
        """Provide detection of this OSPlugin on a given filesystem.

        Note: must be implemented as a classmethod.

        Args:
            fs: :class:`~dissect.target.filesystem.Filesystem` to detect the OS on.

        Returns:
            The root filesystem / sysvol when found.
        """
        raise NotImplementedError

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> OSPlugin:
        """Initiate this OSPlugin with the given target and detected filesystem.

        Note: must be implemented as a classmethod.

        Args:
            target: The Target object.
            sysvol: The filesystem that was detected in the detect() function.

        Returns:
            An instantiated version of the OSPlugin.
        """
        raise NotImplementedError

    @export(property=True)
    def hostname(self) -> Optional[str]:
        """Required OS function.

        Implementations must be decorated with ``@export(property=True)``.

        Returns:
            The hostname as string.
        """
        raise NotImplementedError

    @export(property=True)
    def ips(self) -> list[str]:
        """Required OS function.

        Implementations must be decorated with ``@export(property=True)``.

        Returns:
            The IPs as list.
        """
        raise NotImplementedError

    @export(property=True)
    def version(self) -> Optional[str]:
        """Required OS function.

        Implementations must be decorated with ``@export(property=True)``.

        Returns:
            The OS version as string.
        """
        raise NotImplementedError

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        """Required OS function.

        Implementations must be decorated with @export.

        Returns:
            A list of user records.
        """
        raise NotImplementedError

    @export(property=True)
    def os(self) -> str:
        """Required OS function.

        Implementations must be decorated with ``@export(property=True)``.

        Returns:
            A slug of the OS name, e.g. 'windows' or 'linux'.
        """
        raise NotImplementedError

    @export(property=True)
    def architecture(self) -> Optional[str]:
        """Required OS function.

        Implementations must be decorated with ``@export(property=True)``.

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


def register(plugincls: Type[Plugin]) -> None:
    """Register a plugin, and put related data inside :attr:`PLUGINS`.

    This function uses the following private attributes that are set using decorators:

    - ``__exported__``: Set in :func:`export`.
    - ``__internal__``: Set in :func:`internal`.

    Additionally, ``register`` sets the following private attributes on the `plugincls`:

    - ``__plugin__``: Always set to ``True``.
    - ``__functions__``: A list of all the methods and properties that are ``__internal__`` or ``__exported__``.
    - ``__exports__``: A list of all the methods or properties that were explicitly exported.

    Args:
        plugincls: A plugin class to register.

    Raises:
        ValueError: If ``plugincls`` is not a subclass of :class:`Plugin`.
    """
    if not issubclass(plugincls, Plugin):
        raise ValueError("Not a subclass of Plugin")

    exports = []
    functions = []

    for attr in get_nonprivate_attributes(plugincls):
        if isinstance(attr, property):
            attr = attr.fget

        if getattr(attr, "__autogen__", False) and plugincls != plugincls.__nsplugin__:
            continue

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
    root["fullname"] = ".".join((plugincls.__module__, plugincls.__qualname__))


def internal(*args, **kwargs) -> Callable:
    """Decorator to be used on plugin functions that should be internal only.

    Making a plugin internal means that it's only callable from the Python API and not through ``target-query``.

    This decorator adds the ``__internal__`` private attribute to a method or property.
    The attribute is always set to ``True``, to tell :func:`register` that it is an internal
    method or property.
    """

    def decorator(obj):
        obj.__internal__ = True
        if kwargs.get("property", False):
            obj = property(obj)
        return obj

    if len(args) == 1:
        return decorator(args[0])
    else:
        return decorator


def arg(*args, **kwargs) -> Callable:
    """Decorator to be used on Plugin functions that accept additional command line arguments.

    Command line arguments can be added using the ``@arg`` decorator.
    Arguments to this decorator are directly forwarded to the ``ArgumentParser.add_argument`` function of ``argparse``.
    Resulting arguments are passed to the function using kwargs.
    The keyword argument name must match the argparse argument name.

    This decorator adds the ``__args__`` private attribute to a method or property.
    This attribute holds all the command line arguments that were added to the plugin function.
    """

    def decorator(obj):
        if not hasattr(obj, "__args__"):
            obj.__args__ = []
        arglist = getattr(obj, "__args__", [])
        arglist.append((args, kwargs))
        return obj

    return decorator


def plugins(osfilter: Optional[type[OSPlugin]] = None) -> Iterator[PluginDescriptor]:
    """Retrieve all plugin descriptors.

    Args:
        osfilter: The ``OSPlugin`` to use as template to find os specific plugins for.

    Returns:
        An iterator of all plugin descriptors, optionally filtered on OS.
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
        and not issubclass(osfilter, general.default.DefaultPlugin)
        and osfilter.__module__.startswith(MODULE_PATH)
    ):
        osfilter, _, _ = osfilter.__module__.replace(MODULE_PATH, "", 1).strip(".").rpartition(".")

        # Continue walking up the OS filter tree until we hit the second level
        # As an example, it walk os.unix.debian, followed by os.unix, then exit
        os_parts = osfilter.split(".")
        while len(os_parts) >= 2:
            yield from _walk(".".join(os_parts), _get_plugins())
            os_parts.pop()
    else:
        yield from _walk(None, _get_plugins())


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


def lookup(func_name: str, osfilter: Optional[type[OSPlugin]] = None) -> Iterator[PluginDescriptor]:
    """Lookup a plugin descriptor by function name.

    Args:
        func_name: Function name to lookup.
        osfilter: The ``OSPlugin`` to use as template to find os specific plugins for.
    """
    yield from get_plugins_by_func_name(func_name, osfilter=osfilter)
    yield from get_plugins_by_namespace(func_name, osfilter=osfilter)


def get_plugins_by_func_name(func_name: str, osfilter: Optional[type[OSPlugin]] = None) -> Iterator[PluginDescriptor]:
    """Get a plugin descriptor by function name.

    Args:
        func_name: Function name to lookup.
        osfilter: The ``OSPlugin`` to use as template to find os specific plugins for.
    """
    for plugin_desc in plugins(osfilter):
        if not plugin_desc["namespace"] and func_name in plugin_desc["functions"]:
            yield plugin_desc


def get_plugins_by_namespace(namespace: str, osfilter: Optional[type[OSPlugin]] = None) -> Iterator[PluginDescriptor]:
    """Get a plugin descriptor by namespace.

    Args:
        namespace: Plugin namespace to match.
        osfilter: The ``OSPlugin`` to use as template to find os specific plugins for.
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
    module = plugin_desc["fullname"].rsplit(".", 1)[0]

    try:
        module = importlib.import_module(module)
        return getattr(module, plugin_desc["class"])
    except Exception as e:
        raise PluginError(f"An exception occurred while trying to load a plugin: {module}", cause=e)


def failed() -> list[dict[str, Any]]:
    """Return all plugins that failed to load."""
    return _get_plugins().get("_failed", [])


def _get_plugins() -> dict[str, PluginDescriptor]:
    """Load the plugin registry, or generate it if it doesn't exist yet."""
    global PLUGINS, GENERATED
    if not GENERATED:
        PLUGINS = generate()
        GENERATED = True
    return PLUGINS


def save_plugin_import_failure(module: str) -> None:
    """Store errors that occurred during plugin import."""
    if "_failed" not in PLUGINS:
        PLUGINS["_failed"] = []

    stacktrace = traceback.format_exception(*sys.exc_info())
    PLUGINS["_failed"].append(
        {
            "module": module,
            "stacktrace": stacktrace,
        }
    )


def find_py_files(plugin_path: Path) -> Iterator[Path]:
    """Walk all the files and directories in ``plugin_path`` and return all files ending in ``.py``.

    Do not walk or yield paths containing the following names:

    - __pycache__
    - __init__

    Furthermore, it logs an error if ``plugin_path`` does not exist.

    Args:
        plugin_path: The path to a directory or file to walk and filter.
    """
    if not plugin_path.exists():
        log.error("Path %s does not exist.", plugin_path)
        return

    if plugin_path.is_file():
        path_iterator = [plugin_path]
    else:
        path_iterator = plugin_path.glob("**/*.py")

    for path in path_iterator:
        if not path.is_file() or str(path).endswith("__init__.py"):
            continue

        yield path


def load_module_from_name(module_path: str) -> None:
    """Load a module from ``module_path``."""
    try:
        # This will trigger the __init__subclass__() of the Plugin subclasses in the module.
        importlib.import_module(module_path)
    except Exception as e:
        log.error("Unable to import %s", module_path)
        log.debug("Error while trying to import module %s", module_path, exc_info=e)
        save_plugin_import_failure(module_path)


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

    plugins_dir = Path(__file__).parent / "plugins"
    for path in find_py_files(plugins_dir):
        relative_path = path.relative_to(plugins_dir)
        module_tuple = (MODULE_PATH, *relative_path.parent.parts, relative_path.stem)
        load_module_from_name(".".join(module_tuple))

    return PLUGINS


def load_module_from_file(path: Path, base_path: Path):
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
        log.error("Unable to import %s", path)
        log.debug("Error while trying to import module %s", path, exc_info=e)
        save_plugin_import_failure(str(path))


def load_modules_from_paths(plugin_dirs: list[Path]) -> None:
    """Iterate over the ``plugin_dirs`` and load all ``.py`` files."""
    for plugin_path in plugin_dirs:
        for path in find_py_files(plugin_path):
            base_path = plugin_path.parent if path == plugin_path else plugin_path
            load_module_from_file(path, base_path)


def get_external_module_paths(path_list: list[Path]) -> list[Path]:
    """Create a deduplicated list of paths."""
    output_list = environment_variable_paths() + path_list

    return list(set(output_list))


def environment_variable_paths() -> list[Path]:
    env_var = os.environ.get("DISSECT_PLUGINS")

    plugin_dirs = env_var.split(":") if env_var else []

    return [Path(directory) for directory in plugin_dirs]


def _traverse(key: str, obj: dict[str, Any]) -> dict[str, Any]:
    """Split a module path up in a dictionary."""
    for p in key.split("."):
        if p not in obj:
            obj[p] = {}

        obj = obj[p]

    return obj


def _modulepath(cls) -> str:
    """Returns the module path of a :class:`Plugin` relative to ``dissect.target.plugins``."""
    return cls.__module__.replace(MODULE_PATH, "").lstrip(".")


# These need to be at the bottom of the module because __init_subclass__ requires everything
# in the parent class Plugin to be defined and resolved.
class NamespacePlugin(Plugin):
    def __init__(self, target: Target):
        """A namespace plugin provides services to access functionality from a group of subplugins.

        Support is currently limited to shared exported functions that yield records.
        """
        super().__init__(target)

        # The code below only applies to the direct subclass, indirect subclasses are finished here.
        if self.__class__ != self.__nsplugin__:
            return

        self._subplugins = []
        for entry in self.SUBPLUGINS:
            try:
                subplugin = getattr(self.target, entry)
                self._subplugins.append(subplugin)
            except Exception:
                target.log.exception("Failed to load subplugin: %s", entry)

    def check_compatible(self) -> None:
        if not len(self._subplugins):
            raise UnsupportedPluginError("No compatible subplugins found")

    def __init_subclass_namespace__(cls, **kwargs):
        # If this is a direct subclass of a Namespace plugin, create a reference to the current class for indirect
        # subclasses. This is necessary to autogenerate aggregate methods there
        cls.__nsplugin__ = cls
        cls.__findable__ = False

    def __init_subclass_subplugin__(cls, **kwargs):
        cls.__findable__ = True

        if not getattr(cls.__nsplugin__, "SUBPLUGINS", None):
            cls.__nsplugin__.SUBPLUGINS = set()

        # Register the current plugin class as a subplugin with
        # the direct subclass of NamespacePlugin
        cls.__nsplugin__.SUBPLUGINS.add(cls.__namespace__)

        # Collect the public attrs of the subplugin
        for subplugin_func_name in cls.__exports__:
            subplugin_func = inspect.getattr_static(cls, subplugin_func_name)

            # The attr need to be callable and exported
            if not isinstance(subplugin_func, Callable):
                continue

            # The method needs to output records
            if getattr(subplugin_func, "__output__", None) != "record":
                continue

            # The method needs to be part of the current subclass and not a parent
            if not subplugin_func.__qualname__.startswith(cls.__name__):
                continue

            # If we already have an aggregate method, skip
            if existing_aggregator := getattr(cls.__nsplugin__, subplugin_func_name, None):
                existing_aggregator.__subplugins__.append(cls.__namespace__)
                continue

            # The generic template for the aggregator method
            def generate_aggregator(method_name: str) -> Callable:
                def aggregator(self) -> Iterator[Record]:
                    for entry in aggregator.__subplugins__:
                        try:
                            subplugin = getattr(self.target, entry)
                            for item in getattr(subplugin, method_name)():
                                yield item
                        except Exception:
                            continue

                # Holds the subplugins that share this method
                aggregator.__subplugins__ = []

                return aggregator

            # The generic template for the documentation method
            def generate_documentor(cls, method_name: str, aggregator: Callable) -> str:
                def documentor():
                    return defaultdict(
                        lambda: "???",
                        {
                            "func_name": f"{cls.__nsplugin__.__namespace__}.{method_name}",
                            "short_description": "".join(
                                [
                                    f"Return {method_name} for: ",
                                    ",".join(aggregator.__subplugins__),
                                ]
                            ),
                            "output_type": "records",
                        },
                    )

                return documentor

            # Manifacture a method for the namespaced class
            generated_aggregator = generate_aggregator(subplugin_func_name)
            generated_documentor = generate_documentor(cls, subplugin_func_name, generated_aggregator)

            # Add as an attribute to the namespace class
            setattr(cls.__nsplugin__, subplugin_func_name, generated_aggregator)

            # Copy the meta descriptors of the function attribute
            for copy_attr in ["__output__", "__record__", "__doc__", "__exported__"]:
                setattr(generated_aggregator, copy_attr, getattr(subplugin_func, copy_attr, None))

            # Add subplugin to aggregator
            generated_aggregator.__subplugins__.append(cls.__namespace__)

            # Mark the function as being autogenerated
            setattr(generated_aggregator, "__autogen__", True)

            # Add the documentor function to the aggregator
            setattr(generated_aggregator, "get_func_doc_spec", generated_documentor)

            # Register the newly auto-created method
            cls.__nsplugin__.__exports__.append(subplugin_func_name)
            cls.__nsplugin__.__functions__.append(subplugin_func_name)

    def __init_subclass__(cls, **kwargs):
        # Upon subclassing, decide whether this is a direct subclass of NamespacePlugin
        # If this is not the case, autogenerate aggregate methods for methods record output.
        super().__init_subclass__(**kwargs)
        if cls.__bases__[0] != NamespacePlugin:
            cls.__init_subclass_subplugin__(cls, **kwargs)
        else:
            cls.__init_subclass_namespace__(cls, **kwargs)


class InternalPlugin(Plugin):
    """Parent class for internal plugins.

    InternalPlugin marks all non-private methods internal by default
    (same as ``@internal`` decorator).
    """

    def __init_subclass__(cls, **kwargs):
        for method in get_nonprivate_methods(cls):
            if callable(method):
                method.__internal__ = True

        super().__init_subclass__(**kwargs)
        return cls


@dataclass(frozen=True, eq=True)
class PluginFunction:
    name: str
    path: str
    output_type: str
    class_object: type[Plugin]
    method_name: str
    plugin_desc: dict = field(hash=False)


def plugin_function_index(target: Target) -> tuple[dict[str, Any], set[str]]:
    """Returns an index-list for plugins.

    This list is used to match CLI expressions against to find the desired plugin.
    Also returns the roots to determine whether a CLI expression has to be compared
    to the plugin tree or parsed using legacy rules.
    """
    index = {}
    rootset = set()

    def all_plugins():
        # Filter out plugins based on the target os
        os_type = type(target._os) if target._os and target._os.os != "default" else None

        yield from plugins(os_type)
        yield from os_plugins()
        yield from child_plugins()  # Doesn't export anything but added for completeness.

    for available_original in all_plugins():
        # Prevent modifying the global PLUGINS dict, otherwise -f os.windows._os.users fails for instance.
        available = available_original.copy()
        if "get_all_records" in available["exports"]:
            available["exports"].remove("get_all_records")
        modulepath = available["module"]

        if modulepath.endswith("._os"):
            if not target._os:
                # if no target available add a namespaceless section
                available["module"] = ""
            elif target._os.__class__.__name__ != available["class"]:
                continue
            rootset.add(modulepath.split(".")[0])
            for exported in available["exports"]:
                index[f"{modulepath}.{exported}"] = available
                index[exported] = available
        else:
            rootset.add(modulepath.split(".")[0])
            for exported in available["exports"]:
                index[f"{modulepath}.{exported}"] = available

    return index, rootset


def find_plugin_functions(
    target: Target, patterns: str, compatibility: bool = False, **kwargs
) -> tuple[list[PluginFunction], set[str]]:
    """Finds plugins that match the target and the patterns.

    Given a target, a comma separated list of patterns and an optional compatibility flag,
    this function finds matching plugins, optionally checking compatibility and returns
    a list of plugin function descriptors (including output types).
    """
    result = []

    def add_to_result(func: PluginFunction) -> None:
        if func not in result and not func.class_object.__skip__:
            result.append(func)

    functions, rootset = plugin_function_index(target)

    invalid_funcs = set()
    show_hidden = kwargs.get("show_hidden", False)

    for pattern in patterns.split(","):
        # backward compatibility fix for namespace-level plugins (i.e. chrome)
        for index_name, func in functions.items():
            if func["namespace"] == pattern:
                pattern = func["module"] + "*"

        wildcard = any(char in pattern for char in ["*", "!", "?", "[", "]"])
        treematch = pattern.split(".")[0] in rootset and pattern != "os"
        exact_match = pattern in functions

        # Allow for exact matches, otherwise you cannot reach documented namespace plugins like
        # browsers.browser.downloads. You can *always* run these using the namespace/classic-style like:
        # browser.downloads (but -l lists them in the tree for documentation purposes so it would be misleading
        # not to allow tree access as well). Note that these tree items will never respond to wildcards though
        # (browsers.browser.* won't work) to avoid duplicate results.
        if exact_match:
            show_hidden = True

        if treematch and not wildcard and not exact_match:
            # Examples:
            #     -f browsers -> browsers* (the whole package)
            #     -f apps.webservers.iis -> apps.webservers.iis* (logs etc)
            # We do not include  a dot because that does not work if the full path is given:
            #     -f apps.webservers.iis.logs != apps.webservers.iis.logs.* (does not work)
            pattern += "*"

        if wildcard or treematch:
            matches = False
            for index_name in fnmatch.filter(functions.keys(), pattern):
                func = functions[index_name]

                method_name = index_name.split(".")[-1]
                loaded_plugin_object = load(func)

                # Skip plugins that don't want to be found by wildcards
                if not show_hidden and not loaded_plugin_object.__findable__:
                    continue

                fobject = inspect.getattr_static(loaded_plugin_object, method_name)

                if compatibility:
                    try:
                        if not loaded_plugin_object(target).is_compatible():
                            continue
                    except Exception:
                        continue

                matches = True
                add_to_result(
                    PluginFunction(
                        name=f"{func['namespace']}.{method_name}" if func["namespace"] else method_name,
                        path=index_name,
                        class_object=loaded_plugin_object,
                        method_name=method_name,
                        output_type=getattr(fobject, "__output__", "text"),
                        plugin_desc=func,
                    )
                )

            if not matches:
                invalid_funcs.add(pattern)

        else:
            # otherwise match using ~ classic style
            if pattern.find(".") > -1:
                namespace, funcname = pattern.split(".", 1)
            else:
                funcname = pattern
                namespace = None

            plugin_descriptions = []
            for _, func in functions.items():
                nsmatch = namespace and func["namespace"] == namespace and funcname in func["exports"]
                fmatch = not namespace and not func["namespace"] and funcname in func["exports"]
                if nsmatch or fmatch:
                    plugin_descriptions.append(func)

            if not plugin_descriptions:
                invalid_funcs.add(pattern)

            for description in plugin_descriptions:
                loaded_plugin_object = load(description)
                fobject = inspect.getattr_static(loaded_plugin_object, funcname)

                if compatibility and not loaded_plugin_object(target).is_compatible():
                    continue

                add_to_result(
                    PluginFunction(
                        name=f"{description['namespace']}.{funcname}" if description["namespace"] else funcname,
                        path=f"{description['module']}.{funcname}",
                        class_object=loaded_plugin_object,
                        method_name=funcname,
                        output_type=getattr(fobject, "__output__", "text"),
                        plugin_desc=description,
                    )
                )

    return result, invalid_funcs
