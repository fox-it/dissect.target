from __future__ import annotations

import logging
import os
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Union

from dissect.target import filesystem, loader, plugin, volume
from dissect.target.exceptions import (
    FilesystemError,
    PluginError,
    PluginNotFoundError,
    TargetError,
    UnsupportedPluginError,
)
from dissect.target.helpers import config
from dissect.target.helpers.loaderutil import extract_path_info
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.helpers.utils import StrEnum, parse_path_uri, slugify
from dissect.target.plugins.general import default

log = logging.getLogger(__name__)

FunctionTuple = tuple[plugin.Plugin, Optional[Union[plugin.Plugin, property]]]


class Event(StrEnum):
    INCOMPATIBLE_PLUGIN = "incompatible-plugin"
    REGISTERED_PLUGIN = "registered-plugin"
    FUNC_EXEC = "function-execution"
    FUNC_EXEC_ERROR = "function-execution-error"


def getlogger(target):
    if not log.root.handlers:
        log.setLevel(os.getenv("DISSECT_LOG_TARGET", "CRITICAL"))
    return TargetLogAdapter(log, {"target": target})


class TargetLogAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f"{self.extra['target']}: {msg}", kwargs


class Target:
    """The class that represents the target that you are talking to.

    Targets are the glue that connects the different ``Containers``, ``Loaders``, ``Volumes``
    and ``Filesystems`` together.
    ``Loaders`` are used to map the ``Containers``, ``Volumes`` and ``Filesystems`` of the target
    onto the ``Target`` object.

    The plugins of dissect.target get mapped onto the ``Target`` too.
    They become available as attributes on a ``Target`` object. For example, ``t.hostname``, ``t.evtx()``.
    By executing the plugin function with a target, it will perform the function on itself.

    Args:
        path: The path of a target.
    """

    def __init__(self, path: Union[str, Path] = None):
        # WIP, part of the introduction of URI-style paths.
        # Since pathlib.Path does not support URIs, bigger refactoring
        # is needed in order to fully utilise URI's scheme / path / query
        # for Target configuration.
        self.path_scheme, self.path, self.path_query = parse_path_uri(path)
        if self.path is not None:
            self.path = Path(self.path)

        self.props: dict[Any, Any] = dict()
        self.log = getlogger(self)

        self._name = None
        self._plugins: list[plugin.Plugin] = []
        self._functions: dict[str, FunctionTuple] = {}
        self._loader = None
        self._os = None
        self._os_plugin: plugin.OSPlugin = None
        self._child_plugins: dict[str, plugin.ChildTargetPlugin] = {}
        self._cache = dict()
        self._errors = []
        self._applied = False

        try:
            self._config = config.load(self.path)
        except Exception:
            self.log.exception("Error loading config file")
            self._config = config.load(None)  # This loads an empty config.

        # Fill the disks and/or volumes and/or filesystems and apply() will
        # make sure that volumes/filesystems gets filled and the filesystems
        # get auto mounted on top of fs.
        #
        # Except when a volume's guid or volumesystem's serial is unknown (in
        # the case of windows), in which case _init_os() and
        # _os_plugin.create() won't be able to figure out where to mount the
        # filesystem. In that case they should be added and mounted explicitly
        # by the loader.
        #
        # A collection of instances of Container() subclasses
        self.disks = DiskCollection(self)
        # A collection of instances of Volume() subclasses
        self.volumes = VolumeCollection(self)
        # A collection of instances of Filesystem() subclasses
        self.filesystems = FilesystemCollection(self)

        self.fs = filesystem.RootFilesystem(self)

    @classmethod
    def set_event_callback(cls, *, event_type: Optional[Event] = None, event_callback: Callable) -> None:
        """Sets ``event_callbacks`` on a Target class.

        ``event_callbacks`` get used to handle specific events denoted by :class:`Event`.
        This records events related to the target, such as:

        - a plugin gets registered to the target
        - a plugin is incompatible with the target
        - a function succeededs in its execution
        - a function fails in execution

        """
        if not hasattr(cls, "event_callbacks"):
            cls.event_callbacks = defaultdict(set)

        # When `event_type` is not set or is None, the callback is a catch-all callback
        cls.event_callbacks[event_type].add(event_callback)

    def send_event(self, event_type: Event, **kwargs) -> None:
        """Notify event callbacks for the given ``event_type``.

        Each event can have multiple callback methods, it calls all the callbacks that fit the corresponding event type.
        ``None`` is a catch-all method for event callbacks that always get called.

        Args:
            event_type: The type of event
        """
        cls = type(self)
        if not hasattr(cls, "event_callbacks"):
            return

        specific_callbacks = cls.event_callbacks.get(event_type, set())
        catch_all_callbacks = cls.event_callbacks.get(None, set())

        for callback in set.union(specific_callbacks, catch_all_callbacks):
            try:
                callback(self, event_type, **kwargs)
            except Exception:
                self.log.warning(f"Can't send event {event_type} to {callback}", exc_info=True)

    def apply(self) -> None:
        """Resolve all disks, volumes and filesystems and load an operating system on the current ``Target``."""
        self.disks.apply()
        self.volumes.apply()
        self._init_os()
        self._applied = True

    @property
    def _generic_name(self) -> str:
        """Return a generic name for this target."""

        generic_name = (self.path and self.path.name) or None

        if not generic_name:
            # The os() plugin function is only available after a Target.apply(), as
            # only then an _os_plugin is assigned.
            try:
                generic_name = f"Unknown-{self.os}"
            except Exception:
                generic_name = "Unknown"

        return generic_name

    @property
    def name(self) -> str:
        """Return a name for this target.

        The function is guaranteed to give back some name.
        The name will be guaranteed to not have slashes, backslashes and spaces.
        The name won't be guaranteed to be unique.

        Returns:
            The name of a target.
        """
        if self._name:
            return self._name

        target_name = None
        try:
            target_name = self.hostname
        except Exception:
            pass
        finally:
            if not target_name:
                target_name = self._generic_name

        target_name = slugify(target_name)

        # As name() may be called before the Target instance is fully
        # instantiated (before apply() is called), we only save the name once
        # all parts of the Target instance are there, meaning an _os_plugin is
        # present, and the name won't change anymore.
        if self._applied:
            self._name = target_name

        return target_name

    @classmethod
    def open(cls, path: Union[str, Path]) -> Target:
        """Try to find a suitable loader for the given path and load a ``Target`` from it.

        Args:
            path: Path to load the ``Target`` from.

        Returns:
            A Target with a linked :class:`~dissect.target.loader.Loader` object.
        """

        path, parsed_path = extract_path_info(path)

        loader_cls = loader.find_loader(path, parsed_path=parsed_path)
        if loader_cls:
            loader_instance = loader_cls(path, parsed_path=parsed_path)
            return cls._load(path, loader_instance)
        return cls.open_raw(path)

    @classmethod
    def open_raw(cls, path: Union[str, Path]) -> Target:
        """Open a Target with the given path using the :class:`~dissect.target.loaders.raw.RawLoader`.

        Args:
            path: Path to load the Target from.
        """
        if not isinstance(path, Path):
            path = Path(path)

        return cls._load(path, loader.RawLoader(path))

    @classmethod
    def open_all(cls, paths: list[Union[str, Path]], include_children: bool = False) -> Iterator[Target]:
        """Yield targets from a list of paths.

        If the path is a directory, iterate files one directory deep.

        Args:
            paths: A list of paths to load ``Targets`` from.

        Raises:
            TargetError: Raised when not a single ``Target`` can be loaded.
        """

        def _find(find_path: Path):
            yield find_path
            if find_path.is_dir():
                yield from find_path.iterdir()

        at_least_one_loaded = False
        fallback_loaders = [loader.DirLoader, loader.RawLoader]

        # Treat every path as a unique target spec
        for path in paths:
            loaded = False
            path, parsed_path = extract_path_info(path)

            # Search for targets one directory deep
            for entry in _find(path):
                loader_cls = loader.find_loader(entry, parsed_path=parsed_path, fallbacks=fallback_loaders)
                if not loader_cls:
                    continue

                getlogger(entry).debug("Attempting to use loader: %s", loader_cls)
                for sub_entry in loader_cls.find_all(entry):
                    try:
                        ldr = loader_cls(sub_entry, parsed_path=parsed_path)
                    except Exception as e:
                        getlogger(sub_entry).error("Failed to initiate loader", exc_info=e)
                        continue

                    try:
                        # Attempt to load the target using this loader
                        target = cls._load(sub_entry, ldr)
                        loaded = True
                        at_least_one_loaded = True
                        yield target

                    except Exception as e:
                        getlogger(sub_entry).error("Failed to load target with loader %s", ldr, exc_info=e)

                    if include_children:
                        try:
                            yield from target.open_children()
                        except Exception as e:
                            getlogger(sub_entry).error("Failed to load child target from %s", target, exc_info=e)

                # Found a compatible loader for the top level path, no need to search a level deeper
                # Going deeper could cause unwanted behaviour
                if loaded and entry is path:
                    break

        if not at_least_one_loaded:
            raise TargetError(f"Failed to find any loader for targets: {paths}")

    def _load_child_plugins(self) -> None:
        """Load special :class:`~dissect.target.plugin.ChildTargetPlugin` plugins.

        These plugins inform the ``Target`` how to deal with child targets, such as VMs from a hypervisor.
        Examples of these plugins are:

        - :class:`~dissect.target.plugins.child.esxi.ESXiChildTargetPlugin`
        - :class:`~dissect.target.plugins.child.hyper-v.HyperVChildTargetPlugin`
        """
        if self._child_plugins:
            return

        for plugin_desc in plugin.child_plugins():
            try:
                plugin_cls = plugin.load(plugin_desc)
                child_plugin = plugin_cls(self)
            except PluginError:
                self.log.exception("Failed to load child plugin: %s", plugin_desc["class"])
                continue
            except Exception:
                self.log.exception("Broken child plugin: %s", plugin_desc["class"])
                continue

            try:
                if child_plugin.check_compatible() is False:
                    continue
                self._child_plugins[child_plugin.__type__] = child_plugin
            except PluginError as e:
                self.log.info("Child plugin reported itself as incompatible: %s (%s)", plugin_desc["class"], e)
            except Exception:
                self.log.exception(
                    "An exception occurred while checking for child plugin compatibility: %s", plugin_desc["class"]
                )

    def open_child(self, child: Union[str, Path]) -> Target:
        """Open a child target.

        Args:
            child: The location of a target within the current ``Target``.

        Returns:
            An opened ``Target`` object of the child target.
        """
        if isinstance(child, str) and child.isdecimal():
            child_num = int(child)
            for child_record in self.list_children():
                if child_num == 0:
                    return Target.open(self.fs.path(child_record.path))
                child_num -= 1
        else:
            return Target.open(self.fs.path(child))

    def open_children(self, recursive: bool = False) -> Iterator[Target]:
        """Open all the child targets on a ``Target``.

        Will open all discovered child targets if the current ``Target`` has them, such as VMs on a hypervisor.

        Args:
            recursive: Whether to check the child ``Target`` for more ``Targets``.

        Returns:
            An interator of ``Targets``.
        """
        for child in self.list_children():
            try:
                target = self.open_child(child.path)
            except TargetError as e:
                self.log.error("Failed to open child target %s", child, exc_info=e)
                continue

            yield target

            if recursive:
                yield from target.open_children(recursive=recursive)

    def list_children(self) -> Iterator[ChildTargetRecord]:
        """Lists all child targets that compatible :class:`~dissect.target.plugin.ChildTargetPlugin` classes
        can discover.
        """
        self._load_child_plugins()
        for child_plugin in self._child_plugins.values():
            yield from child_plugin.list_children()

    @classmethod
    def _load(cls, path: Union[str, Path], ldr: loader.Loader) -> Target:
        """Internal function that attemps to load a path using a given loader.

        Args:
            path: The path to the target.
            ldr: The loader to use for loading this target.

        Raises:
            TargetError: If it failed to load a target.

        Returns:
            A ``Target`` object with disks, volumes and/or filesystems mapped by the ``ldr`` from the given ``path``.
        """
        target = cls(path)

        try:
            ldr.map(target)
            target._loader = ldr
            target.apply()
            return target
        except Exception as e:
            raise TargetError(f"Failed to load target: {path}", cause=e)

    def _init_os(self) -> None:
        """Internal function that attemps to load an OSPlugin for this target."""
        if self._os_plugin:
            # If self._os_plugin is already assigned, we expect it to be fully
            # configured and possibly already instantiated (if not, it will
            # be), hence no os_plugin.create() is run and no detection is
            # attempted.
            os_plugin = self._os_plugin

            if isinstance(os_plugin, plugin.OSPlugin):
                self._os_plugin = os_plugin.__class__

            self._os = self.add_plugin(os_plugin)
            return

        if not len(self.disks) and not len(self.volumes) and not len(self.filesystems):
            raise TargetError(f"Failed to load target. No disks, volumes or filesystems: {self.path}")

        candidates = []

        for plugin_desc in plugin.os_plugins():
            # Subclassed OS Plugins used to also subclass the detection of the
            # parent. This meant that in order for a subclassed OS Plugin to be a
            # candidate for the final OS Plugin, the parent OS Plugin's detection
            # had to succeed. This caused some complications in cases where the
            # filesystem layout needed some tweaks by a subclassed OS Plugin before
            # parent OS Plugin paths made sense.
            #
            # E.g. VyOS /boot/<version>/live-rw -> map to /
            #
            # Now subclassed OS Plugins are on the same detection "layer" as
            # regular OS Plugins, but can still inherit functions.
            self.log.debug("Loading OS plugin: %s", plugin_desc["class"])
            try:
                os_plugin = plugin.load(plugin_desc)
                fs = os_plugin.detect(self)
            except PluginError:
                self.log.exception("Failed to load OS plugin: %s", plugin_desc["class"])
                continue
            except Exception:
                self.log.exception("Broken OS plugin: %s", plugin_desc["class"])
                continue

            if not fs:
                continue

            self.log.info("Found compatible OS plugin: %s", plugin_desc["class"])
            candidates.append((plugin_desc, os_plugin, fs))

        fs = None
        os_plugin = default.DefaultPlugin

        if candidates:
            plugin_desc, os_plugin, fs = candidates[0]
            for candidate_plugin_desc, candidate_plugin, candidate_fs in candidates[1:]:
                # More specific OS plugins are considered better candidates
                if len(candidate_plugin.mro()) > len(os_plugin.mro()):
                    plugin_desc, os_plugin, fs = candidate_plugin_desc, candidate_plugin, candidate_fs

            self.log.debug("Selected OS plugin: %s", plugin_desc["class"])
        else:
            # No OS detected
            self.log.warning("Failed to find OS plugin, falling back to default")

        self._os_plugin = os_plugin
        self._os = self.add_plugin(os_plugin.create(self, fs))

    def add_plugin(
        self,
        plugin_cls: Union[plugin.Plugin, type[plugin.Plugin]],
        check_compatible: bool = True,
    ) -> plugin.Plugin:
        """Add and register a plugin by class.

        Args:
            plugin_cls: The plugin to add and register, this can either be a class or instance. When this is a class,
                        it will be instantiated.
            check_compatible: A flag that determines if we check whether the plugin is compatible with the ``Target``.

        Returns:
            The ``plugin_cls`` instance.

        Raises:
            UnsupportedPluginError: Raised when plugins were found, but they were incompatible
            PluginError: Raised when any other exception occurs while trying to load the plugin.
        """
        self.log.debug("Adding plugin: %s", plugin_cls)

        if not isinstance(plugin_cls, plugin.Plugin):
            try:
                p = plugin_cls(self)
            except PluginError:
                raise
            except Exception as e:
                raise PluginError(f"An exception occurred while trying to initialize a plugin: {plugin_cls}", cause=e)
        else:
            p = plugin_cls

        if not isinstance(p, plugin.Plugin):
            raise PluginError(f"Not a subclass of Plugin: {p}")

        if check_compatible:
            try:
                if p.check_compatible() is False:
                    self.send_event(Event.INCOMPATIBLE_PLUGIN, plugin_cls=plugin_cls)
                    raise UnsupportedPluginError(f"Plugin reported itself as incompatible: {plugin_cls}")
            except PluginError:
                raise
            except Exception as e:
                raise UnsupportedPluginError(
                    f"An exception occurred while checking for plugin compatibility: {plugin_cls}", cause=e
                )

        self._register_plugin_functions(p)

        return p

    def _register_plugin_functions(self, plugin_inst: plugin.Plugin) -> None:
        """Internal function that registers all the exported functions from a given plugin.

        Args:
            plugin_inst: Instance of a plugin.
        """
        self.send_event(Event.REGISTERED_PLUGIN, plugin_inst=plugin_inst)

        self._plugins.append(plugin_inst)

        if plugin_inst.__namespace__:
            self._functions[plugin_inst.__namespace__] = (plugin_inst, plugin_inst)
        else:
            for func in plugin_inst.__functions__:
                # If we getattr here, property members will be executed, so we do that in __getattr__
                self._functions[func] = (plugin_inst, None)

    def get_function(self, function: str) -> FunctionTuple:
        """Attempt to get a given function.

        If the function is not already registered, look for plugins that export the function and register them.

        Args:
            function: Function name to look for.

        Returns:
            A tuple of the plugin and the corresponding function.

        Raises:
            UnsupportedPluginError: Raised when plugins were found, but they were incompatible
            PluginError: Raised when any other exception occurs while trying to load the plugin.
        """
        if function not in self._functions:
            causes = []

            plugin_desc = None
            for plugin_desc in plugin.lookup(function, self._os_plugin):
                try:
                    plugin_cls = plugin.load(plugin_desc)
                    self.add_plugin(plugin_cls)
                    self.log.debug("Found compatible plugin '%s' for function '%s'", plugin_desc["class"], function)
                    break
                except UnsupportedPluginError as e:
                    self.send_event(Event.INCOMPATIBLE_PLUGIN, plugin_desc=plugin_desc)
                    causes.append(e)
            else:
                if plugin_desc:
                    # In this case we made at least one iteration but it was skipped due incompatibility.
                    # Just take the last known cause for now
                    raise UnsupportedPluginError(
                        f"Unsupported function `{function}` for target with OS plugin {self._os_plugin}",
                        cause=causes[0] if causes else None,
                        extra=causes[1:] if len(causes) > 1 else None,
                    )

        # We still ended up with no compatible plugins
        if function not in self._functions:
            raise PluginNotFoundError(f"Can't find plugin with function `{function}`")

        p, func = self._functions[function]
        if func is None:
            func = getattr(p.__class__, function)
            if not isinstance(func, property) or (
                isinstance(func, property) and getattr(func.fget, "__persist__", False)
            ):
                # If the persist flag is set on a property, store the property result in the function cache
                # This is so we don't have to evaluate the property again
                func = getattr(p, function)
            self._functions[function] = (p, func)

        return p, func

    def has_function(self, function: str) -> bool:
        """Return whether this Target supports a given function.

        Args:
            function: The function name to look for.

        Returns:
            ``True`` if the function can be found, ``False`` otherwise.
        """
        try:
            self.get_function(function)
            return True
        except PluginError:
            return False

    def __getattr__(self, attr: str) -> Union[plugin.Plugin, Any]:
        """Override of the default __getattr__ so plugins and functions can be called from a ``Target`` object."""
        p, func = self.get_function(attr)

        if isinstance(func, property):
            # If it's a property, execute it and return the result
            try:
                result = func.__get__(p)
                self.send_event(Event.FUNC_EXEC, func=attr)
                return result
            except Exception:
                if not attr.startswith("__"):
                    self.send_event(
                        Event.FUNC_EXEC_ERROR,
                        func=attr,
                        stacktrace=traceback.format_exc(),
                    )
                raise

        return func

    def __dir__(self):
        """Override the default __dir__ to provide autocomplete for things like IPython."""
        funcs = []
        if self._os_plugin:
            funcs = list(self._os_plugin.__functions__)

        for plugin_desc in plugin.plugins(self._os_plugin):
            funcs.extend(plugin_desc["functions"])

        result = set(self.__dict__.keys())
        result.update(self.__class__.__dict__.keys())
        result.update(object.__dict__.keys())
        result.update(funcs)

        return list(result)

    def __repr__(self):
        return f"<Target {self.path}>"


class Collection:
    def __init__(self, target):
        self.target = target
        self.entries = []

    def add(self, entry):
        self.entries.append(entry)

    def __getitem__(self, k):
        return self.entries[k]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.entries!r}>"


class DiskCollection(Collection):
    def apply(self):
        for disk in self.entries:
            try:
                if not hasattr(disk, "vs") or disk.vs is None:
                    disk.vs = volume.open(disk)
                    self.target.log.debug("Opened volume system: %s on %s", disk.vs, disk)

                for vol in disk.vs.volumes:
                    self.target.volumes.add(vol)
            except Exception as e:
                self.target.log.warning("Can't identify volume system, adding as raw volume instead: %s", disk)
                self.target.log.debug("", exc_info=e)
                vol = volume.Volume(disk, 1, 0, disk.size, None, None, disk=disk)
                self.target.volumes.add(vol)


class VolumeCollection(Collection):
    def open(self, vol):
        try:
            if not hasattr(vol, "fs") or vol.fs is None:
                vol.fs = filesystem.open(vol)
                self.target.log.debug("Opened filesystem: %s on %s", vol.fs, vol)
            self.target.filesystems.add(vol.fs)
        except FilesystemError as e:
            self.target.log.warning("Can't identify filesystem: %s", vol)
            self.target.log.debug("", exc_info=e)

    def apply(self):
        lvm_volumes = []
        encrypted_volumes = []
        for vol in self.entries:
            if volume.is_lvm_volume(vol):
                lvm_volumes.append(vol)

            if volume.is_encrypted(vol):
                encrypted_volumes.append(vol)

            self.open(vol)

        self.target.log.debug("LVM volumes found: %s", lvm_volumes)
        self.target.log.debug("Encrypted volumes found: %s", encrypted_volumes)

        for lvm in volume.open_lvm(lvm_volumes):
            self.target.log.debug("Opened LVM: %s", lvm)
            for lv in lvm.volumes:
                self.add(lv)
                self.open(lv)

        for enc_volume in encrypted_volumes:
            for dec_volume in volume.open_encrypted(enc_volume):
                self.add(dec_volume)
                self.open(dec_volume)
                self.target.log.debug("Encrypted volume opened: %s", enc_volume)

        # ASDF - getting the correct starting system volume
        start_fs = None
        start_vol = None
        for idx, vol in enumerate(self.entries):
            if start_fs is None and (vol.name is None):
                start_fs = idx

            if start_vol is None and start_fs is not None and (vol.name is not None and vol.fs is None):
                start_vol = idx

            if start_fs is not None and start_vol is not None and (vol.name is not None and vol.fs is None):
                rel_vol = idx - start_vol
                vol.fs = self.entries[start_fs + rel_vol].fs


class FilesystemCollection(Collection):
    pass
