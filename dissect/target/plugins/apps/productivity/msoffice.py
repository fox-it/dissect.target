from __future__ import annotations

import itertools
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Final, Literal, NamedTuple

from defusedxml import ElementTree
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import to_list
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from xml.etree.ElementTree import Element

    from dissect.target.helpers.regutil import KeyCollection
    from dissect.target.target import Target

OfficeStartupItem = TargetRecordDescriptor(
    "application/productivity/msoffice/startup_item",
    [("path", "path"), ("datetime", "creation_time"), ("datetime", "modification_time")],
)

# Web add-in
OfficeWebAddinRecord = TargetRecordDescriptor(
    "application/productivity/msoffice/web_addin",
    [
        ("path", "manifest"),
        ("datetime", "modification_time"),
        ("string", "name"),
        ("string", "version"),
        ("string", "provider_name"),
        ("string[]", "source_locations"),
    ],
)

# COM and VSTO add-ins
OfficeNativeAddinRecord = TargetRecordDescriptor(
    "application/productivity/msoffice/native_addin",
    [
        ("path", "manifest"),
        ("datetime", "modification_time"),
        ("string", "name"),
        ("string", "type"),
        ("path[]", "codebases"),
        ("boolean", "loaded"),
        ("string", "load_behavior"),
    ],
)


class ClickOnceDeploymentManifestParser:
    """Parser to extact information out ClickOnce deployment manifest files.

    Currently only extracts codebase information. Also handles nested manifests.
    Can be extended to a .NET assembly parser in the future.
    """

    XML_NAMESPACE: Final[dict[str, str]] = {"": "urn:schemas-microsoft-com:asm.v2"}

    class Assembly(NamedTuple):
        installed: bool
        codebase: Path

    def __init__(self, root_manifest_path: Path, target: Target, user_sid: str):
        self.root_manifest_path = root_manifest_path
        self._target = target
        self._user_sid = user_sid
        self._visited_manifests: set[Path] = set()
        self._codebases: set[Path] = set()

    def find_codebases(self, manifest_path: str) -> set[Path]:
        """Dig for executables given a manifest."""

        assemblies = self._parse_manifest(manifest_path)
        # Ignore pre-installed assemblies
        return {assembly.codebase for assembly in assemblies if assembly.installed}

    def _parse_manifest(self, manifest_path: Path) -> set[Assembly]:
        # See https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-deployment-manifest?view=vs-2022

        if manifest_path in self._visited_manifests:
            return self._codebases  # Prevent cycles

        self._visited_manifests.add(manifest_path)
        try:
            manifest_tree: Element = ElementTree.fromstring(manifest_path.read_text("utf-8-sig"))
        except Exception as e:
            self._target.log.warning("Error parsing manifest %s", manifest_path)
            self._target.log.debug("", exc_info=e)
            return set()

        dependent_assemblies: set[ClickOnceDeploymentManifestParser.Assembly] = set()
        dependent_assembly_elements = manifest_tree.findall(".//dependentAssembly", self.XML_NAMESPACE)
        for dependent_assembly_element in dependent_assembly_elements:
            dependent_assemblies |= self._parse_dependent_assembly(dependent_assembly_element, manifest_path.parent)

        return dependent_assemblies

    def _parse_dependent_assembly(self, dependent_assembly: Element, cwd: Path) -> set[Assembly]:
        # See https://learn.microsoft.com/en-us/visualstudio/deployment/dependency-element-clickonce-deployment?view=vs-2022#dependentassembly # noqa: E501

        if not (codebase_str_path := dependent_assembly.get("codebase")):
            return set()

        codebase_str_path = fsutil.abspath(codebase_str_path, str(cwd), alt_separator=self._target.fs.alt_separator)
        codebase_path: Path = self._target.fs.path(codebase_str_path)
        if not codebase_path.exists():
            return set()  # Ignore files which are not actually installed, for example due to language settings

        installed = dependent_assembly.get("dependencyType") == "install"
        if codebase_path.name.endswith(".manifest") and installed:
            return self._parse_manifest(codebase_path)  # Yes, a codebase can point to another manifest

        return {self.Assembly(installed, codebase_path)}


class LoadBehavior(Enum):
    """Values that specify the run time behavior of the VSTO add-in."""

    Manual = 1
    Autostart = 2
    OnDemand = 3
    FistTime = 4


class NativePluginStatus(NamedTuple):
    loaded: bool
    load_behavior: LoadBehavior


class MSOffice(Plugin):
    """Microsoft Office productivity suite plugin."""

    __namespace__ = "msoffice"

    HIVES = ("HKLM", "HKCU")
    OFFICE_KEY = "Software\\Microsoft\\Office"
    OFFICE_COMPONENTS = ("Access", "Excel", "Outlook", "PowerPoint", "Word", "OneNote")
    ADD_IN_KEY = "Addins"
    OFFICE_DEFAULT_USER_STARTUP = (
        "%APPDATA%/Microsoft/Templates",
        "%APPDATA%/Microsoft/Word/Startup",
        "%APPDATA%/Microsoft/Excel/XLSTART",
        "%APPDATA%/Microsoft/Outlook/Startup",
        "%APPDATA%/Microsoft/PowerPoint/Startup",
    )

    OFFICE_DEFAULT_ROOT = "C:/Program Files/Microsoft Office/root/Office16/"

    # Office is fixed at version 16.0 since Microsoft Office 2016 (released in 2015)
    # Powerpoint and Outlook do not have a alternate startup folder
    OFFICE_STARTUP_OPTIONS = (
        ("Software\\Microsoft\\Office\\16.0\\Word\\Options", "STARTUP-PATH"),
        ("Software\\Microsoft\\Office\\16.0\\Word\\Options", "UserTemplates"),
        ("Software\\Microsoft\\Office\\16.0\\Excel\\Options", "AltStartup"),
    )

    CLASSES_ROOTS = (
        "HKCR",
        # Click To Run Application Virtualization:
        "HKLM\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\REGISTRY\\MACHINE\\Software\\Classes",
        # For 32-bit software running under 64-bit Windows:
        "HKLM\\SOFTWARE\\Wow6432Node\\Classes",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self._office_install_root = lru_cache(32)(self._office_install_root)

    def check_compatible(self) -> None:
        if not self.target.has_function("registry") or not list(self.target.registry.keys(f"HKLM\\{self.OFFICE_KEY}")):
            raise UnsupportedPluginError("Registry key not found: %s", self.OFFICE_KEY)

    @export(record=OfficeWebAddinRecord)
    def web(self) -> Iterator[OfficeWebAddinRecord]:
        """Returns all available Web add-ins cached in the WEF (Web Extension Framework) folder.

        Office Web Add-ins are web-based applications that extend the functionality of Office applications like Word, Excel, and Outlook.
        These add-ins can interact with the content in Office documents and provide additional features and capabilities.
        The WEF folder contains cached data and manifests for Office Web Add-ins.
        The manifest includes information about the add-ins, such as their source locations, display names, and other metadata.

        References:
            - https://learn.microsoft.com/en-us/office/dev/add-ins/overview/office-add-ins

        Yields a ``OfficeWebAddinRecord`` with fields:

        .. code-block:: text

            manifest (path): The full path to the manifest in the WEF folder.
            modification_time (datetime): The modification time of the manifest.
            name (string): The display name of the add-in.
            version (string): The version of the add-in.
            provider_name (string): The provider name of the add-in.
            source_locations (string[]): URLs referencing the web assets of the add-in (such as javascript and html files).
        """  # noqa: E501

        for manifest_file in self._wef_cache_folders():
            try:
                yield self._parse_web_addin_manifest(manifest_file)
            except Exception as e:  # noqa: PERF203
                self.target.log.warning("Error parsing web-addin manifest %s", manifest_file)
                self.target.log.debug("", exc_info=e)

    @export(record=OfficeNativeAddinRecord)
    def native(self) -> Iterator[OfficeNativeAddinRecord]:
        """Returns all native (COM / VSTO) add-ins by parsing the registry and manifest files.

        COM (Component Object Model) is a binary-interface standard developed by Microsoft that enables software components to communicate with each other.
        COM plugins for Microsoft Office applications, such as Word, Excel, and Outlook, are typically used to extend the functionality of these programs by integrating custom features.
        COM plugins interact directly with Office applications through COM interfaces, offering a low-level approach to automation.

        VSTO is a set of tools provided by Microsoft to create Office add-ins using the .NET Framework.
        VSTO plugins are more modern than COM plugins and leverage managed code. They are typically developed in C# or VB.NET using Visual Studio.

        Both COM and VSTO add-ins are registered in the Windows registry, where they are associated with specific Office applications and configured to load automatically or on demand.

        References:
            - https://learn.microsoft.com/en-us/office/dev/add-ins/overview/office-add-ins
            - https://learn.microsoft.com/en-us/visualstudio/vsto/registry-entries-for-vsto-add-ins

        Yields a ``OfficeNativeAddinRecord`` with fields:

        .. code-block:: text

            manifest (path): The full path to the manifest of a VSTO plugin. ``None`` for COM plugins.
            modification_time (datetime): The modification time of the registry key of the plugin.
            name (string): The name of the add-in.
            type (string): The type of the add-in, either "com" or "vsto".
            codebases (path[]): The full paths to the executables associated with the add-in.
            loaded (boolean): Whether the add-in is currently loaded.
            load_behavior (string): The load behavior of the add-in, e.g., "Autostart", "Manual", "OnDemand", "FirstTime".
        """  # noqa: E501

        addin_path_tuples = itertools.product(self.HIVES, [self.OFFICE_KEY], self.OFFICE_COMPONENTS, [self.ADD_IN_KEY])
        addin_paths = ["\\".join(addin_path_tuple) for addin_path_tuple in addin_path_tuples]
        for addin_key in self.target.registry.keys(addin_paths):
            for addin in addin_key.subkeys():
                key_owner = self.target.registry.get_user(addin)
                sid = key_owner.sid if key_owner else None

                if manifest_path_str := addin.value("Manifest", None).value:
                    addin_type = "vsto"
                    executables = self._parse_vsto_manifest(manifest_path_str, sid)
                else:
                    addin_type = "com"
                    dll_str = self._lookup_com_executable(addin.name)
                    executables = to_list(self.target.resolve(dll_str, sid))

                native_plugin_status = self._parse_plugin_status(addin)
                yield OfficeNativeAddinRecord(
                    name=addin.value("FriendlyName", None).value,
                    modification_time=addin.timestamp,
                    loaded=native_plugin_status.loaded if native_plugin_status else None,
                    load_behavior=native_plugin_status.load_behavior.name if native_plugin_status else None,
                    type=addin_type,
                    manifest=windows_path(manifest_path_str) if manifest_path_str else None,
                    codebases=executables,
                )

    @export(record=OfficeStartupItem)
    def startup(self) -> Iterator[OfficeStartupItem]:
        """Returns all startup items found in Microsoft Office startup folders.

        Office startup folders are specific directories where Microsoft Office looks add-ins, macros, templates, or custom scripts.
        These are used to automatically load when the corresponding Office application starts up.
        These folders allow users and administrators to automate launching add-ins, executing scripts, or applying custom settings.

        References:
            - https://pentestlab.blog/2019/12/11/persistence-office-application-startup/

        Yields a ``OfficeStartupItem`` with fields:

        .. code-block:: text

            path (path): The full path to the startup item.
            creation_time (datetime): The creation time of the startup item.
            modification_time (datetime): The modification time of the startup item.
        """  # noqa: E501

        # Get items from default machine-scoped startup folder
        for machine_startup_folder in self._machine_startup_folders():
            yield from self._walk_startup_folder(machine_startup_folder)

        # Get items from default user-scoped startup folder
        for user in self.target.user_details.all_with_home():
            for user_startup_folder in self.OFFICE_DEFAULT_USER_STARTUP:
                yield from self._walk_startup_folder(user_startup_folder, user.user.sid)

        # Get items from alternate machine or user scoped startup folder
        for hive in self.HIVES:
            for options_key, startup_value in self.OFFICE_STARTUP_OPTIONS:
                alt_startup_folders = self.target.registry.values(f"{hive}\\{options_key}", startup_value)
                for alt_startup_folder in alt_startup_folders:
                    user = self.target.registry.get_user(alt_startup_folder)
                    user_sid = user.sid if user else None
                    yield from self._walk_startup_folder(alt_startup_folder.value, user_sid)

    def _wef_cache_folders(self) -> Iterator[Path]:
        """List cache folders which contain office web-addin data."""

        WEB_ADDIN_MANIFEST_GLOB = "AppData/Local/Microsoft/Office/16.0/Wef/**/Manifests/**/*"
        for user_details in self.target.user_details.all_with_home():
            for manifest_path in user_details.home_path.glob(WEB_ADDIN_MANIFEST_GLOB):
                if manifest_path.is_file() and manifest_path.suffix != ".metadata":
                    yield manifest_path

    def _walk_startup_folder(self, startup_folder: str, user_sid: str | None = None) -> Iterator[OfficeStartupItem]:
        """Resolve the given path and return all statup items."""

        resolved_startup_folder: Path = self.target.resolve(startup_folder, user_sid)
        if not resolved_startup_folder.is_dir():
            return

        for current_path, _, plugin_files in resolved_startup_folder.walk():
            for plugin_file in plugin_files:
                item_startup = current_path / plugin_file
                stats = item_startup.stat()
                yield OfficeStartupItem(
                    path=item_startup, creation_time=stats.st_birthtime, modification_time=stats.st_mtime
                )

    def _lookup_com_executable(self, prog_id: str) -> str | None:
        """Lookup the com executable given a prog id using the registry."""

        for classes_root in self.CLASSES_ROOTS:
            try:
                cls_id = self.target.registry.value(f"{classes_root}\\{prog_id}\\CLSID", "(Default)").value
                inproc_key = f"{classes_root}\\CLSID\\{cls_id}\\InprocServer32"
                return self.target.registry.value(inproc_key, "(Default)").value
            except RegistryError:  # noqa: PERF203
                pass

        return None

    def _parse_vsto_manifest(self, manifest_path_str: str, user_sid: str) -> set[str]:
        """Parse a vsto manifest.

        Non-local manifests, i.e. not ending with suffix "vstolocal" are listed but skipped.
        """

        if not manifest_path_str.endswith("vstolocal"):
            self.target.log.warning("Parsing of remote vsto manifest %s is not supported")
            return set(manifest_path_str)

        manifest_path: Path = self.target.resolve(manifest_path_str.removesuffix("|vstolocal"), user_sid)
        manifest_parser = ClickOnceDeploymentManifestParser(manifest_path, self.target, user_sid)
        return manifest_parser.find_codebases(manifest_path)

    def _parse_web_addin_manifest(self, manifest_path: Path) -> OfficeWebAddinRecord:
        """Parses a web addin manifest."""

        ns = {"": "http://schemas.microsoft.com/office/appforoffice/1.1"}

        manifest_tree: Element = ElementTree.fromstring(manifest_path.read_text("utf-8-sig"))

        source_location_elements = manifest_tree.findall(".//SourceLocation", ns)
        source_locations = [source_location.get("DefaultValue") for source_location in source_location_elements]

        display_name_element = manifest_tree.find(".//DisplayName", ns)
        display_name = display_name_element.get("DefaultValue") if display_name_element is not None else None

        return OfficeWebAddinRecord(
            name=display_name,
            manifest=manifest_path,
            version=manifest_tree.findtext(".//Version", namespaces=ns),
            provider_name=manifest_tree.findtext(".//ProviderName", namespaces=ns),
            source_locations=filter(None, source_locations),
            modification_time=manifest_path.stat().st_mtime,
        )

    def _office_install_root(self, component: Literal["Word", "Excel"]) -> str:
        """Return the installation root for a office component."""

        # Typically, all components share the same root.
        # Curiously enough, the "Common" component has no InstallRoot defined.
        key = f"HKLM\\{self.OFFICE_KEY}\\16.0\\{component}\\InstallRoot"
        try:
            return self.target.registry.value(key, "Path").value
        except RegistryError:
            return self.OFFICE_DEFAULT_ROOT

    def _machine_startup_folders(self) -> Iterator[str]:
        """Return machine-scoped office startup folders."""

        yield fsutil.join(self._office_install_root("Word"), "STARTUP", alt_separator="\\")
        yield fsutil.join(self._office_install_root("Excel"), "XLSTART", alt_separator="\\")
        yield fsutil.join(self._office_install_root("Word"), "Templates", alt_separator="\\")
        yield fsutil.join(self._office_install_root("Word"), "Document Themes", alt_separator="\\")

    def _parse_plugin_status(self, addin: KeyCollection) -> NativePluginStatus | None:
        """Parse the registry value which controls if the add-in autostarts.

        See https://learn.microsoft.com/en-us/visualstudio/vsto/registry-entries-for-vsto-add-ins?view=vs-2022#LoadBehavior
        """

        load_behavior = addin.value("LoadBehavior", None).value

        if load_behavior is None:
            return None
        if load_behavior == 0:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.Manual)
        if load_behavior == 1:
            return NativePluginStatus(loaded=True, load_behavior=LoadBehavior.Manual)
        if load_behavior == 2:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.Autostart)
        if load_behavior == 3:
            return NativePluginStatus(loaded=True, load_behavior=LoadBehavior.Autostart)
        if load_behavior == 8:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.OnDemand)
        if load_behavior == 9:
            return NativePluginStatus(loaded=True, load_behavior=LoadBehavior.OnDemand)
        if load_behavior == 16:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.FistTime)

        return None
