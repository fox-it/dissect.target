from __future__ import annotations

from enum import Enum
import itertools
from pathlib import Path
from typing import Iterable, Iterator, NamedTuple
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from flow.record.fieldtypes import windows_path

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.regutil import KeyCollection
from dissect.target.helpers.utils import to_list
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

OfficeStartupItem = TargetRecordDescriptor(
    "productivity/msoffice/startup_item",
    [("path", "path"), ("datetime", "creation_time"), ("datetime", "modification_time")],
)

# Web add-in
OfficeWebAddinRecord = TargetRecordDescriptor(
    "productivity/msoffice/web_addin",
    [
        ("string[]", "source_locations"),
        ("string", "name"),
        ("path", "manifest"),
        ("string", "version"),
        ("string", "provider_name"),
    ],
)

# COM and VSTO add-ins
OfficeNativeAddinRecord = TargetRecordDescriptor(
    "productivity/msoffice/native_addin",
    [
        ("string", "name"),
        ("string", "type"),
        ("path[]", "codebases"),
        ("boolean", "loaded"),
        ("string", "load_behavior"),
        ("path", "manifest"),
        ("datetime", "modification_time"),
    ],
)


class ClickOnceDeploymentManifestParser:
    """Parser for information about vsto plugins"""

    XML_NAMESPACE = {"": "urn:schemas-microsoft-com:asm.v2"}

    class Assembly(NamedTuple):
        installed: bool
        codebase: Path

    def __init__(self, root_manifest_path: Path, target: Target, user_sid: str) -> None:
        self.root_manifest_path = root_manifest_path
        self._target = target
        self._user_sid = user_sid
        self._visited_manifests: set[Path] = set()
        self._codebases: set[Path] = set()

    def find_codebases(self, manifest_path: str) -> set[Path]:
        """Dig for executables given a manifest"""

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

        dependent_assemblies: set[self.Assembly] = set()
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
            return set()     # Ignore files which are not actually installed, for example due to language settings

        installed = dependent_assembly.get("dependencyType") == "install"
        if codebase_path.name.endswith(".manifest") and installed:
            return self._parse_manifest(codebase_path)  # Yes, a codebase can point to another manifest

        return {self.Assembly(installed, codebase_path)}


class LoadBehavior(Enum):
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

    HIVES = ["HKLM", "HKCU"]
    OFFICE_KEY = "Software\\Microsoft\\Office"
    OFFICE_COMPONENTS = ["Access", "Excel", "Outlook", "PowerPoint", "Word", "OneNote"]
    ADD_IN_KEY = "Addins"
    WEB_ADDIN_MANIFEST_GLOB = "AppData/Local/Microsoft/Office/16.0/Wef/**/Manifests/**/*"
    OFFICE_DEFAULT_USER_STARTUP = [
        "%APPDATA%/Microsoft/Templates",
        "%APPDATA%/Microsoft/Word/Startup",
        "%APPDATA%/Microsoft/Excel/XLSTART",
    ]

    OFFICE_DEFAULT_ROOT = "C:/Program Files/Microsoft Office/root/Office16/"

    # Office is fixed at version 16.0 since Microsoft Office 2016 (released in 2015)
    OFFICE_STARTUP_OPTIONS = [
        ("Software\\Microsoft\\Office\\16.0\\Word\\Options", "STARTUP-PATH"),
        ("Software\\Microsoft\\Office\\16.0\\Word\\Options", "UserTemplates"),
        ("Software\\Microsoft\\Office\\16.0\\Excel\\Options", "AltStartup"),
    ]

    CLASSES_ROOTS = [
        "HKCR",
        # Click To Run Application Virtualization:
        "HKLM\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\REGISTRY\\MACHINE\\Software\\Classes",
        # For 32-bit software running under 64-bit Windows:
        "HKLM\\SOFTWARE\\Wow6432Node\\Classes",
    ]

    def check_compatible(self) -> None:
        if not self.target.has_function("registry") or not list(self.target.registry.keys(f"HKLM\\{self.OFFICE_KEY}")):
            raise UnsupportedPluginError("Registry key not found: %s", self.OFFICE_KEY)

    @export(record=OfficeWebAddinRecord)
    def web(self) -> Iterator[OfficeWebAddinRecord]:
        """List all web add-ins by parsing the manifests in the web extension framework cache"""

        for manifest_file in self._wef_cache_folders():
            try:
                yield self._parse_web_addin_manifest(manifest_file)
            except Exception as e:
                self.target.log.warning("Error parsing web-addin manifest %s", manifest_file)
                self.target.log.debug("", exc_info=e)

    @export(record=OfficeNativeAddinRecord)
    def native(self) -> Iterator[OfficeNativeAddinRecord]:
        """List all native (COM / vsto) add-ins by parsing the registry and manifest files."""

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

                nativePluginStatus = self._parse_plugin_status(addin)
                yield OfficeNativeAddinRecord(
                    name=addin.value("FriendlyName", None).value,
                    modification_time=addin.timestamp,
                    loaded=nativePluginStatus.loaded if nativePluginStatus else None,
                    load_behavior=nativePluginStatus.load_behavior.name if nativePluginStatus else None,
                    type=addin_type,
                    manifest=windows_path(manifest_path_str) if manifest_path_str else None,
                    codebases=executables,
                )

    @export(record=OfficeStartupItem)
    def startup(self) -> Iterable[OfficeStartupItem]:
        """List items in startup paths.

        Note that on Office 365, legacy addins such as .wll are no longer automatically loaded.
        """

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

    def _wef_cache_folders(self) -> Iterable[Path]:
        """List cache folders which contain office web-addin data."""

        for user_details in self.target.user_details.all_with_home():
            for manifest_path in user_details.home_path.glob(self.WEB_ADDIN_MANIFEST_GLOB):
                if manifest_path.is_file():
                    yield manifest_path

    def _walk_startup_folder(self, startup_folder: str, user_sid: str | None = None) -> Iterable[OfficeStartupItem]:
        """Resolve the given path and return all statup items"""

        resolved_startup_folder_str = self.target.resolve(startup_folder, user_sid)
        resolved_startup_folder: Path = self.target.fs.path(resolved_startup_folder_str)
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
            except RegistryError:
                pass

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
        display_name = display_name_element.get("DefaultValue") if display_name_element else None

        return OfficeWebAddinRecord(
            name=display_name,
            manifest=manifest_path,
            version=manifest_tree.findtext(".//Version", namespaces=ns),
            provider_name=manifest_tree.findtext(".//ProviderName", namespaces=ns),
            source_locations=filter(None, source_locations),
        )

    def _office_install_root(self, component: str) -> str:
        """Return the installation root for a office component"""

        # Typically, all components share the same root.
        # Curiously enough, the "Common" component has no InstallRoot defined.
        key = f"HKLM\\{self.OFFICE_KEY}\\16.0\\{component}\\InstallRoot"
        try:
            return self.target.registry.value(key, "Path").value
        except RegistryError:
            return self.OFFICE_DEFAULT_ROOT

    def _machine_startup_folders(self) -> Iterable[str]:
        """Return machine-scoped office startup folders"""

        yield fsutil.join(self._office_install_root("Word"), "STARTUP", alt_separator="\\")
        yield fsutil.join(self._office_install_root("Excel"), "XLSTART", alt_separator="\\")
        yield fsutil.join(self._office_install_root("Word"), "Templates", alt_separator="\\")
        yield fsutil.join(self._office_install_root("Word"), "Document Themes", alt_separator="\\")

    def _parse_plugin_status(self, addin: KeyCollection) -> NativePluginStatus | None:
        """Parse the registry value which controls if the add-in autostarts.

        See https://learn.microsoft.com/en-us/visualstudio/vsto/registry-entries-for-vsto-add-ins?view=vs-2022#LoadBehavior # noqa: E501
        """

        load_behavior = addin.value("LoadBehavior", None).value

        if load_behavior is None:
            return None
        elif load_behavior == 0:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.Manual)
        elif load_behavior == 1:
            return NativePluginStatus(loaded=True, load_behavior=LoadBehavior.Manual)
        elif load_behavior == 2:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.Autostart)
        elif load_behavior == 3:
            return NativePluginStatus(loaded=True, load_behavior=LoadBehavior.Autostart)
        elif load_behavior == 8:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.OnDemand)
        elif load_behavior == 9:
            return NativePluginStatus(loaded=True, load_behavior=LoadBehavior.OnDemand)
        elif load_behavior == 16:
            return NativePluginStatus(loaded=False, load_behavior=LoadBehavior.FistTime)

        return None
