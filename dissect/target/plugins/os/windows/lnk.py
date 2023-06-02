from typing import Iterator, Optional

from dissect.shellitem.lnk import Lnk
from dissect.util import ts
from flow.record.fieldtypes import path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.target import Target

LnkRecord = TargetRecordDescriptor(
    "windows/filesystem/lnk",
    [
        ("path", "lnk_path"),
        ("string", "lnk_name"),
        ("datetime", "lnk_mtime"),
        ("datetime", "lnk_atime"),
        ("datetime", "lnk_ctime"),
        ("path", "lnk_relativepath"),
        ("path", "lnk_workdir"),
        ("string", "lnk_arguments"),
        ("path", "lnk_iconlocation"),
        ("string", "local_base_path"),
        ("string", "common_path_suffix"),
        ("string", "lnk_net_name"),
        ("string", "lnk_device_name"),
        ("path", "lnk_full_path"),
        ("string", "machine_id"),
        ("datetime", "target_mtime"),
        ("datetime", "target_atime"),
        ("datetime", "target_ctime"),
    ],
)


class LnkPlugin(Plugin):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.folders = ["programdata", "users", "windows"]

    def check_compatible(self) -> None:
        for folder in self.folders:
            if self.target.fs.path(f"sysvol/{folder}").exists():
                return None
        raise UnsupportedPluginError("No folders containing link files found")

    @arg("--directory", "-d", dest="directory", default=None, help="Path to .lnk file in target")
    @export(record=LnkRecord)
    def lnk(self, directory: Optional[str] = None) -> Iterator[LnkRecord]:
        """Parse all .lnk files in /ProgramData, /Users, and /Windows or from a specified path in record format.

        Yields a LnkRecord record with the following fields:
            lnk_path (path): Path of the link (.lnk) file.
            lnk_name (string): Name of the link (.lnk) file.
            lnk_mtime (datetime): Modification time of the link (.lnk) file.
            lnk_atime (datetime): Access time of the link (.lnk) file.
            lnk_ctime (datetime): Creation time of the link (.lnk) file.
            lnk_relativepath (path): Relative path of target file to the link (.lnk) file.
            lnk_workdir (path): Path of the working directory the link (.lnk) file will execute from.
            lnk_iconlocation (path): Path of the display icon used for the link (.lnk) file.
            lnk_arguments (string): Command-line arguments passed to the target (linked) file.
            local_base_path (string): Absolute path of the target (linked) file.
            common_path_suffix (string): Suffix of the local_base_path.
            lnk_full_path (string): Full path of the linked file. Made from local_base_path and common_path_suffix.
            lnk_net_name (string): Specifies a server share path; for example, "\\\\server\\share".
            lnk_device_name (string): Specifies a device; for example, the drive letter "D:"
            machine_id (string): The NetBIOS name of the machine where the linked file was last known to reside.
            target_mtime (datetime): Modification time of the target (linked) file.
            target_atime (datetime): Access time of the target (linked) file.
            target_ctime (datetime): Creation time of the target (linked) file.
        """

        # we need to get the active codepage from the system to properly decode some values
        codepage = self.target.codepage or "ascii"

        for entry in self.lnk_entries(directory):
            lnk_file = Lnk(entry.open())
            lnk_net_name = lnk_device_name = None

            if lnk_file.link_header:
                lnk_path = entry
                lnk_name = lnk_file.stringdata.name_string.string if lnk_file.flag("has_name") else None

                lnk_mtime = ts.from_unix(entry.stat().st_mtime)
                lnk_atime = ts.from_unix(entry.stat().st_atime)
                lnk_ctime = ts.from_unix(entry.stat().st_ctime)

                lnk_relativepath = (
                    path.from_windows(lnk_file.stringdata.relative_path.string)
                    if lnk_file.flag("has_relative_path")
                    else None
                )
                lnk_workdir = (
                    path.from_windows(lnk_file.stringdata.working_dir.string)
                    if lnk_file.flag("has_working_dir")
                    else None
                )
                lnk_iconlocation = (
                    path.from_windows(lnk_file.stringdata.icon_location.string)
                    if lnk_file.flag("has_icon_location")
                    else None
                )
                lnk_arguments = (
                    lnk_file.stringdata.command_line_arguments.string if lnk_file.flag("has_arguments") else None
                )
                local_base_path = (
                    lnk_file.linkinfo.local_base_path.decode(codepage)
                    if lnk_file.flag("has_link_info") and lnk_file.linkinfo.flag("volumeid_and_local_basepath")
                    else None
                )
                common_path_suffix = (
                    lnk_file.linkinfo.common_path_suffix.decode(codepage) if lnk_file.flag("has_link_info") else None
                )

                if local_base_path and common_path_suffix:
                    lnk_full_path = path.from_windows(local_base_path + common_path_suffix)
                elif local_base_path and not common_path_suffix:
                    lnk_full_path = path.from_windows(local_base_path)
                else:
                    lnk_full_path = None

                if lnk_file.flag("has_link_info"):
                    if lnk_file.linkinfo.flag("common_network_relative_link_and_pathsuffix"):
                        lnk_net_name = (
                            lnk_file.linkinfo.common_network_relative_link.net_name.decode()
                            if lnk_file.linkinfo.common_network_relative_link.net_name
                            else None
                        )
                        lnk_device_name = (
                            lnk_file.linkinfo.common_network_relative_link.device_name.decode()
                            if lnk_file.linkinfo.common_network_relative_link.device_name
                            else None
                        )
                try:
                    machine_id = lnk_file.extradata.TRACKER_PROPS.machine_id.decode(codepage).strip("\x00")
                except AttributeError:
                    machine_id = None

                target_mtime = ts.wintimestamp(lnk_file.link_header.write_time)
                target_atime = ts.wintimestamp(lnk_file.link_header.access_time)
                target_ctime = ts.wintimestamp(lnk_file.link_header.creation_time)

                yield LnkRecord(
                    lnk_path=lnk_path,
                    lnk_name=lnk_name,
                    lnk_mtime=lnk_mtime,
                    lnk_atime=lnk_atime,
                    lnk_ctime=lnk_ctime,
                    lnk_relativepath=lnk_relativepath,
                    lnk_workdir=lnk_workdir,
                    lnk_iconlocation=lnk_iconlocation,
                    lnk_arguments=lnk_arguments,
                    local_base_path=local_base_path,
                    common_path_suffix=common_path_suffix,
                    lnk_full_path=lnk_full_path,
                    lnk_net_name=lnk_net_name,
                    lnk_device_name=lnk_device_name,
                    machine_id=machine_id,
                    target_mtime=target_mtime,
                    target_atime=target_atime,
                    target_ctime=target_ctime,
                )

    def lnk_entries(self, path: Optional[str] = None) -> Iterator[TargetPath]:
        if path:
            yield self.target.fs.path(path)
        else:
            for folder in self.folders:
                yield from self.target.fs.path("sysvol").joinpath(folder).rglob("*.lnk")
