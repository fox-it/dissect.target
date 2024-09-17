from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import configutil
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, alias, export
from dissect.target.plugins.general.users import UserDetails
from dissect.target.target import Target

TrashRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "linux/filesystem/recyclebin",
    [
        ("datetime", "ts"),
        ("path", "path"),
        ("filesize", "filesize"),
        ("path", "deleted_path"),
        ("path", "source"),
    ],
)


class GnomeTrashPlugin(Plugin):
    """Linux GNOME Trash plugin.

    Recovers deleted files and artifacts from ``$HOME/.local/share/Trash``.
    Probably also works with other desktop interfaces as long as they follow
    the Trash specification from FreeDesktop.

    Resources:
        - https://specifications.freedesktop.org/trash-spec/latest/
        - https://github.com/GNOME/glib/blob/main/gio/glocalfile.c
        - https://specifications.freedesktop.org/basedir-spec/latest/
    """

    PATHS = [
        # Default $XDG_DATA_HOME/Trash
        ".local/share/Trash",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self.trashes = list(self.garbage_collector())

    def garbage_collector(self) -> Iterator[tuple[UserDetails, TargetPath]]:
        for user_details in self.target.user_details.all_with_home():
            for trash_path in self.PATHS:
                if (path := user_details.home_path.joinpath(trash_path)).exists():
                    yield user_details, path

    def check_compatible(self) -> None:
        if not self.trashes:
            raise UnsupportedPluginError("No Trash folder(s) found")

    @export(record=TrashRecord)
    @alias(name="recyclebin")
    def trash(self) -> Iterator[TrashRecord]:
        """Yield deleted files from GNOME Trash folders."""

        for user_details, trash in self.trashes:
            for trash_info_file in trash.glob("info/*.trashinfo"):
                trash_info = configutil.parse(trash_info_file, hint="ini").get("Trash Info", {})
                original_path = self.target.fs.path(trash_info.get("Path"))

                # TODO: also iterate the expunged folder
                # https://gitlab.gnome.org/GNOME/glib/-/issues/1665
                # https://bugs.launchpad.net/ubuntu/+source/nautilus/+bug/422012

                if (deleted_path := (trash / "files" / original_path.name)).exists():
                    deleted_files = [deleted_path]

                    if deleted_path.is_dir():
                        for child in deleted_path.rglob("*"):
                            deleted_files.append(child)

                    for file in deleted_files:
                        yield TrashRecord(
                            ts=trash_info.get("DeletionDate"),
                            path=original_path,
                            filesize=file.lstat().st_size if file.is_file() else None,
                            deleted_path=file,
                            source=trash_info_file,
                            _user=user_details.user,
                            _target=self.target,
                        )
