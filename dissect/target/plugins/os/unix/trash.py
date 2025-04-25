from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import configutil
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, alias, export
from dissect.target.plugins.general.users import UserDetails

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
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
    """Linux GNOME Trash plugin."""

    PATHS = (
        # Default $XDG_DATA_HOME/Trash
        ".local/share/Trash",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.trashes = set(self._garbage_collector())

    def _garbage_collector(self) -> Iterator[tuple[UserDetails, TargetPath]]:
        """it aint much, but its honest work"""

        # home trash folders
        for user_details in self.target.user_details.all_with_home():
            for trash_path in self.PATHS:
                if (path := user_details.home_path.joinpath(trash_path)).exists():
                    yield user_details, path

        # mounted devices trash folders
        for mount_path in [*self.target.fs.mounts, "/mnt", "/media"]:
            if mount_path == "/":
                continue

            for mount_trash in self.target.fs.path(mount_path).rglob(".Trash-*"):
                yield UserDetails(None, None), mount_trash

    def check_compatible(self) -> None:
        if not self.trashes:
            raise UnsupportedPluginError("No Trash folder(s) found")

    @export(record=TrashRecord)
    @alias(name="recyclebin")
    def trash(self) -> Iterator[TrashRecord]:
        """Yield deleted files from GNOME Trash folders.

        Recovers deleted files and artifacts from ``$HOME/.local/share/Trash``.
        Probably also works with other desktop interfaces as long as they follow the Trash specification from FreeDesktop.

        Also parses media trash locations such as ``/media/$USER/$Label/.Trash-*``, ``/mnt/$Label/.Trash-*`` and other
        locations as defined in ``/etc/fstab``.

        Resources:
            - https://specifications.freedesktop.org/trash-spec/latest/
            - https://github.com/GNOME/glib/blob/main/gio/glocalfile.c
            - https://specifications.freedesktop.org/basedir-spec/latest/

        Yields ``TrashRecord`` records with the following fields:

        .. code-block:: text

            ts           (datetime): timestamp when the file was deleted or for expunged files when it could not be permanently deleted
            path         (path):     path where the file was located before it was deleted
            filesize     (filesize): size in bytes of the deleted file
            deleted_path (path):     path to the current location of the deleted file
            source       (path):     path to the .trashinfo file
        """  # noqa: E501

        for user_details, trash in self.trashes:
            for trash_info_file in trash.glob("info/*.trashinfo"):
                trash_info = configutil.parse(trash_info_file, hint="ini").get("Trash Info", {})
                original_path = self.target.fs.path(trash_info.get("Path", ""))

                # We use the basename of the .trashinfo file and not the Path variable inside the
                # ini file. This way we can keep duplicate basenames of trashed files separated correctly.
                deleted_path = trash / "files" / trash_info_file.name.replace(".trashinfo", "")

                if deleted_path.exists():
                    deleted_files = [deleted_path]

                    if deleted_path.is_dir():
                        deleted_files.extend(deleted_path.rglob("*"))

                    for file in deleted_files:
                        # NOTE: We currently do not 'fix' the original_path of files inside deleted directories.
                        # This would require guessing where the parent folder starts, which is impossible without
                        # making assumptions.
                        yield TrashRecord(
                            ts=trash_info.get("DeletionDate", 0),
                            path=original_path,
                            filesize=file.lstat().st_size if file.is_file() else None,
                            deleted_path=file,
                            source=trash_info_file,
                            _user=user_details.user,
                            _target=self.target,
                        )

                # We cannot determine if the deleted entry is a directory since the path does
                # not exist at $TRASH/files, so we work with what we have instead.
                else:
                    self.target.log.warning("Expected trashed file(s) at %s", deleted_path)
                    yield TrashRecord(
                        ts=trash_info.get("DeletionDate", 0),
                        path=original_path,
                        filesize=0,
                        deleted_path=deleted_path,
                        source=trash_info_file,
                        _user=user_details.user,
                        _target=self.target,
                    )

            # We also iterate expunged folders, they can contain files that could not be
            # deleted when the user pressed the "empty trash" button in the file manager.
            # Resources:
            #   - https://gitlab.gnome.org/GNOME/glib/-/issues/1665
            #   - https://bugs.launchpad.net/ubuntu/+source/nautilus/+bug/422012
            for item in (trash / "expunged").rglob("*/*"):
                stat = item.lstat()
                yield TrashRecord(
                    ts=stat.st_mtime,  # NOTE: This is the timestamp at which the file failed to delete
                    path=None,  # We do not know the original file path
                    filesize=stat.st_size if item.is_file() else None,
                    deleted_path=item,
                    source=trash / "expunged",
                    _user=user_details.user,
                    _target=self.target,
                )
