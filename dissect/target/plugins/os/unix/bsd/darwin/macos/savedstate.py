from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SavedStateRecord = TargetRecordDescriptor(
    "macos/savedstate/entry",
    [
        ("string", "bundle_id"),
        ("string", "state_id"),
        ("path", "source"),
    ],
)


class MacOSSavedStatePlugin(Plugin):
    """Plugin to parse macOS Saved Application State.

    Pre-macOS 15: ~/Library/Saved Application State/<bundle_id>.savedState/
    macOS 15+: ~/Library/Daemon Containers/<UUID>/Data/Library/Saved Application State/<UUID>.savedState/
    The container's bundle ID is resolved from .com.apple.containermanagerd.metadata.plist.
    """

    __namespace__ = "savedstate"

    GLOBS = [
        "Users/*/Library/Saved Application State/*/windows.plist",
        "Users/*/Library/Daemon Containers/*/Data/Library/Saved Application State/*/windows.plist",
    ]

    CONTAINER_METADATA = ".com.apple.containermanagerd.metadata.plist"

    def __init__(self, target):
        super().__init__(target)
        self._plist_paths = []
        root = self.target.fs.path("/")
        for g in self.GLOBS:
            self._plist_paths.extend(root.glob(g))

    def check_compatible(self) -> None:
        if not self._plist_paths:
            raise UnsupportedPluginError("No Saved Application State found")

    def _resolve_bundle_id(self, path):
        """Resolve the bundle ID for a saved state entry.

        For the old layout, the parent dir name IS the bundle ID (e.g. com.apple.Terminal.savedState).
        For macOS 15 Daemon Containers, read the container metadata plist.
        """
        parts = list(path.parts)

        # Check if this is a Daemon Containers path
        for i, part in enumerate(parts):
            if part == "Daemon Containers" and i + 1 < len(parts):
                # Container root is everything up to and including the UUID dir
                container_root = path.parents[0]
                for p in path.parents:
                    if p.parent.name == "Daemon Containers":
                        container_root = p
                        break
                meta_path = container_root / self.CONTAINER_METADATA
                if meta_path.exists():
                    try:
                        with meta_path.open("rb") as fh:
                            meta = plistlib.load(fh)
                        return meta.get("MCMMetadataIdentifier", path.parent.name)
                    except Exception:
                        pass
                return path.parent.name

        # Old layout: parent dir name minus .savedState suffix
        parent_name = path.parent.name
        if parent_name.endswith(".savedState"):
            return parent_name[: -len(".savedState")]
        return parent_name

    @export(record=SavedStateRecord)
    def entries(self) -> Iterator[SavedStateRecord]:
        """Report apps with saved application state (windows.plist)."""
        for path in self._plist_paths:
            try:
                bundle_id = self._resolve_bundle_id(path)
                state_id = path.parent.name

                yield SavedStateRecord(
                    bundle_id=bundle_id,
                    state_id=state_id,
                    source=path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading saved state %s: %s", path, e)
