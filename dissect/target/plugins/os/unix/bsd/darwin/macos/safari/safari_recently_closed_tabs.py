from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

SafariRecentlyClosedTabsRecord = TargetRecordDescriptor(
    "macos/safari_recently_closed_tabs",
    [
        ("boolean", "is_disposable"),
        ("string[]", "ancestor_tab_uuids_key"),
        ("boolean", "tab_group_type_for_tab_key"),
        ("string", "tab_group_for_tab"),
        ("datetime", "date_closed"),
        ("string", "profile_uuid"),
        ("boolean", "safe_to_load"),
        ("varint", "tab_index"),
        ("string", "window_uuid"),
        ("datetime", "last_visit_time"),
        ("string", "tab_uuid"),
        ("string", "tab_url"),
        ("varint", "tab_state_version"),
        ("string", "tab_title"),
        ("boolean", "is_muted"),
        ("varint", "process_identifier"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

WindowRecord = TargetRecordDescriptor(
    "macos/safari_recently_closed_tabs/window",
    [
        ("varint", "selected_tab_index"),
        ("varint", "window_unified_sidebar_mode"),
        ("boolean", "tab_bar_hidden"),
        ("datetime", "date_closed"),
        ("boolean", "favorites_bar_hidden"),
        ("boolean", "is_popup_window"),
        ("string", "profile_uuid"),
        ("string", "window_restoration_archive_data"),
        ("boolean", "is_private_window"),
        ("boolean", "miniaturized"),
        ("boolean", "prefers_reading_list_sidebar_visible"),
        ("varint", "selected_pinned_tab_index"),
        ("string[]", "unnamed_tab_group_uuids"),
        ("string", "window_content_rect"),
        ("string", "window_state_version"),
        ("string", "window_uuid"),
        ("string", "active_tab_group_uuid"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

ClosedPersistentStatesVersionRecord = TargetRecordDescriptor(
    "macos/safari_recently_closed_tabs/closed_persistent_states_version",
    [
        ("string", "closed_tab_or_window_persistent_states_version"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

PersistentStateTypeRecord = TargetRecordDescriptor(
    "macos/safari_recently_closed_tabs/persistent_state_type",
    [
        ("varint", "persistent_state_type"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

SafariRecentlyClosedTabsRecords = (
    SafariRecentlyClosedTabsRecord,
    WindowRecord,
    ClosedPersistentStatesVersionRecord,
    PersistentStateTypeRecord,
)

FIELD_MAPPINGS = {
    "IsDisposable": "is_disposable",
    "AncestorTabUUIDsKey": "ancestor_tab_uuids_key",
    "TabGroupTypeForTabKey": "tab_group_type_for_tab_key",
    "TabGroupForTab": "tab_group_for_tab",
    "DateClosed": "date_closed",
    "ProfileUUID": "profile_uuid",
    "SafeToLoad": "safe_to_load",
    "TabIndex": "tab_index",
    "WindowUUID": "window_uuid",
    "LastVisitTime": "last_visit_time",
    "TabUUID": "tab_uuid",
    "TabURL": "tab_url",
    "TabStateVersion": "tab_state_version",
    "TabTitle": "tab_title",
    "IsMuted": "is_muted",
    "ProcessIdentifier": "process_identifier",
    "SelectedTabIndex": "selected_tab_index",
    "WindowUnifiedSidebarMode": "window_unified_sidebar_mode",
    "TabBarHidden": "tab_bar_hidden",
    "FavoritesBarHidden": "favorites_bar_hidden",
    "IsPopupWindow": "is_popup_window",
    "WindowRestorationArchiveData": "window_restoration_archive_data",
    "IsPrivateWindow": "is_private_window",
    "Miniaturized": "miniaturized",
    "PrefersReadingListSidebarVisible": "prefers_reading_list_sidebar_visible",
    "SelectedPinnedTabIndex": "selected_pinned_tab_index",
    "UnnamedTabGroupUUIDs": "unnamed_tab_group_uuids",
    "WindowContentRect": "window_content_rect",
    "WindowStateVersion": "window_state_version",
    "activeTabGroupUUID": "active_tab_group_uuid",
    "PersistentStateType": "persistent_state_type",
    "ClosedTabOrWindowPersistentStatesVersion": "closed_tab_or_window_persistent_states_version",
}


class SafariRecentlyClosedTabsPlugin(Plugin):
    """macOS Safari recently closed tabs (plist) plugin.

    References:
        - https://medium.com/@cyberengage.org/p13-analyzing-safari-browser-apple-mail-data-and-recents-database-artifacts-on-macos-9b58848d70ec
    """

    USER_PATH = ("Library/Safari/RecentlyClosedTabs.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No RecentlyClosedTabs.plist files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariRecentlyClosedTabsRecords)
    def safari_recently_closed_tabs(self) -> Iterator[SafariRecentlyClosedTabsRecords]:
        """Return macOS Safari recently closed tabs information.

        Yields the following record types extracted from the
        RecentlyClosedTabs.plist files:

        .. code-block:: text

            SafariRecentlyClosedTabsRecord:
                is_disposable (boolean): Indicates whether the tab entry is disposable.
                ancestor_tab_uuids_key (string[]): List of ancestor tab UUIDs.
                tab_group_type_for_tab_key (boolean): Indicates if the tab belongs to a tab group type.
                tab_group_for_tab (string): UUID of the associated tab group.
                date_closed (datetime): Timestamp when the tab was closed.
                profile_uuid (string): Profile identifier.
                safe_to_load (boolean): Indicates if the tab is safe to restore.
                tab_index (varint): Index of the tab within the window.
                window_uuid (string): UUID of the parent window.
                last_visit_time (datetime): Timestamp of the last visit to the tab.
                tab_uuid (string): Unique identifier for the tab.
                tab_url (string): URL of the tab.
                tab_state_version (varint): Version of the tab state.
                tab_title (string): Title of the tab.
                is_muted (boolean): Indicates whether the tab was muted.
                process_identifier (varint): Process identifier associated with the tab.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the RecentlyClosedTabs.plist file.

            WindowRecord:
                selected_tab_index (varint): Index of the selected tab in the window.
                window_unified_sidebar_mode (varint): Sidebar mode.
                tab_bar_hidden (boolean): Indicates if the tab bar is hidden.
                date_closed (datetime): Timestamp when the window was closed.
                favorites_bar_hidden (boolean): Indicates if the favorites bar is hidden.
                is_popup_window (boolean): Indicates if the window is a popup.
                profile_uuid (string): Profile identifier.
                window_restoration_archive_data (string): Window restoration archive data.
                is_private_window (boolean): Indicates if the window was private.
                miniaturized (boolean): Indicates if the window was minimized.
                prefers_reading_list_sidebar_visible (boolean): Reading list sidebar visibility.
                selected_pinned_tab_index (varint): Index of the selected pinned tab.
                unnamed_tab_group_uuids (string[]): List of unnamed tab group UUIDs.
                window_content_rect (string): Window geometry (position and size).
                window_state_version (string): Version of the window state data.
                window_uuid (string): Unique identifier for the window.
                active_tab_group_uuid (string): UUID of the active tab group.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the RecentlyClosedTabs.plist file.

            ClosedPersistentStatesVersionRecord:
                closed_tab_or_window_persistent_states_version (string): Version of the persistent states.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the RecentlyClosedTabs.plist file.

            PersistentStateTypeRecord:
                persistent_state_type (varint): Type of the persistent state.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the RecentlyClosedTabs.plist file.

        """
        yield from build_plist_records(
            self,
            self.files,
            SafariRecentlyClosedTabsRecords,
            field_mappings=FIELD_MAPPINGS,
            function_name="macos/safari_recently_closed_tabs",
        )
