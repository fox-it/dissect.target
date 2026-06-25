from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.plugin import Plugin
    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


def _build_userdirs(plugin: Plugin, hist_paths: list[str]) -> set[tuple[UserDetails, Path]]:
    """Join the selected dirs with the user home path.

    Args:
        hist_paths: A list with paths as strings.

    Returns:
        List of tuples containing user and unique file path objects.
    """
    users_dirs: set[tuple] = set()
    for user_details in plugin.target.user_details.all_with_home():
        for d in hist_paths:
            home_dir: Path = user_details.home_path
            try:
                for cur_dir in home_dir.glob(d):
                    cur_dir = cur_dir.resolve()
                    if cur_dir.exists():
                        users_dirs.add((user_details, cur_dir))
            except Exception:
                pass
    return users_dirs


START_PATHS = {
    "/Applications/",
    "/Applications/Utilities/",
    "/System/Library/CoreServices/",
    "/System/Library/Extensions/",
    "/System/Library/Filesystems/*/",
    "/System/Library/Filesystems/*/Encodings/",
    "/System/Library/PrivateFrameworks/",
    "/System/Library/SystemProfiler/*/",
    "/System/Library/Frameworks",
}

EXTENSIONS = {
    "*.app": ["/Contents/", "/Contents/Resources/"],
    "*.kext": ["/Contents/", "/Contents/PlugIns/", "/Contents/Resources/"],
    "*.framework": ["/Versions/A/", "/Versions/A/Resources/"],
    "*.bundle": ["/Contents/", "/Contents/Resources/"],
    "*.plugin": ["/Contents/"],
    "*.prefPane": ["/Contents/", "/Contents/Resources/"],
    "*.help": ["/Contents/", "/Contents/Resources/"],
    "*.spreporter": ["/Contents/Resources/"],
}


def find_bundle_files(target: Target, end_path: str) -> set:
    """Search for files matching a given end path within known macOS bundle locations.

    Iterates over predefined base system paths and collects all matching files
    found by recursively exploring bundle structures.

    Args:
        target (Target): Object providing filesystem access.
        end_path (str): Relative path to search for within bundles.

    Returns:
        set: A set of matching file paths.
    """
    results = set()

    for base in START_PATHS:
        results.update(find_end_paths(target, end_path, target.fs.path(base)))

    return results


def find_end_paths(target: Target, end_path: str, base_path: Path) -> set:
    """Recursively search for files within macOS bundle directories that match a given end path.

    Looks for known bundle types (e.g., .app, .framework, .kext) based on the
    EXTENSIONS mapping, which defines the internal subdirectories that should be traversed
    for each bundle extension. Explores the relevant subpaths for every discovered bundle,
    and checks whether the specified relative file path (end path) exists.

    Continues recursively into each valid subpath, in order to handle
    nested bundle structures.

    Args:
        target (Target): Object providing filesystem access.
        end_path (str): Relative path to locate inside bundle directories.
        base_path (Path): Base directory from which the search begins.

    Returns:
        set: A set of matching file paths found within bundle hierarchies.
    """
    found = set()

    for ext, subpaths in EXTENSIONS.items():
        for bundle_str in target.fs.glob(f"{base_path}/{ext}"):
            bundle = target.fs.path(bundle_str)

            for sub in subpaths:
                sub_path = bundle.joinpath(sub.lstrip("/"))

                if not sub_path.exists():
                    continue

                candidate = sub_path.joinpath(end_path.lstrip("/"))
                if candidate.exists():
                    found.add(candidate)

                found.update(find_end_paths(target, end_path, sub_path))

    return found
