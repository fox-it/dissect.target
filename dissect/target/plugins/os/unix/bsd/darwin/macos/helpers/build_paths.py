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
            for cur_dir in home_dir.glob(d):
                cur_dir = cur_dir.resolve()
                if cur_dir.exists():
                    users_dirs.add((user_details, cur_dir))
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
    results = set()

    for base in START_PATHS:
        results.update(find_end_paths(target, end_path, base))

    return results


def find_end_paths(target: Target, end_path: str, base_path: str) -> set:
    found = set()

    if isinstance(base_path, str):
        base_path = target.fs.path(base_path)

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
