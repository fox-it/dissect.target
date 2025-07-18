from __future__ import annotations

import re

from dissect.target.helpers import fsutil
from dissect.target.plugin import OperatingSystem, Plugin, internal

re_quoted = re.compile(r"\"(.+?)\"")

REPLACEMENTS = [
    # Windows sometimes uses /systemroot/ instead of /%SystemRoot%/, so we
    # replace the former with the latter so expand_env() can replace it with
    # the correct value.
    (r"/systemroot/", r"/%systemroot%/"),
]

FALLBACK_SEARCH_PATHS = [
    "sysvol/windows/system32",
    "sysvol/windows/syswow64",
    "sysvol/windows",
    "sysvol/winnt/system32",
    "sysvol/winnt",
]


class ResolverPlugin(Plugin):
    def check_compatible(self) -> None:
        pass

    @internal
    def resolve(self, path: str, user: str | None = None) -> fsutil.TargetPath:
        """Resolve a partial path string to a file or directory present in the target.

        For Windows known file locations are searched, e.g. paths from the ``%path%`` variable and common
        path extensions tried. If a user SID is provided that user's ``%path%`` variable is used.
        """
        if not path:
            return self.target.fs.path(path)

        if self.target.os == OperatingSystem.WINDOWS:
            resolved_path = self.resolve_windows(path, user_sid=user)
        else:
            resolved_path = self.resolve_default(path, user_id=user)

        return self.target.fs.path(resolved_path)

    def resolve_windows(self, path: str, user_sid: str | None = None) -> str:
        # Normalize first so the replacements are easier
        path = fsutil.normalize(path, alt_separator=self.target.fs.alt_separator)

        for entry, environment in REPLACEMENTS:
            path = re.sub(entry, re.escape(environment), path, flags=re.IGNORECASE)

        path = self.target.expand_env(path, user_sid)
        # Normalize again because environment variable expansion may have introduced backslashes again
        path = fsutil.normalize(path, alt_separator=self.target.fs.alt_separator)

        # The \??\ pseudo path is used to point to the directory containing
        # (the user's) devices, e.g. \??\C:\foo\bar.
        # The \\?\ prefix in Windows file I/O bypasses string parsing and
        # allows exceeding the MAX_PATH limit, e.g. \\?\C:\very\long\path.
        # For more information see:
        # - https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
        # - https://stackoverflow.com/questions/23041983/path-prefixes-and
        # - https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file#win32-file-namespaces
        path = path.replace("/??/", "").replace("/?/", "")

        if self.target.fs.exists(path):
            return path

        # Very simplistic lookup for an executable as part of an `"path/to/executable" -arguments -here` construction
        quoted = re_quoted.findall(path)
        if quoted and self.target.fs.exists(quoted[0]):
            return quoted[0]

        # Construct a list of search paths to look in. If a user SID is given, both the system and user search paths are
        # used, else only the system search paths.
        search_paths = []
        user_env_vars = self.target.user_env(user_sid)
        user_path_env = user_env_vars.get("%path%")
        if user_path_env:
            for path_env in user_path_env.split(";"):
                # Normalize because environment variable may contain backslashes
                path_env = fsutil.normalize(path_env, alt_separator=self.target.fs.alt_separator).rstrip("/")
                search_paths.append(path_env)
        if not search_paths:
            search_paths = FALLBACK_SEARCH_PATHS

        # Windows supports some path resolution when leaving out the extension or full path.
        # The string given to this function may be a command string including arguments, so split on spaces and,
        # appending one part at a time, check if a file exists with an allowed extension and in any of the search paths.
        # If it does, it's probably the file we're looking for.
        lookup = ""
        parts = path.split(" ")
        pathext = self.target.pathext | {""}

        for part in parts:
            lookup = f"{lookup} {part}" if lookup else part
            for ext in pathext:
                lookup_ext = lookup + ext
                if self.target.fs.is_file(lookup_ext):
                    return lookup_ext

                for search_path in search_paths:
                    lookup_path = fsutil.join(search_path, lookup_ext, alt_separator=self.target.fs.alt_separator)
                    if self.target.fs.is_file(lookup_path):
                        return lookup_path

        return path

    def resolve_default(self, path: str, user_id: str | None = None) -> str:
        return fsutil.normalize(path, alt_separator=self.target.fs.alt_separator)
