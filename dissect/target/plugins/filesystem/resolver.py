import re
from typing import Optional

from dissect.target.helpers import fsutil
from dissect.target.plugin import Plugin, internal

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
]


class ResolverPlugin(Plugin):
    def check_compatible(self):
        pass

    @internal
    def resolve(self, path: str, user: Optional[str] = None):
        """Resolve a partial path string to a file or directory present in the target.

        For Windows known file locations are searched, e.g. paths from the %path% variable and common path extentions
        tried. If a user SID is provided that user's %path% variable is used.
        """
        if not path:
            return path

        if self.target.os == "windows":
            return self.resolve_windows(path, user_sid=user)
        else:
            return self.resolve_default(path, user_id=user)

    def resolve_windows(self, path: str, user_sid: Optional[str] = None):
        # Normalize first so the replacements are easier
        path = fsutil.normalize(path, alt_separator=self.target.fs.alt_separator)

        for entry, environment in REPLACEMENTS:
            path = re.sub(entry, re.escape(environment), path, flags=re.IGNORECASE)

        path = self.target.expand_env(path)
        # Normalize again because environment variable expansion may have introduced backslashes again
        path = fsutil.normalize(path, alt_separator=self.target.fs.alt_separator)

        # The \??\ pseudo path is used to point to the directory containing
        # (the user's) devices, e.g. \??\C:\foo\bar.
        # For more information see:
        # - https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
        # - https://stackoverflow.com/questions/23041983/path-prefixes-and
        path = path.replace("/??/", "")

        if self.target.fs.exists(path):
            return path

        # Very simplistic lookup for an executable as part of an `"path/to/executable" -arguments -here` construction
        quoted = re_quoted.findall(path)
        if quoted:
            if self.target.fs.exists(quoted[0]):
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
        pathext = self.target.pathext | set([""])

        for part in parts:
            lookup = " ".join([lookup, part]) if lookup else part
            for ext in pathext:
                lookup_ext = lookup + ext
                if self.target.fs.exists(lookup_ext):
                    return lookup_ext

                for search_path in search_paths:
                    lookup_path = "/".join([search_path, lookup_ext])
                    if self.target.fs.exists(lookup_path):
                        return lookup_path

        return path

    def resolve_default(self, path: str, user_id: Optional[str] = None):
        return fsutil.normalize(path, alt_separator=self.target.fs.alt_separator)
