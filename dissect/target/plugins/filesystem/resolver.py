import re

from dissect.target.helpers import fsutil
from dissect.target.plugin import Plugin, internal

re_quoted = re.compile(r"\"(.+?)\"")

REPLACEMENTS = [
    # Windows sometimes uses /systemroot/ instead of /%SystemRoot%/, so we
    # replace the former with the latter so expand_env() can replace it with
    # the correct value.
    (r"/systemroot/", r"/%systemroot%/"),
]

SEARCH_PATHS = [
    "sysvol/windows/system32",
    "sysvol/windows/syswow64",
    "sysvol/windows",
]


class ResolverPlugin(Plugin):
    def check_compatible(self):
        pass

    @internal
    def resolve(self, path):
        if not path:
            return path

        if self.target.os == "windows":
            return self.resolve_windows(path)
        else:
            return self.resolve_default(path)

    def resolve_windows(self, path):
        # Normalize first so the replacements are easier
        path = fsutil.normalize(path)

        for entry, environment in REPLACEMENTS:
            path = re.sub(entry, re.escape(environment), path, flags=re.IGNORECASE)

        path = self.target.expand_env(path)
        # Normalize again because environment variable expansion may have introduced backslashes again
        path = fsutil.normalize(path)

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

        # Windows supports some path resolution when leaving out the extension or full path
        # The string given to this function may be a command string including arguments, so split on spaces and
        # for each part, check if a file exists with an allowed extension and in any of the search paths.
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

                for search_path in SEARCH_PATHS:
                    fpath = "/".join([search_path, lookup_ext])
                    if self.target.fs.exists(fpath):
                        return fpath

        return path

    @staticmethod
    def resolve_default(path):
        return fsutil.normalize(path)
