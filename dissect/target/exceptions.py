import os
import sys
import traceback
from typing import Callable


class Error(Exception):
    """Generic dissect.target error"""

    def __init__(self, message=None, cause=None, extra=None):
        if extra:
            exceptions = "\n\n".join(["".join(traceback.format_exception_only(type(e), e)) for e in extra])
            message = f"{message}\n\nAdditionally, the following exceptions occurred:\n\n{exceptions}"

        super().__init__(message)
        self.__cause__ = cause
        self.__extra__ = extra


# Use FatalError if you don't want your error to be buried by other errors
# but just mark it as fatal so the tools 'on top' may proceed to shutdown
class FatalError(Error):
    """An error occurred that cannot be resolved."""

    def emit_last_message(self, emitter: Callable) -> None:
        emitter(str(self))
        os.dup2(os.open(os.devnull, os.O_RDWR), sys.stdout.fileno())
        os.dup2(os.open(os.devnull, os.O_RDWR), sys.stderr.fileno())


class TargetError(Error):
    """A target error occurred."""


class LoaderError(Error):
    """A loader error occurred."""


class PluginError(Error):
    """A plugin error occurred."""


class ContainerError(Error):
    """A container error occurred."""


class VolumeSystemError(Error):
    """A volume system error occurred."""


class FilesystemError(Error):
    """A filesystem error occurred."""


class InvalidTaskError(Error):
    """A invalid XML file."""


class RegistryKeyNotFoundException(Error):
    """The registry was not found."""


class UnsupportedPluginError(PluginError):
    """The requested plugin is not supported by the target."""

    def root_cause_str(self) -> str:
        """Often with this type of Error, the root cause is more descriptive for the user."""
        return str(self.__cause__.args[0])


class PluginNotFoundError(PluginError):
    """Plugin cannot be found."""


class FileNotFoundError(FilesystemError):
    """The requested path could not be found."""


class IsADirectoryError(FilesystemError):
    """The entry is a directory."""


class NotADirectoryError(FilesystemError):
    """The entry is not a directory."""


class NotASymlinkError(FilesystemError):
    """The entry is not a symlink."""


class SymlinkRecursionError(FilesystemError):
    """A symlink loop is detected for the entry."""


class RegistryError(Error):
    """A registry error occurred."""


class RegistryKeyNotFoundError(RegistryError):
    """The requested registry key could not be found."""


class RegistryValueNotFoundError(RegistryError):
    """The requested registry value could not be found."""


class HiveUnavailableError(RegistryError):
    """The requested hive is unavailable."""


class RegistryCorruptError(RegistryError):
    """The registry is corrupt."""
