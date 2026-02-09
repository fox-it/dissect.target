from __future__ import annotations

import re
from collections import OrderedDict
from typing import TYPE_CHECKING, NamedTuple

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
    create_extended_descriptor,
)
from dissect.target.plugin import OperatingSystem, Plugin, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

EnvironmentRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/environment",
    [
        ("string", "name"),
        ("string", "value"),
    ],
)

PathextRecord = TargetRecordDescriptor(
    "windows/pathext",
    [
        ("string", "pathext"),
    ],
)


class EnvVarDetails(NamedTuple):
    name: str
    reg_keys: tuple[str, ...] = ()
    reg_value: str | None = None
    default: str | None = None


class EnvironmentVariablePlugin(Plugin):
    """Plugin that provides access to global environment variables.

    Mostly used internally.
    """

    # More information on the variables below can be found at:
    # https://renenyffenegger.ch/notes/Windows/development/environment-variables/index
    VARIABLES = (
        EnvVarDetails(
            # The value 'sysvol' is dissect specific as we map the system drive
            # to the sysvol drive name / directory in the root fs.
            name="%systemdrive%",
            default="sysvol",
        ),
        EnvVarDetails(
            "%windir%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",),
            "SystemRoot",
        ),
        EnvVarDetails(
            # Note that the Directory value in
            # HKLM\SYSTEM\CurrentControlSet\Control\Windows, which is sometimes
            # mentioned, contains the literal %SystemRoot%.
            "%systemroot%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",),
            "SystemRoot",
        ),
        EnvVarDetails(
            # Since Windows Vista this has the same value as %programdata%
            # Before that it was %systemdrive%\Documents and Settings\All Users.
            "%allusersprofile%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",),
            "ProgramData",
        ),
        EnvVarDetails(
            "%programdata%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",),
            "ProgramData",
        ),
        EnvVarDetails(
            "%public%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",),
            "Public",
        ),
        EnvVarDetails(
            "%commonprogramfiles%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",),
            "CommonFilesDir",
        ),
        EnvVarDetails(
            "%commonprogramfiles(x86)%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",),
            "CommonFilesDir (x86)",
        ),
        EnvVarDetails(
            "%commonprogramw6432%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",),
            "CommonW6432Dir",
        ),
        EnvVarDetails(
            "%programfiles%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",),
            "ProgramFilesDir",
        ),
        EnvVarDetails(
            "%programfiles(x86)%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",),
            "ProgramFilesDir (x86)",
        ),
        EnvVarDetails(
            "%programw6432%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",),
            "ProgramW6432Dir",
        ),
        EnvVarDetails(
            "%temp%",
            (
                "HKLM\\SOFTWARE\\DefaultUserEnvironment",
                "HKLM\\SYSTEM\\CurrentControlSet\\Session Manager\\Environment",
            ),
            "TEMP",
        ),
        EnvVarDetails(
            "%tmp%",
            (
                "HKLM\\SOFTWARE\\DefaultUserEnvironment",
                "HKLM\\SYSTEM\\CurrentControlSet\\Session Manager\\Environment",
            ),
            "TMP",
        ),
        EnvVarDetails(
            # Note that %path% is a concatenation of the given reg_keys, not an
            # override by the last one available.
            "%path%",
            (
                "HKLM\\SOFTWARE\\DefaultUserEnvironment",
                "HKLM\\SYSTEM\\CurrentControlSet\\Session Manager\\Environment",
            ),
            "Path",
        ),
    )

    USER_VARIABLES = (
        EnvVarDetails(
            "%userprofile%",
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{user_sid}",),
            "ProfileImagePath",
        ),
        EnvVarDetails(
            name="%appdata%",
            default="%userprofile%\\appdata\\roaming",
        ),
        EnvVarDetails(
            name="%localappdata%",
            default="%userprofile%\\appdata\\local",
        ),
        EnvVarDetails(
            "%onedrive%",
            ("HKU\\{user_sid}\\Environment",),
            "Onedrive",
        ),
        EnvVarDetails(
            # This overrides the 'global' %temp% variable
            "%temp%",
            (
                "HKLM\\SOFTWARE\\DefaultUserEnvironment",
                "HKLM\\SYSTEM\\CurrentControlSet\\Session Manager\\Environment",
                "HKU\\{user_sid}\\Environment",
            ),
            "TEMP",
        ),
        EnvVarDetails(
            # This overrides the 'global' %tmp% variable
            "%tmp%",
            (
                "HKLM\\SOFTWARE\\DefaultUserEnvironment",
                "HKLM\\SYSTEM\\CurrentControlSet\\Session Manager\\Environment",
                "HKU\\{user_sid}\\Environment",
            ),
            "TMP",
        ),
        EnvVarDetails(
            # Note that %path% is a concatenation of the given reg_keys, not an
            # override by the last one available.
            "%path%",
            (
                "HKLM\\SOFTWARE\\DefaultUserEnvironment",
                "HKLM\\SYSTEM\\CurrentControlSet\\Session Manager\\Environment",
                "HKU\\{user_sid}\\Environment",
            ),
            "Path",
        ),
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self._env = None
        self._pathext = None

    @staticmethod
    def _expand_env(value: str, env_vars: OrderedDict[str, str]) -> str:
        """Replace, in order, all occurences of the keys from env_vars in path
        with the respective values from env_vars.
        """
        for var_name, var_value in env_vars.items():
            # lambda is used to prevent re.sub from doing substitution logic itself
            value = re.sub(re.escape(var_name), lambda _, var_value=var_value: var_value, value, flags=re.IGNORECASE)
        return value

    @classmethod
    def _expand_env_vars(cls, env_vars: OrderedDict[str, str]) -> OrderedDict[str, str]:
        """Replace, in order, all occurrences of the keys from env_vars in the
        other values of env_vars with the respective values of env_vars.

        This mimics Windows' immediate expansion and means the order in which
        the variables are defined in env_vars matters.
        See also: https://devblogs.microsoft.com/oldnewthing/20060823-00/?p=29993
        """
        expanded_env_vars = OrderedDict()

        for var_name, var_value in env_vars.items():
            var_value = cls._expand_env(var_value, expanded_env_vars)
            expanded_env_vars[var_name] = var_value

        return expanded_env_vars

    def _get_env_vars(self, env_var_details: list[EnvVarDetails]) -> OrderedDict[str, str]:
        """Get the environment variables defined in the env_var_details list.

        An OrderedDict is returned with the variable names as the keys and the
        variable values as the values. The values are NOT expanded with the
        values of variables earlier in the order.
        """
        env_vars = OrderedDict()

        for env_var_detail in env_var_details:
            var_value = env_var_detail.default

            if env_var_detail.reg_keys and env_var_detail.reg_value:
                # If there are multiple reg_keys, values from later ones override
                # those from earlier ones. Except for the %path% variable,
                # which is concatenated (with a ; separator) instead of
                # being overwritten.
                for reg_key in env_var_detail.reg_keys:
                    try:
                        reg_key_value = self.target.registry.value(reg_key, env_var_detail.reg_value).value
                    except RegistryError:  # noqa: PERF203
                        pass
                    else:
                        if env_var_detail.name == "%path%" and var_value is not None:
                            var_value = ";".join((var_value.rstrip(";"), reg_key_value))
                        else:
                            var_value = reg_key_value

            if not var_value:
                continue

            env_vars[env_var_detail.name] = var_value

        return env_vars

    def _get_system_env_vars(self) -> OrderedDict[str, str]:
        """Get the system environment variables

        An OrderedDict is returned with the variable names as the keys and the
        variable values as the values. The values ARE expanded with the values
        of variables earlier in the order.
        """
        if self._env is None:
            self._env = self._get_env_vars(self.VARIABLES)
            self._env = self._expand_env_vars(self._env)

        return self._env

    def _get_user_env_vars(self, user_sid: str | None = None) -> OrderedDict[str, str]:
        """Get the environment variables as seen by the user of the given user SID.

        If no user_sid is given, the function gives back the system environment
        variables.

        An OrderedDict is returned with the variable names as the keys and the
        variable values as the values. The values ARE expanded with the values
        of variables earlier in the order.
        """
        env_vars = self._get_system_env_vars()
        if user_sid is not None:
            env_vars = env_vars.copy()
            user_env_var_details = []

            for env_var_details in self.USER_VARIABLES:
                reg_keys = tuple(reg_key.format(user_sid=user_sid) for reg_key in env_var_details.reg_keys)
                env_var_details = env_var_details._replace(reg_keys=reg_keys)
                user_env_var_details.append(env_var_details)

            user_vars = self._get_env_vars(user_env_var_details)

            # To preserve the order in USER_VARIABLES, variables which are also
            # present in the system env_vars OrderedDict must be removed
            # before updating it with the user_vars.
            for user_var in user_vars:
                if user_var in env_vars:
                    del env_vars[user_var]
            env_vars.update(user_vars)
            env_vars = self._expand_env_vars(env_vars)

        return env_vars

    def check_compatible(self) -> None:
        if self.target.os != OperatingSystem.WINDOWS:
            raise UnsupportedPluginError("Target operating system is not Windows")

    @internal
    def expand_env(self, path: str, user_sid: str | None = None) -> str:
        env_vars = self._get_user_env_vars(user_sid)
        return self._expand_env(path, env_vars)

    @internal
    def user_env(self, user_sid: str | None = None) -> OrderedDict[str, str]:
        """Return a dict of all found (user) environment variables.

        If no ``user_sid`` is provided, this function will return just the system environment variables.
        """
        return self._get_user_env_vars(user_sid)

    @property
    @internal
    def env(self) -> OrderedDict[str, str]:
        """Return a dict of all found system environment variables."""
        return self._get_system_env_vars()

    @export(record=EnvironmentRecord)
    def environment_variables(self) -> Iterator[EnvironmentRecord]:
        """Return all environment variables on a Windows system.

        Environment variables are dynamic-named values that can affect the way processes are running on the system.
        Examples variables are PATH, HOME and TEMP. Adversaries may alter or create environment variables to exploit
        a system.

        References:
            - https://en.wikipedia.org/wiki/Environment_variable
            - https://www.elttam.com/blog/env/
        """
        for name, value in self._get_system_env_vars().items():
            yield EnvironmentRecord(
                name=name,
                value=value,
                _target=self.target,
            )

        for user in self.target.users():
            for name, value in self._get_user_env_vars(user.sid).items():
                yield EnvironmentRecord(
                    name=name,
                    value=value,
                    _target=self.target,
                    _user=user,
                )

    def _get_pathext(self) -> set[str]:
        if self._pathext is None:
            self._pathext = set()

            try:
                env_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
                for key in self.target.registry.keys(env_key):
                    for ext in key.value("PATHEXT").value.lower().split(";"):
                        self._pathext.add(ext)
            except RegistryError:
                pass
        return self._pathext

    @property
    @internal
    def pathext(self) -> set[str]:
        """Return a list of all found path extensions."""
        return self._get_pathext()

    @export(record=PathextRecord)
    def path_extensions(self) -> Iterator[PathextRecord]:
        """Return all found path extensions."""
        for pathext in self._get_pathext():
            yield PathextRecord(
                pathext=pathext,
                _target=self.target,
            )
