from __future__ import annotations

import ast
import importlib.machinery
import importlib.util
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

log = logging.getLogger(__name__)

CONFIG_NAME = ".targetcfg.py"


def load(paths: list[Path | str] | Path | str | None) -> ModuleType:
    """Attempt to load one configuration from the provided path(s)."""

    if isinstance(paths, (Path, str)):
        paths = [paths]

    config_spec = importlib.machinery.ModuleSpec("config", None)
    config = importlib.util.module_from_spec(config_spec)
    config_file = _find_config_file(paths)

    if config_file:
        config_values = _parse_ast(config_file.read_bytes())
        config.__dict__.update(config_values)

    return config


def _parse_ast(code: str) -> dict[str, str | int]:
    # Only allow basic value assignments for backwards compatibility
    obj = {}

    module = ast.parse(code)
    if not isinstance(module, ast.Module):
        log.debug("Config did not parse to a module AST -- skipping")
        return obj

    for statement in module.body:
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.value, ast.Constant)
        ):
            log.debug("Skipping non-constant assignment")
            continue

        target = statement.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(target.ctx, ast.Store):
            log.debug("Skipping non-name assignment store")
            continue

        obj[target.id] = statement.value.value

    return obj


def _find_config_file(paths: list[Path | str] | None) -> Path | None:
    """Find a config file anywhere in the given path(s) and return it.

    This algorithm allows parts of the path to not exist or the last part to be a filename.
    It also does not look in the root directory ('/') for config files.
    """

    if not paths:
        return None

    config_file = None

    for path in paths:
        if not path:
            continue

        path = Path(path)
        cur_path = path.absolute()

        # Look for a config file in provided path or in parent directories until found.
        # This will not allow config files in the root directory or "virtual" targets (e.g. "local").
        while not config_file and cur_path.exists() and cur_path.name != "":
            cur_config = cur_path.joinpath(CONFIG_NAME)
            if cur_config.is_file():
                config_file = cur_config
            cur_path = cur_path.parent

        if config_file:
            break

    return config_file
