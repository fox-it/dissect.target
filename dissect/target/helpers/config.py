import importlib
from pathlib import Path

CONFIG_NAME = ".targetcfg.py"


def load(path):
    config_spec = importlib.machinery.ModuleSpec("config", None)
    config = importlib.util.module_from_spec(config_spec)
    config_file = _find_config_file(path)
    if config_file:
        exec(config_file.read_text(), config.__dict__)
    return config


def _find_config_file(path):
    """Find a config file anywhere in the given path and return it.

    This algorithm allows parts of the path to not exist or the last part to be
    a filename.
    It also does not look in the root directory ('/') for config files.
    """

    config_file = None
    if path:
        path = Path(path)
        cur_path = path.absolute()

        # Look for a config file in provided path or in parent directories until found.
        # This will not allow config files in the root directory or "virtual" targets (e.g. "local").
        while not config_file and cur_path.exists() and cur_path.name != "":
            cur_config = cur_path.joinpath(CONFIG_NAME)
            if cur_config.is_file():
                config_file = cur_config
            cur_path = cur_path.parent

    return config_file
