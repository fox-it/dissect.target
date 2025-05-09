from __future__ import annotations

from pathlib import Path
from typing import Any

import setuptools.build_meta
from setuptools.build_meta import *  # noqa: F403
from setuptools.command.build_py import build_py as _build_py

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def get_requires_for_build_wheel(config_settings: dict[str, Any] | None = None) -> list[str]:
    with Path(__file__).parent.parent.parent.joinpath("pyproject.toml").open("rb") as fh:
        pyproject = tomllib.load(fh)

    return [
        *setuptools.build_meta.get_requires_for_build_wheel(config_settings),
        *pyproject["project"]["dependencies"],
        *pyproject["project"]["optional-dependencies"]["full"],
    ]


class build_py(_build_py):
    def find_package_modules(self, package: str, package_dir: str) -> list[tuple[str, str, str]]:
        result = super().find_package_modules(package, package_dir)
        if package == "dissect.target.plugins":
            result.append(("dissect.target.plugins", "_pluginlist", str(Path(package_dir) / "_pluginlist.py")))
        return result

    def build_module(self, module: str, module_file: str, package: str) -> None:
        if (package, module) == ("dissect.target.plugins", "_pluginlist"):
            import sys

            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from dissect.target.tools.build_pluginlist import generate_pluginlist

            if isinstance(package, str):
                package = package.split(".")

            out_file = Path(self.get_module_outfile(self.build_lib, package, module))
            self.mkpath(str(out_file.parent))

            print(f"generating pluginlist -> {out_file}")
            out_file.write_text(generate_pluginlist())

            return (out_file, True)
        return super().build_module(module, module_file, package)
