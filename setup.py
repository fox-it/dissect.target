import re

from setuptools import find_packages, setup
from setuptools.command.easy_install import ScriptWriter

# Use a custom entrypoint script template when installing in editable mode (pip
# install -e). When installing in editable mode the legacy, unused and slow
# import:
#
# from pkg_resources import load_entry_point
#
# is added because a legacy code path from setuptools is called by pip which
# generates the entrypoint scripts. This does not affect generating entrypoint
# script when installing from wheels or source distributions (as
# pep-517/pep-518 will turn them into wheels first).
CONSOLE_SCRIPT_TEMPLATE = """\
# -*- coding: utf-8 -*-
# EASY-INSTALL-ENTRY-SCRIPT: '{3}','{4}','{5}'
__requires__ = '{3}'
import re
import sys

from {0} import {1}

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\\.pyw?|\\.exe)?$', '', sys.argv[0])
    sys.exit({2}())
"""


@classmethod
def get_args_patched(cls, dist, header=None):
    if header is None:
        header = cls.get_header()
    spec = str(dist.as_requirement())
    for type_ in "console", "gui":
        group = type_ + "_scripts"
        for name, ep in dist.get_entry_map(group).items():
            if re.search(r"[\\/]", name):
                raise ValueError("Path separators not allowed in script names")
            script_text = CONSOLE_SCRIPT_TEMPLATE.format(
                ep.module_name, ep.attrs[0], ".".join(ep.attrs), spec, group, name
            )
            args = cls._get_script_args(type_, name, header, script_text)
            for res in args:
                yield res


ScriptWriter.get_args = get_args_patched

setup(
    name="dissect.target",
    packages=list(map(lambda v: "dissect." + v, find_packages("dissect"))),
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.eventlog>=3.0.dev,<4.0.dev",
        "dissect.evidence>=3.0.dev,<4.0.dev",
        "dissect.ntfs>=3.0.dev,<4.0.dev",
        "dissect.regf>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
        "dissect.hypervisor>=3.0.dev,<4.0.dev",
        "dissect.volume>=3.0.dev,<4.0.dev",
        "flow.record~=3.5",
        "structlog",
    ],
    extras_require={
        "full": [
            "asn1crypto",
            "defusedxml",
            "dissect.cim>=3.0.dev,<4.0.dev",
            "dissect.clfs>=1.0.dev,<2.0.dev",
            "dissect.esedb>=3.0.dev,<4.0.dev",
            "dissect.etl>=3.0.dev,<4.0.dev",
            "dissect.extfs>=3.0.dev,<4.0.dev",
            "dissect.fat>=3.0.dev,<4.0.dev",
            "dissect.ffs>=3.0.dev,<4.0.dev",
            "dissect.sql>=3.0.dev,<4.0.dev",
            "dissect.xfs>=3.0.dev,<4.0.dev",
            "ipython",
            "fusepy",
            "pyyaml",
            "yara-python",
            # dissect.target's caching uses flow.record functionlity which depends on the
            # zstandard module being available. However flow.record does not define
            # zstandard as a dependency, nor does it allow zstandard to be installed
            # through extras.
            #
            # Until such time that this dependency can be installed through
            # flow.record, we define it as a dependency of dissect.target.
            "zstandard",
        ]
    },
    entry_points={
        "console_scripts": [
            "target-build-pluginlist=dissect.target.tools.build_pluginlist:main",
            "target-dump=dissect.target.tools.dump.run:main",
            "target-dd=dissect.target.tools.dd:main",
            "target-fs=dissect.target.tools.fs:main",
            "target-mount=dissect.target.tools.mount:main",
            "target-query=dissect.target.tools.query:main",
            "target-reg=dissect.target.tools.reg:main",
            "target-shell=dissect.target.tools.shell:main",
        ],
    },
    data_files=[("autocompletion", ["autocompletion/target_bash_completion.sh"])],
)
