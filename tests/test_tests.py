from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

try:
    subprocess.run(["git", "lfs", "--version"], check=True)
    HAS_GIT_LFS = True
except Exception:
    HAS_GIT_LFS = False


@pytest.mark.skipif(not HAS_GIT_LFS, reason="git lfs command not available")
def test_lfs_tracking(request: pytest.FixtureRequest) -> None:
    """Test if all files that should be checked into git lfs are actually tracked."""
    output = subprocess.run(["git", "lfs", "ls-files", "--name-only"], capture_output=True, text=True)
    tracked_lfs_files = set(output.stdout.splitlines())

    output = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
    tracked_git_files = set(output.stdout.splitlines())

    with (request.config.rootdir / ".gitattributes").open("rt") as fh:
        lfs_patterns = [line.split()[0] for line in fh.readlines() if "filter=lfs" in line]

    untracked_files = []
    for pattern in lfs_patterns:
        if pattern.endswith("/**"):
            pattern += "/*"

        for path in Path(request.config.rootdir).rglob(pattern):
            relative_path = str(path.relative_to(request.config.rootdir))
            if (
                path.stat().st_size != 0
                and relative_path in tracked_git_files
                and relative_path not in tracked_lfs_files
            ):
                untracked_files.append(relative_path)

    assert not untracked_files, f"Untracked LFS files: {', '.join(untracked_files)}"
