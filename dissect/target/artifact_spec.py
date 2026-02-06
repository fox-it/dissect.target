from collections.abc import Iterator
from pathlib import Path

from dissect.target import Target
from dissect.target.plugins.general.users import UserRecord


class Artifact:
    """
    An artifact is a specific location of a forensic artifact, including related metadata
    """

    def __init__(self, path: Path, user: UserRecord = None):
        self.path = path
        self.user = user


class Spec:
    """
    A spec is a definition of artifact locations
    """

    def __init__(self, glob_list: tuple, from_user_home: bool = False):
        self.glob_list = glob_list
        self._from_user_home = from_user_home

    def get_artifacts(self, target: Target) -> Iterator[Artifact]:
        for glob in self.glob_list:
            if self._from_user_home:
                for user_details in target.user_details.all_with_home():
                    user_glob = user_details.home_path.joinpath(glob).as_posix()
                    for path in target.fs.path().glob(user_glob):
                        yield Artifact(path, user=user_details.user)
            else:
                for path in target.fs.path().glob(glob):
                    yield Artifact(path)
