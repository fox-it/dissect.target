import os


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def mkdirs(root, paths):
    for path in paths:
        root.joinpath(path).mkdir(parents=True)
