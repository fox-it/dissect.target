import base64
import functools
import inspect
import os
from itertools import tee
from types import GeneratorType

from flow.record import RecordReader, RecordWriter
from flow.record.base import HAS_ZSTD

Tee = type(tee([], 1)[0])

IGNORE_CACHE = os.getenv("IGNORE_CACHE", "0") == "1"
ONLY_READ_CACHE = os.getenv("ONLY_READ_CACHE", "0") == "1"
REWRITE_CACHE = os.getenv("REWRITE_CACHE", "0") == "1"


class LineWriter:
    def __init__(self, path):
        self.fh = open(path, "w")

    def write(self, line):
        self.fh.write(line + "\n")

    def close(self):
        self.fh.close()


class LineReader:
    def __init__(self, path):
        self.path = path

    def __iter__(self):
        with open(self.path, "r") as fh:
            for line in fh:
                yield line.strip()


class CacheWriter:
    def __init__(self, path, temp, reader, writer):
        self.path = path
        self.temp = temp
        self.reader = reader
        self.writer = writer

    def __iter__(self):
        for obj in self.reader:
            self.writer.write(obj)
            yield obj
        self.close()

    def close(self):
        self.writer.close()
        try:
            os.rename(self.temp, self.path)
        except OSError:
            pass


class Cache:
    def __init__(self, func, no_cache=False, cls=None):
        self.func = func
        self.no_cache = no_cache

        module = inspect.getmodule(cls or func)
        module = f"{module.__name__}." if module else ""
        qualname = f"{cls.__name__}.{func.__name__}" if cls else func.__qualname__

        self.fname = f"{module}{qualname}"
        self.wrapper = None

    def open_reader(self, path, output):
        if output == "record":
            return RecordReader(path)
        elif output == "yield":
            return LineReader(path)

    def open_writer(self, path, output):
        if output == "record":
            return RecordWriter(path)
        elif output == "yield":
            return LineWriter(path)

    def cache_path(self, target, key):
        cache_dir = getattr(target._config, "CACHE_DIR", None) if target._config else None
        if not cache_dir:
            return None

        path_key = base64.b64encode(repr(key).encode()).decode("utf8")
        ext = "zstd" if HAS_ZSTD else "rec"
        fname = f"{self.fname}.{path_key}.{ext}"
        return os.path.join(cache_dir, os.path.basename(target.path), fname)

    def call(self, *args, **kwargs):
        target = args[0].target

        output = getattr(self.wrapper, "__output__", None)
        if output not in ("record", "yield"):
            # Cache property and default outputs on the target object itself
            func_cache = target._cache.setdefault(self.fname, {})
            key = (args[1:], frozenset(sorted(kwargs.items())))

            if key not in func_cache:
                func_cache[key] = self.func(*args, **kwargs)

            if isinstance(func_cache[key], (GeneratorType, Tee)):
                func_cache[key], cache_result = tee(func_cache[key])
                return cache_result

            return func_cache[key]

        key = (args[1:], list(sorted(kwargs.items())))
        cache_file = self.cache_path(target, key)

        # The default policy is READ cache if available else WRITE it (reading
        # takes precedense over writing) and only if the cache directory is
        # configured in the environment. Furthermore, reading is disabled if
        # there is no cache file for the specific function called.
        #
        # Further the IGNORE_CACHE takes precedence over ONLY_READ_CACHE takes
        # precedence over REWRITE_CACHE. So setting an option of a lower
        # precedence to True has no effect if a higher precedence option is
        # already set to True.
        #
        # This set of rules makes sure the 'safest' cache option that is set
        # will be used.
        read_file_cache = True
        write_file_cache = True

        if cache_file:
            if not os.path.exists(cache_file):
                read_file_cache = False
        else:
            read_file_cache = False
            write_file_cache = False

        if IGNORE_CACHE:
            read_file_cache = False
            write_file_cache = False
        elif ONLY_READ_CACHE:
            write_file_cache = False
        elif REWRITE_CACHE:
            read_file_cache = False

        if read_file_cache:
            target.log.debug("Reading from cache file: %s", cache_file)
            if os.access(cache_file, os.R_OK, effective_ids=True):
                if os.stat(cache_file).st_size != 0:
                    try:
                        return self.open_reader(cache_file, output)
                    except Exception as e:
                        target.log.warning("Cache will NOT be used. Error opening cache file: %s", cache_file)
                        target.log.debug("", exc_info=e)
                else:
                    target.log.warning("Cache will NOT be used. File is empty: %s", cache_file)
            else:
                target.log.warning("Cache will NOT be used. No permissions to read cache file: %s", cache_file)
        elif write_file_cache:
            dir_mode = getattr(target._config, "CACHE_DIR_MODE", 0o777) if target._config else 0o777
            file_mode = getattr(target._config, "CACHE_FILE_MODE", 0o666) if target._config else 0o666

            temp_dir = os.path.dirname(cache_file)
            temp_name = f"_{os.path.basename(cache_file)}"
            temp_path = os.path.join(temp_dir, temp_name)

            if not os.path.exists(temp_dir):
                try:
                    os.makedirs(temp_dir, mode=dir_mode)
                except Exception as err:
                    target.log.warning(
                        "Cache will NOT be written. Unable to create cache directory: %s (%s)",
                        temp_dir,
                        err,
                    )

            if os.access(temp_dir, os.W_OK | os.R_OK | os.X_OK, effective_ids=True):
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception as err:
                        target.log.warning(
                            "Cache will NOT be written. Unable to remove pre-existing cache temp file: %s (%s)",
                            temp_path,
                            err,
                        )

                if not os.path.exists(temp_path):
                    try:
                        writer = self.open_writer(temp_path, output)
                        try:
                            # Set permissions
                            os.chmod(temp_path, file_mode)
                        except OSError as err:
                            target.log.debug(
                                "Setting permissions on temp cache file failed, "
                                "continuing with existing permissions: %s (%s)",
                                temp_path,
                                err,
                            )
                        target.log.debug("Caching to file: %s", temp_path)
                        return CacheWriter(cache_file, temp_path, self.func(*args, **kwargs), writer)
                    except Exception as err:
                        target.log.exception(
                            "Cache will NOT be written. Failed to cache to file: %s (%s)",
                            cache_file,
                            err,
                        )
                        try:
                            os.remove(temp_path)
                        except Exception as err:
                            target.log.warning("Unable to remove cache temp file: %s (%s)", temp_path, err)
            else:
                target.log.warning(
                    "Cache will NOT be written. No permissions to write cache file in directory: %s",
                    temp_dir,
                )

        return self.func(*args, **kwargs)


def wrap(func, no_cache=False, cls=None):
    cache = Cache(func, no_cache=no_cache, cls=cls)

    @functools.wraps(func)
    def cache_wrapper(*args, **kwargs):
        if cache.no_cache:
            return cache.func(*args, **kwargs)
        return cache.call(*args, **kwargs)

    cache.wrapper = cache_wrapper
    return cache_wrapper
