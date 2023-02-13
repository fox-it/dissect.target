from dissect.target.exceptions import PluginError


class RecordDescriptorExtensionBase:
    _default_fields = ()
    _input_fields = ()
    _prepend_fields = False

    def _fill_default_fields(self, record_kwargs):
        raise NotImplementedError()


class UserRecordDescriptorExtension(RecordDescriptorExtensionBase):
    _default_fields = [
        ("string", "username"),
        ("string", "user_id"),
        ("string", "user_group"),
        ("string", "user_home"),
    ]

    _input_fields = ("_user",)

    def _fill_default_fields(self, record_kwargs):
        user = record_kwargs.get("_user", None)

        username = None
        user_id = None
        user_group = None
        user_home = None
        if user:
            username = user.name
            user_id = getattr(user, "sid", None)
            if user_id is None:
                user_id = getattr(user, "uid", None)
            user_group = getattr(user, "gid", None)
            user_home = user.home

        record_kwargs.update(
            {"username": username, "user_id": user_id, "user_group": user_group, "user_home": user_home}
        )
        return record_kwargs


class RegistryRecordDescriptorExtension(RecordDescriptorExtensionBase):
    _default_fields = [
        ("string", "regf_hive_path"),
        ("string", "regf_key_path"),
    ]

    _input_fields = ("_key", "_hive")

    def _fill_default_fields(self, record_kwargs):
        key = record_kwargs.get("_key", None)
        hive = record_kwargs.get("_hive", key.hive if hasattr(key, "hive") else None)
        record_kwargs["regf_key_path"] = key.path if hasattr(key, "path") else None
        record_kwargs["regf_hive_path"] = hive.filepath if hasattr(hive, "filepath") else None
        return record_kwargs


class TargetRecordDescriptorExtension(RecordDescriptorExtensionBase):
    _default_fields = [
        ("string", "hostname"),
        ("string", "domain"),
    ]

    _input_fields = ("_target",)

    _prepend_fields = True

    def _fill_default_fields(self, record_kwargs):
        hostname = None
        domain = None
        source = None

        target = record_kwargs.get("_target", None)
        if target:
            hostname = target.hostname
            try:
                domain = target.domain
            except PluginError:
                pass
            source = target.path

        record_kwargs["hostname"] = hostname
        record_kwargs["domain"] = domain
        # Reserved keywords are never part of the args of a Record's __init__.
        record_kwargs["_source"] = source
        return record_kwargs
