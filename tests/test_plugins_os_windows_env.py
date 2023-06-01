import platform
from collections import OrderedDict, namedtuple
from unittest import mock

import pytest

from dissect.target.plugins.os.windows.env import (
    EnvironmentVariablePlugin,
    EnvVarDetails,
)

PATHEXTS = [".ext_1", ".ext_2"]

MockUser = namedtuple("user", ["name", "home", "sid"])(
    "test-user",
    "test-user-home",
    "test-user-sid",
)


class MockEnvironmentVariablePlugin(EnvironmentVariablePlugin):
    VARIABLES = [
        EnvVarDetails(
            "%foo%",
            (
                "foo1",
                "foo2",
            ),
            "FOO",
        ),
        EnvVarDetails(
            "%path%",
            (
                "path1;;;",
                "path2;;;",
            ),
            "PATH",
        ),
    ]

    USER_VARIABLES = [
        EnvVarDetails(
            "%path%",
            (
                "{user_sid}/path1;;;",
                "{user_sid}/path2;;;",
            ),
            "PATH",
        ),
    ]


TEST_USER_ENV_VARS = (
    (
        None,
        (
            ("%foo%", "foo2"),
            ("%path%", "path1;path2;;;"),
        ),
    ),
    (
        MockUser,
        (
            ("%foo%", "foo2"),
            ("%path%", f"{MockUser.sid}/path1;test-user-sid/path2;;;"),
        ),
    ),
)


@pytest.fixture
def env_plugin():
    mock_target = mock.Mock()

    def registry_value_side_effect(key, value):
        Value = namedtuple("Value", "value")
        return Value(key)

    mock_registry_value = mock.Mock(side_effect=registry_value_side_effect)
    mock_target.registry.value = mock_registry_value

    mock_users = mock.Mock(side_effect=lambda: [MockUser])
    mock_target.users = mock_users

    mock_target.path = "mock"
    mock_target._config.CACHE_DIR = "cache"

    plugin = MockEnvironmentVariablePlugin(mock_target)
    plugin._pathext = set(PATHEXTS)

    return plugin


def test__expand_env():
    test_value = "%foo%%bAr%/%FoO%foo%bar%bar"
    test_env_vars = OrderedDict([("%FOO%", "bar"), ("%bar%", "foo")])
    expanded_value = EnvironmentVariablePlugin._expand_env(test_value, test_env_vars)
    assert expanded_value == "barfoo/barfoofoobar"


def test__expand_env_vars():
    test_env_vars = OrderedDict(
        [
            ("%first%", "first"),
            ("%second%", "%first%"),
            ("%third%", "%fourth%"),
            ("%fourth%", "%second%"),
        ]
    )

    result_env_vars = OrderedDict(
        [
            ("%first%", "first"),
            ("%second%", "first"),
            ("%third%", "%fourth%"),
            ("%fourth%", "first"),
        ]
    )

    assert result_env_vars == EnvironmentVariablePlugin._expand_env_vars(test_env_vars)


def test__get_env_vars(env_plugin):
    env_vars = env_plugin._get_env_vars(env_plugin.VARIABLES)

    assert env_vars["%foo%"] == "foo2"
    assert env_vars["%path%"] == "path1;path2;;;"


def test__get_system_env_vars(env_plugin):
    with mock.patch.object(env_plugin, "_get_env_vars"):
        with mock.patch.object(env_plugin, "_expand_env_vars"):
            env_plugin._get_system_env_vars()
            env_plugin._get_env_vars.assert_called_with(env_plugin.VARIABLES)
            env_plugin._expand_env_vars.assert_called_with(env_plugin._get_env_vars.return_value)


@pytest.mark.parametrize("user, results", TEST_USER_ENV_VARS)
def test__get_user_env_vars(env_plugin, user, results):
    user_sid = None
    if user:
        user_sid = user.sid
    env_vars = env_plugin._get_user_env_vars(user_sid)

    for variable, value in results:
        assert env_vars[variable] == value


@pytest.mark.parametrize("user, _", TEST_USER_ENV_VARS)
def test_expand_env(env_plugin, user, _):
    path = "mock"

    with mock.patch.object(env_plugin, "_get_user_env_vars"):
        with mock.patch.object(env_plugin, "_expand_env"):
            user_sid = None
            if user:
                user_sid = user.sid
            expanded_path = env_plugin.expand_env(path, user_sid)
            env_plugin._get_user_env_vars.assert_called_with(user_sid)
            env_plugin._expand_env.assert_called_with(path, env_plugin._get_user_env_vars.return_value)
            assert expanded_path == env_plugin._expand_env.return_value


@pytest.mark.parametrize("user, _", TEST_USER_ENV_VARS)
def test_user_env(env_plugin, user, _):
    with mock.patch.object(env_plugin, "_get_user_env_vars"):
        user_sid = None
        if user:
            user_sid = user.sid
        env_vars = env_plugin.user_env(user_sid)
        env_plugin._get_user_env_vars.assert_called_with(user_sid)
        assert env_vars == env_plugin._get_user_env_vars.return_value


def test_env(env_plugin):
    with mock.patch.object(env_plugin, "_get_system_env_vars"):
        env_vars = env_plugin.env
        env_plugin._get_system_env_vars.assert_called()
        assert env_vars == env_plugin._get_system_env_vars.return_value


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="NotImplementedError: access: effective_ids unavailable on this platform. Needs to be fixed.",
)
def test_environment_variables(env_plugin):
    with mock.patch.object(env_plugin, "_get_system_env_vars", side_effect=lambda: {"sys-name": "sys-value"}):
        with mock.patch.object(env_plugin, "_get_user_env_vars", side_effect=lambda _: {"usr-name": "usr-value"}):
            records = list(env_plugin.environment_variables())
            # unwind the generator, so all functions are called
            [_ for _ in records]
            env_plugin._get_system_env_vars.assert_called()
            env_plugin._get_user_env_vars.assert_called_once_with(MockUser.sid)
            assert records[0].name == "sys-name"
            assert records[0].value == "sys-value"
            assert records[0].username is None
            assert records[1].name == "usr-name"
            assert records[1].value == "usr-value"
            assert records[1].username == "test-user"


def test__get_pathext(env_plugin):
    pathexts = env_plugin.pathext
    pathexts = sorted(tuple(pathexts))
    assert pathexts == PATHEXTS


def test_pathext(env_plugin):
    with mock.patch.object(env_plugin, "_get_pathext"):
        env_plugin.pathext()
        env_plugin._get_pathext.assert_called_once()


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="NotImplementedError: access: effective_ids unavailable on this platform. Needs to be fixed.",
)
def test_path_extensions(env_plugin):
    pathext_records = env_plugin.path_extensions()
    pathext_records = sorted(pathext_records, key=lambda record: record.pathext)
    for idx, record in enumerate(pathext_records):
        assert record.pathext == PATHEXTS[idx]
