from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.authorization_rules import AuthorizationRulesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "auth.db",
    ],
)
def test_authorization_rules(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/var/db/{test_file}", data_file)

    target_unix.add_plugin(AuthorizationRulesPlugin)

    results = list(target_unix.authorization_rules())

    assert len(results) == 249

    assert results[0].table == "sqlite_sequence"
    assert results[0].name == "rules"
    assert results[0].seq == 205
    assert results[0].source == "/var/db/auth.db"

    assert sorted(results[175].tables) == ["delegates_map", "rules", "rules_history"]
    assert results[175].rules_id == 159
    assert results[175].rules_name == "com.apple.tcc.util.admin"
    assert results[175].rules_type == 1
    assert results[175].rules_class == 2
    assert results[175].rules_group is None
    assert results[175].rules_kofn is None
    assert results[175].rules_timeout is None
    assert results[175].rules_flags == 0
    assert results[175].rules_tries is None
    assert results[175].rules_version == 0
    assert results[175].rules_created == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[175].rules_modified == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[175].rules_hash is None
    assert results[175].rules_identifier is None
    assert results[175].rules_requirement is None
    assert results[175].rules_comment == "For modification of TCC settings."
    assert results[175].rules_history_timestamp == datetime(2026, 3, 25, 14, 7, 1, tzinfo=tz)
    assert results[175].rules_history_source == "authd"
    assert results[175].rules_history_operation == 0
    assert results[175].mechanisms_map_m_id is None
    assert results[175].mechanisms_map_ord is None
    assert results[175].mechanisms_plugin is None
    assert results[175].mechanisms_param is None
    assert results[175].mechanisms_privileged is None
    assert results[175].rules_delegates_map == ["{'d_id': 9, 'ord': 0}"]
    assert results[175].source == "/var/db/auth.db"

    assert sorted(results[177].tables) == ["mechanisms", "mechanisms_map", "rules", "rules_history"]
    assert results[177].rules_id == 161
    assert results[177].rules_name == "system.login.filevault"
    assert results[177].rules_type == 1
    assert results[177].rules_class == 3
    assert results[177].rules_group is None
    assert results[177].rules_kofn is None
    assert results[177].rules_timeout is None
    assert results[177].rules_flags == 1
    assert results[177].rules_tries == "10000"
    assert results[177].rules_version == 0
    assert results[177].rules_created == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[177].rules_modified == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[177].rules_hash is None
    assert results[177].rules_identifier is None
    assert results[177].rules_requirement is None
    assert results[177].rules_comment == "Login mechanism based rule for Filevault."
    assert results[177].rules_history_timestamp == datetime(2026, 3, 25, 14, 7, 1, tzinfo=tz)
    assert results[177].rules_history_source == "authd"
    assert results[177].rules_history_operation == 0
    assert results[177].mechanisms_map_m_id == 24
    assert results[177].mechanisms_map_ord == 0
    assert results[177].mechanisms_plugin == "builtin"
    assert results[177].mechanisms_param == "policy-banner"
    assert results[177].mechanisms_privileged == 0
    assert results[177].rules_delegates_map == []
    assert results[177].source == "/var/db/auth.db"

    assert sorted(results[-9].tables) == ["rules", "rules_history"]
    assert results[-9].rules_id == 199
    assert results[-9].rules_name == "system.preferences.security.remotepair"
    assert results[-9].rules_type == 1
    assert results[-9].rules_class == 1
    assert results[-9].rules_group == "admin"
    assert results[-9].rules_kofn is None
    assert results[-9].rules_timeout == 30
    assert results[-9].rules_flags == 73
    assert results[-9].rules_tries == "10000"
    assert results[-9].rules_version == 1
    assert results[-9].rules_created == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[-9].rules_modified == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[-9].rules_hash is None
    assert results[-9].rules_identifier is None
    assert results[-9].rules_requirement is None
    assert results[-9].rules_comment == "Used by Bezel Services to gate IR remote pairing."
    assert results[-9].rules_delegates_map == []
    assert results[-9].rules_history_timestamp == datetime(2026, 3, 25, 14, 7, 1, tzinfo=tz)
    assert results[-9].rules_history_source == "authd"
    assert results[-9].rules_history_operation == 0
    assert results[-9].mechanisms_map_m_id is None
    assert results[-9].mechanisms_map_ord is None
    assert results[-9].mechanisms_plugin is None
    assert results[-9].mechanisms_param is None
    assert results[-9].mechanisms_privileged is None
    assert results[-9].source == "/var/db/auth.db"

    assert sorted(results[-4].tables) == ["rules", "rules_history"]
    assert results[-4].rules_id == 204
    assert results[-4].rules_name == "com.apple.Safari.allow-apple-events-to-run-javascript"
    assert results[-4].rules_type == 1
    assert results[-4].rules_class == 1
    assert results[-4].rules_group is None
    assert results[-4].rules_kofn is None
    assert results[-4].rules_timeout == 2147483647
    assert results[-4].rules_flags == 12
    assert results[-4].rules_tries == "10000"
    assert results[-4].rules_version == 0
    assert results[-4].rules_created == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[-4].rules_modified == datetime(2026, 3, 25, 14, 7, 1, 144442, tzinfo=tz)
    assert results[-4].rules_hash is None
    assert results[-4].rules_identifier is None
    assert results[-4].rules_requirement is None
    assert (
        results[-4].rules_comment
        == "This right is used by Safari to allow Apple Events to run JavaScript on web pages."
    )
    assert results[-4].rules_delegates_map == []
    assert results[-4].rules_history_timestamp == datetime(2026, 3, 25, 14, 7, 1, tzinfo=tz)
    assert results[-4].rules_history_source == "authd"
    assert results[-4].rules_history_operation == 0
    assert results[-4].mechanisms_map_m_id is None
    assert results[-4].mechanisms_map_ord is None
    assert results[-4].mechanisms_plugin is None
    assert results[-4].mechanisms_param is None
    assert results[-4].mechanisms_privileged is None
    assert results[-4].source == "/var/db/auth.db"

    assert sorted(results[-3].tables) == ["delegates_map", "rules", "rules_history"]
    assert results[-3].rules_id == 205
    assert results[-3].rules_name == "com.apple.wifi"
    assert results[-3].rules_type == 1
    assert results[-3].rules_class == 2
    assert results[-3].rules_group is None
    assert results[-3].rules_kofn == 1
    assert results[-3].rules_timeout is None
    assert results[-3].rules_flags == 0
    assert results[-3].rules_tries is None
    assert results[-3].rules_version == 0
    assert results[-3].rules_created == datetime(2026, 3, 25, 14, 7, 2, 383632, tzinfo=tz)
    assert results[-3].rules_modified == datetime(2026, 3, 25, 14, 7, 2, 383632, tzinfo=tz)
    assert results[-3].rules_hash is None
    assert results[-3].rules_identifier == "com.apple.airport.airportd"
    assert results[-3].rules_requirement is not None
    assert isinstance(results[-3].rules_requirement, (bytes, bytearray))
    assert results[-3].rules_comment == "For restricting WiFi control"
    assert results[-3].rules_delegates_map == [
        "{'d_id': 22, 'ord': 0}",
        "{'d_id': 26, 'ord': 1}",
        "{'d_id': 25, 'ord': 2}",
        "{'d_id': 35, 'ord': 3}",
    ]
    assert results[-3].rules_history_timestamp == datetime(2026, 3, 25, 14, 7, 2, tzinfo=tz)
    assert results[-3].rules_history_source == "/usr/libexec/airportd"
    assert results[-3].rules_history_operation == 0
    assert results[-3].mechanisms_map_m_id is None
    assert results[-3].mechanisms_map_ord is None
    assert results[-3].mechanisms_plugin is None
    assert results[-3].mechanisms_param is None
    assert results[-3].mechanisms_privileged is None
    assert results[-3].source == "/var/db/auth.db"

    assert results[-1].table == "config"
    assert results[-1].key == "data_ts"
    assert results[-1].value == "795677157.0"
    assert results[-1].source == "/var/db/auth.db"
