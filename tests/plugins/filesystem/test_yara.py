from __future__ import annotations

import tempfile
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.filesystem.yara import HAS_YARA, YaraPlugin, is_valid_yara
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

if HAS_YARA:
    import yara

rule_file = absolute_path("_data/plugins/filesystem/yara/rule.yar")
another_rule_file = absolute_path("_data/plugins/filesystem/yara/another.yar")
invalid_rule = absolute_path("_data/plugins/filesystem/yara/invalid.yar")
rule_dir = rule_file.parent


@pytest.fixture
def target_yara(target_default: Target) -> Target:
    vfs = VirtualFilesystem()
    vfs.map_file_fh("test_file", BytesIO(b"test string"))
    vfs.map_file_fh("/test/dir/to/test_file", BytesIO(b"test string"))
    vfs.map_file_fh("should_not_hit", BytesIO(b"this is another file."))
    target_default.fs.mount("/", vfs)
    target_default.add_plugin(YaraPlugin)
    return target_default


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
def test_yara_plugin(target_yara: Target) -> None:
    results = list(target_yara.yara(rules=[rule_file]))

    assert len(results) == 2
    assert results[0].path == "/test_file"
    assert results[1].path == "/test/dir/to/test_file"
    assert results[0].rule == "test_rule_name"


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
@pytest.mark.parametrize(
    ("rules", "expected_hits", "should_be_valid"),
    [
        (["/does/not/exist"], 0, False),
        ([rule_file, rule_file], 2, True),
        ([rule_file, another_rule_file], 4, True),
        ([rule_dir], 4, False),  # contains invalid.yar
        ([invalid_rule], 0, False),
    ],
)
def test_yara_plugin_invalid_rules(
    target_yara: Target, rules: list[str | Path], expected_hits: int, should_be_valid: bool
) -> None:
    assert is_valid_yara(files={str(file): file for file in rules}) == should_be_valid

    results = list(target_yara.yara(rules=rules, check=True))
    assert len(results) == expected_hits


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
def test_yara_plugin_invalid_rule_warn(target_yara: Target, caplog: pytest.CaptureFixture) -> None:
    results = list(target_yara.yara(rules=[invalid_rule, another_rule_file], check=True))
    assert "invalid.yar contains invalid rule(s)!" in caplog.text
    assert len(results) == 2


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
def test_yara_plugin_compiled_rule(target_yara: Target, tmp_path: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", dir=tmp_path, delete=False) as tf:
        rules = yara.compile(str(rule_file))
        rules.save(tf.name)
        tf.close()

        results = list(target_yara.yara(rules=[tf.name]))

        assert len(results) == 2

        assert results[0].path == "/test_file"
        assert results[0].rule == "test_rule_name"
        assert results[0].tags == ["tag1", "tag2", "tag3"]
        assert results[0].namespace == "default"
        assert results[0].digest.md5 == "6f8db599de986fab7a21625b7916589c"
        assert results[0].digest.sha1 == "661295c9cbf9d6b2f6428414504a8deed3020641"
        assert results[0].digest.sha256 == "d5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b"
