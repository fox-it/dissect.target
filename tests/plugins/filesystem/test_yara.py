import tempfile
from io import BytesIO
from pathlib import Path
from typing import Iterator

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.filesystem.yara import HAS_YARA, YaraPlugin
from tests._utils import absolute_path

if HAS_YARA:
    import yara

rule_file = absolute_path("_data/plugins/filesystem/yara/rule.yar")
another_rule_file = absolute_path("_data/plugins/filesystem/yara/another.yar")
invalid_rule = absolute_path("_data/plugins/filesystem/yara/invalid.yar")
rule_dir = Path(rule_file).parent


@pytest.fixture
def target_yara(target_default: Target) -> Iterator[Target]:
    vfs = VirtualFilesystem()
    vfs.map_file_fh("test_file", BytesIO(b"test string"))
    vfs.map_file_fh("/test/dir/to/test_file", BytesIO(b"test string"))
    vfs.map_file_fh("should_not_hit", BytesIO(b"this is another file."))
    target_default.fs.mount("/", vfs)
    target_default.add_plugin(YaraPlugin)
    yield target_default


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
def test_yara_plugin(target_yara: Target) -> None:
    results = list(target_yara.yara(rules=[Path(rule_file)]))

    assert len(results) == 2
    assert results[0].path == "/test_file"
    assert results[1].path == "/test/dir/to/test_file"
    assert results[0].rule == "test_rule_name"


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
@pytest.mark.parametrize(
    "rules,expected_hits",
    [
        (["/does/not/exist"], 0),
        ([rule_file, rule_file], 2),
        ([rule_file, another_rule_file], 4),
        ([rule_dir], 4),
        ([invalid_rule], 0),
    ],
)
def test_yara_plugin_invalid_rules(target_yara: Target, rules: list[str | Path], expected_hits: int) -> None:
    results = list(target_yara.yara(rules=rules, check_rules=True))
    assert len(results) == expected_hits


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
def test_yara_plugin_invalid_rule_warn(target_yara: Target, caplog: pytest.CaptureFixture) -> None:
    results = list(target_yara.yara(rules=[invalid_rule, another_rule_file], check_rules=True))
    assert "invalid.yar contains invalid rule(s)!" in caplog.text
    assert len(results) == 2


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
def test_yara_plugin_compiled_rule(target_yara: Target, tmp_path: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", dir=tmp_path) as tmp_file:
        rules = yara.compile(rule_file)
        rules.save(tmp_file.name)

        results = list(target_yara.yara(rules=[tmp_file.name]))
        assert len(results) == 2
