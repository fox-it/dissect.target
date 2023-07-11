import re

import pytest

from dissect.target.tools.query import main as target_query


def test_target_query_list(capsys, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "--list"])

        with pytest.raises((SystemExit, IndexError, ImportError)):
            target_query()
        out, err = capsys.readouterr()

        assert out.startswith("Available plugins:")
        assert "Failed to load:\n    None\nAvailable loaders:\n" in out


@pytest.mark.parametrize(
    "given_funcs, expected_invalid_funcs",
    [
        (
            ["foo"],
            ["foo"],
        ),
        (
            ["bar", "version"],
            ["bar"],
        ),
        (
            ["version", "foo", "wireguard.config", "bar", "apps.webservers.iis*"],
            ["bar", "foo"],
        ),
        (
            ["browsers.*.downloads", "bar", "version", "foo"],
            ["bar", "foo"],
        ),
        (
            ["apps.webservers.iis.doesnt.exist", "apps.webservers.apache.access"],
            ["apps.webservers.iis.doesnt.exist*"],
        ),
    ],
)
def test_target_query_invalid_functions(capsys, monkeypatch, given_funcs, expected_invalid_funcs):
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["target-query", "-f", ",".join(given_funcs), "tests/data/loaders/tar/test-archive-dot-folder.tgz"],
        )

        with pytest.raises((SystemExit)):
            target_query()
        out, err = capsys.readouterr()

        assert "target-query: error: argument -f/--function contains invalid plugin(s):" in err

        # Workaround for https://github.com/fox-it/dissect.target/issues/266
        RE_ERR = re.compile(r"contains invalid plugin\(s\)\: (?P<funcs>.*?)\n$")
        match = RE_ERR.search(err).groupdict()

        invalid_funcs = [i.strip() for i in match["funcs"].split(",")]
        invalid_funcs.sort()

        assert invalid_funcs == expected_invalid_funcs
