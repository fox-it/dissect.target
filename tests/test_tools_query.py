import pytest

from dissect.target.tools.query import main as target_query


def test_target_query_list(capsys, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "--list"])

        with pytest.raises((SystemExit, IndexError, ImportError)):
            target_query()
        out, err = capsys.readouterr()

        assert out.startswith("Available plugins:")
        assert out.endswith("Failed to load:\n    None\n")


@pytest.mark.parametrize(
    "given_funcs, invalid_funcs",
    [
        (
            "foo",
            "foo",
        ),
        (
            "bar,version",
            "bar",
        ),
        (
            "version,foo,wireguard.config,bar,apps.webservers.iis*",
            "foo, bar",
        ),
        (
            "browsers.*.downloads,bar,version,foo",
            "bar, foo",
        ),
    ],
)
def test_target_query_invalid_functions(capsys, monkeypatch, given_funcs, invalid_funcs):
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-query", "-f", given_funcs, "tests/data/loaders/tar/test-archive-dot-folder.tgz"])

        with pytest.raises((SystemExit)):
            target_query()
        out, err = capsys.readouterr()

        assert err.endswith(
            f"target-query: error: argument -f/--function contains invalid plugin(s): {invalid_funcs}\n"
        )
