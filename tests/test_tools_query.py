from unittest.mock import patch

from dissect.target.tools.query import get_wildcard_functions


@patch(
    "dissect.target.tools.query.plugins", return_value=[{"module": "a.b.c", "namespace": "q", "exports": ["d", "e"]}]
)
@patch("dissect.target.tools.query.os_plugins", return_value=[{"module": "p.q", "namespace": "p", "exports": ["z"]}])
def test_tools_query(*args):

    implicit, allfuncs = get_wildcard_functions(["a.b.*", "p.*", "f"], ["d"])
    assert implicit == ["q.e", "p.z"]
    assert allfuncs == ["f", "q.e", "p.z"]

    implicit, allfuncs = get_wildcard_functions(["a.b.*", "f"], [])
    assert implicit == ["q.d", "q.e"]
    assert allfuncs == ["f", "q.d", "q.e"]

    implicit, allfuncs = get_wildcard_functions(["a.b.c"], [])
    assert implicit == ["q.d", "q.e"]
    assert allfuncs == ["q.d", "q.e"]

    implicit, allfuncs = get_wildcard_functions(["a"], [])
    assert implicit == []
    assert allfuncs == ["a"]

    implicit, allfuncs = get_wildcard_functions([], [])
    assert implicit == []
    assert allfuncs == []
