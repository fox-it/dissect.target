from unittest.mock import patch

from dissect.target.tools.query import wildcard


@patch(
    "dissect.target.tools.query.plugins", return_value=[{"module": "a.b.c", "namespace": "q", "exports": ["d", "e"]}]
)
@patch(
    "dissect.target.tools.query._special_plugins", return_value=[{"module": "p.q", "namespace": "p", "exports": ["z"]}]
)
def test_tools_query(*args):

    implicit, allfuncs = wildcard(["a.b.*", "p.*", "f"], ["d"])
    assert implicit == ["q.e", "p.z"]
    assert allfuncs == ["f", "q.e", "p.z"]

    implicit, allfuncs = wildcard(["a.b.*", "f"], [])
    assert implicit == ["q.d", "q.e"]
    assert allfuncs == ["f", "q.d", "q.e"]

    implicit, allfuncs = wildcard(["a.b.c"], [])
    assert implicit == ["q.d", "q.e"]
    assert allfuncs == ["q.d", "q.e"]

    implicit, allfuncs = wildcard(["a"], [])
    assert implicit == []
    assert allfuncs == ["a"]

    implicit, allfuncs = wildcard([], [])
    assert implicit == []
    assert allfuncs == []
