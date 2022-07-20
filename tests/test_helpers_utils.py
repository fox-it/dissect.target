from dissect.target.helpers.utils import slugify


def test_slugify():
    assert slugify("foo/bar\\baz bla") == "foo_bar_baz_bla"
