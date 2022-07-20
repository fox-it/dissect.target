import itertools

import pytest

from dissect.target.exceptions import PluginError
from dissect.target.helpers.descriptor_extensions import (
    TargetRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import (
    create_extended_descriptor,
    TargetRecordDescriptor,
    UnixUserRecord,
    WindowsUserRecord,
)

RECORD_NAME = "test/record"
RECORD_FIELDS = [
    ("string", "foo"),
    ("string", "bar"),
]

BasicTestRecord = TargetRecordDescriptor(RECORD_NAME)
TestRecord = TargetRecordDescriptor(RECORD_NAME, RECORD_FIELDS)
OrderedTestRecord = create_extended_descriptor([UserRecordDescriptorExtension])(RECORD_NAME, RECORD_FIELDS)


class MockTarget:
    hostname = "some-host"
    domain = "some.domain"
    path = "/some/path"


class MockNoDomainTarget(MockTarget):
    @property
    def domain(self):
        raise PluginError("No plugin domain")


def test_trd_init():
    default_field_names = [field_name for _, field_name in TargetRecordDescriptor._default_fields]
    record_field_names = list(BasicTestRecord.fields.keys())

    assert default_field_names == record_field_names

    descriptor_field_names = [
        field_name
        for _, field_name in itertools.chain(
            TargetRecordDescriptor._default_fields,
            RECORD_FIELDS,
        )
    ]
    record_field_names = list(TestRecord.fields.keys())

    assert descriptor_field_names == record_field_names


def test_trd_init_with_defaults_fail():
    for field_type, field_name in TargetRecordDescriptor._default_fields:
        with pytest.raises(TypeError, match=f"Default field '{field_name}'"):
            TargetRecordDescriptor(
                RECORD_NAME,
                [(field_type, field_name)],
            )


def test_trd_call_with_kwargs():
    record = TestRecord(
        foo="foo",
        bar="bar",
        _target=MockTarget(),
    )

    assert record.foo == "foo"
    assert record.bar == "bar"
    assert record.hostname == "some-host"
    assert record.domain == "some.domain"
    assert record._source == "/some/path"


def test_trd_call_with_args():
    with pytest.raises(ValueError):
        TestRecord(
            "foo",
            "bar",
            _target=MockTarget(),
        )


def test_trd_call_with_args_kwargs():
    with pytest.raises(ValueError):
        TestRecord(
            "foo",
            bar="bar",
            _target=MockTarget(),
        )


def test_trd_call_with_default_fields():
    record = TestRecord(
        hostname="hostname-ignored",
        domain="domain-ignored",
        foo="foo",
        bar="bar",
        _target=MockTarget(),
    )

    assert record.foo == "foo"
    assert record.bar == "bar"
    assert record.hostname == "some-host"
    assert record.domain == "some.domain"
    assert record._source == "/some/path"


def test_trd_call_no_target():
    record = TestRecord(
        foo="foo",
        bar="bar",
    )

    assert record.foo == "foo"
    assert record.bar == "bar"
    assert record.hostname is None
    assert record.domain is None
    assert record._source is None


def test_trd_call_no_domain_target():
    record = TestRecord(
        foo="foo",
        bar="bar",
        _target=MockNoDomainTarget(),
    )

    assert record.foo == "foo"
    assert record.bar == "bar"
    assert record.hostname == "some-host"
    assert record.domain is None
    assert record._source == "/some/path"


def test_ordered_record():
    expected_ordered_fields = tuple(
        TargetRecordDescriptorExtension._default_fields + RECORD_FIELDS + UserRecordDescriptorExtension._default_fields
    )

    actual_fields = OrderedTestRecord.get_field_tuples()

    assert actual_fields == expected_ordered_fields


@pytest.fixture
def mock_windows_user():
    return WindowsUserRecord(
        sid="some-sid",
        name="some-name",
        home="some-home",
        _target=MockTarget(),
    )


@pytest.fixture
def mock_unix_user():
    return UnixUserRecord(
        uid=1337,
        name="some-name",
        home="some-home",
        _target=MockTarget(),
    )


def test_user_record_descriptor_extension(mock_windows_user, mock_unix_user):
    TestRecord = create_extended_descriptor([UserRecordDescriptorExtension])("test/record", [])

    test_record = TestRecord(_user=mock_windows_user)
    assert test_record.username == "some-name"
    assert test_record.user_id == "some-sid"
    assert test_record.user_home == "some-home"

    test_record = TestRecord(_user=mock_unix_user)
    assert test_record.username == "some-name"
    assert test_record.user_id == "1337"
    assert test_record.user_home == "some-home"
