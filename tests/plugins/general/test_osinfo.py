from __future__ import annotations

import json
from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from flow.record.base import Record

    from dissect.target.target import Target


@dataclass
class OSInfoFixture:
    """Small helper around one target for osinfo tests."""

    target: Target

    def add_export(self, name: str, func: Callable[[], object]) -> None:
        self.target._os.__exports__ = [*self.target._os.__exports__, name]
        setattr(self.target._os, name, func)

    def record(self) -> Record:
        records = list(self.target.osinfo())
        assert len(records) == 1
        return records[0]

    def values(self) -> dict:
        return json.loads(self.record().values)


@pytest.fixture
def osinfo_fixture(target_default: Target) -> OSInfoFixture:
    return OSInfoFixture(target=target_default)


def test_osinfo_returns_single_record_per_host(osinfo_fixture: OSInfoFixture) -> None:
    assert len(list(osinfo_fixture.target.osinfo())) == 1


def test_osinfo_contains_expected_defaults(osinfo_fixture: OSInfoFixture) -> None:
    values = osinfo_fixture.values()

    assert values["os"] == "default"
    assert values["ips"] == []
    assert values["version"] is None
    assert values["architecture"] is None


def test_osinfo_materializes_generator_exports(osinfo_fixture: OSInfoFixture) -> None:
    assert osinfo_fixture.values()["users"] == []


def test_osinfo_skips_exports_that_raise(osinfo_fixture: OSInfoFixture) -> None:
    def explode() -> str:
        raise RuntimeError("boom")

    osinfo_fixture.add_export("explode", explode)
    values = osinfo_fixture.values()

    assert "explode" not in values


def test_osinfo_skips_generator_exports_that_fail(osinfo_fixture: OSInfoFixture) -> None:
    def broken_generator() -> Generator[str, None, None]:
        yield "first"
        raise RuntimeError("broken generator")

    osinfo_fixture.add_export("broken_generator", broken_generator)
    values = osinfo_fixture.values()

    assert "broken_generator" not in values


def test_osinfo_includes_property_exports(osinfo_fixture: OSInfoFixture) -> None:
    values = osinfo_fixture.values()
    record = osinfo_fixture.record()

    assert values["os"] == "default"
    assert "hostname" in values
    assert "hostname" in record.__slots__
