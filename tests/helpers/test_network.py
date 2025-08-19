from __future__ import annotations

import pytest

from dissect.target.helpers.network import IANAProtocol


@pytest.mark.parametrize(
    ("input_number", "expected_output"),
    [
        (0, "HOPOPT"),
        (6, "TCP"),
        (17, "UDP"),
        (27, "RDP"),
        (148, "UNASSIGNED_148"),
        (169, "UNASSIGNED_169"),
        (252, "UNASSIGNED_252"),
        (253, "USE_FOR_EXPERIMENTATION_AND_TESTING_253"),
        (255, "RESERVED_255"),
        (1337, "UNKNOWN_1337"),
    ],
)
def test_helpers_network_iana_protocol_translation(input_number: int, expected_output: str) -> None:
    """Test if we translate IANA protocol numbers correctly."""

    assert IANAProtocol(input_number).name == expected_output
    assert IANAProtocol(input_number).value == input_number
