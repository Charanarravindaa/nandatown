# SPDX-License-Identifier: Apache-2.0
"""Tests for layer interface definitions — verify they are importable and runtime-checkable."""

from typing import runtime_checkable

from nest_core.layers import (
    Auth,
    CommsProtocol,
    Coordination,
    DataFacts,
    Identity,
    Memory,
    Negotiation,
    Payments,
    Policy,
    Privacy,
    Registry,
    Transport,
    Trust,
)


def test_all_13_layers_importable() -> None:
    """All 13 layer protocols can be imported from nest_core.layers."""
    layers = [
        Auth,
        CommsProtocol,
        Coordination,
        DataFacts,
        Identity,
        Memory,
        Negotiation,
        Payments,
        Policy,
        Privacy,
        Registry,
        Transport,
        Trust,
    ]
    assert len(layers) == 13


def test_layers_are_runtime_checkable() -> None:
    """All layer protocols are decorated with @runtime_checkable."""
    for protocol in [
        Auth,
        CommsProtocol,
        Coordination,
        DataFacts,
        Identity,
        Memory,
        Negotiation,
        Payments,
        Policy,
        Privacy,
        Registry,
        Transport,
        Trust,
    ]:
        assert runtime_checkable(protocol) is protocol
