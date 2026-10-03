"""Coldline.

===================

File:              tests/unit/adapters/test_model_provider.py
Component:         Unit tests — Test Model Provider
Purpose:           Unit tests for the deterministic model provider.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, failure paths, raw provider answers
Tools:             Python 3.12, pytest
"""

import json
from typing import Any

import pytest

from adapters.model import DeterministicModelProvider
from domain.contracts import ModelRequest

NOTE = "Call Priya Natarajan on +1 555 0142 before the pallet moves."
EXCERPT = (
    "A thermal excursion begins the moment a probe reports a reading outside the accepted "
    "handling range. Notify the duty terminal coordinator immediately."
)


def _request(**overrides: Any) -> ModelRequest:
    """Return the fixed upper-bound excursion request with optional extras."""
    fields: dict[str, Any] = {
        "exception_id": "exc-001",
        "shipment_id": "shipment-syn-001",
        "temperature_c": 9.2,
        "allowed_min_c": 2.0,
        "allowed_max_c": 8.0,
    }
    fields.update(overrides)
    return ModelRequest(**fields)


async def _payload(request: ModelRequest) -> dict[str, Any]:
    """Run the emulator and parse the JSON document it answered with."""
    provider = DeterministicModelProvider(latency_ms=0, provider_key="unit-key")
    answer = await provider.summarize(request)
    assert answer.provider == "deterministic-local"
    loaded = json.loads(answer.text)
    assert isinstance(loaded, dict)
    return loaded


@pytest.mark.asyncio
async def test_provider_returns_raw_json_text_with_a_bounded_summary() -> None:
    """A fixed request must produce a stable raw answer whose summary is unchanged."""
    payload = await _payload(_request())

    assert payload["summary"] == (
        "Synthetic shipment shipment-syn-001 exceeded the upper handling bound "
        "by 1.2 C; operational review is required."
    )
    assert payload["handling_class"] == "thermal_excursion"
    assert payload["next_step"] == "operational_review"
    assert payload["procedure_id"] is None
    assert len(payload["response_id"]) == 16


@pytest.mark.asyncio
async def test_provider_handles_lower_bound_excursion() -> None:
    """A lower excursion must report the correct direction and magnitude."""
    payload = await _payload(
        _request(exception_id="exc-002", shipment_id="shipment-syn-002", temperature_c=1.5)
    )

    assert "fell below the lower handling bound by 0.5 C" in payload["summary"]


@pytest.mark.asyncio
async def test_provider_repeats_the_handling_note_and_the_procedure_in_its_summary() -> None:
    """Text the request carried comes back in the answer, as a summarising model would."""
    payload = await _payload(
        _request(
            handling_note=NOTE,
            procedure_id="playbook-thermal-excursion",
            procedure_excerpt=EXCERPT,
        )
    )

    assert payload["procedure_id"] == "playbook-thermal-excursion"
    assert "Procedure playbook-thermal-excursion: A thermal excursion begins" in payload["summary"]
    assert "Notify the duty terminal coordinator" not in payload["summary"]
    assert payload["summary"].endswith(f"Handling note: {NOTE}")


@pytest.mark.asyncio
async def test_provider_takes_the_key_and_checks_nothing_about_it_yet() -> None:
    """Any key, or none, is accepted at this checkpoint."""
    for key in ("", "coldline-dev-provider-key-v1", "not-a-real-key"):
        provider = DeterministicModelProvider(latency_ms=0, provider_key=key)
        assert provider.provider_key == key
        answer = await provider.summarize(_request())
        assert json.loads(answer.text)["summary"]


@pytest.mark.asyncio
async def test_provider_answers_are_deterministic() -> None:
    """The same request must give byte-identical raw text on every call."""
    provider = DeterministicModelProvider(latency_ms=0)
    request = _request(handling_note=NOTE)

    first = await provider.summarize(request)
    second = await provider.summarize(request)

    assert first == second
