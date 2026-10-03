"""Coldline.

===================

File:              src/adapters/model/deterministic.py
Component:         Adapter — Deterministic
Purpose:           Implement the deterministic local model-provider adapter.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Boundary translation, deterministic infrastructure, raw provider answers
Tools:             Python 3.12, OpenTelemetry
"""

import asyncio
import hashlib
import json

from opentelemetry import trace

from domain.contracts import ModelAnswer, ModelRequest

_TRACER = trace.get_tracer(__name__)
# How much of the retrieved procedure the emulator repeats in its summary.
_PROCEDURE_SENTENCE_CHARACTERS = 160


class DeterministicModelProvider:
    """Return repeatable answers without network or paid-model calls.

    The emulator imitates a hosted provider's wire shape: it takes a provider
    key at construction, the way a client would carry an API key, and answers
    with one JSON document as raw text. At this checkpoint it checks nothing
    about the key; a later Task makes it accept only the current version.

    The answer repeats what the request carried. A handling note on the
    request appears in the summary verbatim, and so does the first sentence of
    the procedure excerpt, which is what a summarising model would do with the
    text it was given.
    """

    def __init__(self, *, latency_ms: int = 250, provider_key: str = "") -> None:
        """Configure a fixed non-negative provider delay in milliseconds and the key."""
        if latency_ms < 0:
            raise ValueError("latency_ms must not be negative")
        self._latency_seconds = latency_ms / 1000
        self._provider_key = provider_key

    @property
    def provider_key(self) -> str:
        """Return the key the worker handed this client at composition time."""
        return self._provider_key

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return one raw JSON answer for a synthetic temperature excursion."""
        with _TRACER.start_as_current_span(
            "model_provider.summarize",
            attributes={"coldline.exception_id": request.exception_id},
        ):
            if self._latency_seconds:
                await asyncio.sleep(self._latency_seconds)

            if request.temperature_c > request.allowed_max_c:
                magnitude = request.temperature_c - request.allowed_max_c
                condition = f"exceeded the upper handling bound by {magnitude:.1f} C"
            else:
                magnitude = request.allowed_min_c - request.temperature_c
                condition = f"fell below the lower handling bound by {magnitude:.1f} C"

            sentences = [
                f"Synthetic shipment {request.shipment_id} {condition}; "
                "operational review is required."
            ]
            if request.procedure_id is not None and request.procedure_excerpt:
                sentences.append(
                    f"Procedure {request.procedure_id}: "
                    f"{_first_sentence(request.procedure_excerpt)}"
                )
            if request.handling_note:
                sentences.append(f"Handling note: {request.handling_note}")

            payload = {
                "summary": " ".join(sentences),
                "handling_class": "thermal_excursion",
                "next_step": "operational_review",
                "procedure_id": request.procedure_id,
                "response_id": _response_id(request),
            }
            return ModelAnswer(
                provider="deterministic-local",
                text=json.dumps(payload, sort_keys=True),
            )


def _first_sentence(text: str) -> str:
    """Return the excerpt's first sentence, bounded, so the summary stays short."""
    sentence = text.split(". ", maxsplit=1)[0].strip()
    if not sentence.endswith("."):
        sentence = f"{sentence}."
    return sentence[:_PROCEDURE_SENTENCE_CHARACTERS]


def _response_id(request: ModelRequest) -> str:
    """Imitate a provider's per-answer response id from the request identity.

    A stable, short identifier that a log line can quote; it protects nothing
    and is never compared against anything.
    """
    digest = hashlib.sha1(f"{request.exception_id}:{request.shipment_id}".encode())
    return digest.hexdigest()[:16]
