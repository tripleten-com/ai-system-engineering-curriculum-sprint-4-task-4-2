"""Coldline.

===================

File:              src/worker/use_cases.py
Component:         Worker — Use Cases
Purpose:           Coordinate one provider-neutral exception-processing attempt.
Interacts With:    LocalStack SQS, domain, ports, and adapters
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Background processing, retries, idempotency, failure classification, retrieval
Tools:             Python 3.12

The Project 4 opening checkpoint adds the exception-resolution request this
Project secures. For each job the worker logs the reading it took, retrieves
the matching procedure through the Retriever port, sends the reading, the
handling note and the procedure excerpt to the model provider, parses the
provider's raw answer, and stores the summary it finds there.
"""

import json
import logging
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from domain.contracts import (
    ExceptionJob,
    ExceptionState,
    ModelAnswer,
    ModelRequest,
    ModelSummary,
    SensorReading,
)
from domain.errors import TerminalProviderError
from domain.failures import RetrievalUnavailable
from domain.repositories import ExceptionRepository
from ports import ModelProvider
from worker.procedures import ProcedureExcerpt

LOGGER = logging.getLogger(__name__)


class ProcessingDisposition(StrEnum):
    """Tell the transport loop whether to acknowledge or retry a delivery."""

    ACK = "ACK"
    ACK_EXISTING = "ACK_EXISTING"
    ACK_MISSING = "ACK_MISSING"
    RETRY = "RETRY"


class ProcedureSource(Protocol):
    """Find the procedure excerpt for one reading."""

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Return the excerpt, or an empty one when nothing matched."""
        ...


def parse_summary(answer: ModelAnswer) -> ModelSummary:
    """Read the summary out of the provider's raw answer with a plain parse.

    The emulator answers with a JSON document; the summary is its ``summary``
    field. Nothing here checks the document's shape beyond finding that one
    string: an answer that is not JSON, or has no summary string, is stored
    as the text the provider returned.
    """
    try:
        payload = json.loads(answer.text)
    except json.JSONDecodeError:
        payload = None
    summary = payload.get("summary") if isinstance(payload, dict) else None
    return ModelSummary(
        summary=summary if isinstance(summary, str) else answer.text,
        provider=answer.provider,
    )


class WorkerApplication:
    """Apply bounded model processing to one durable exception job."""

    def __init__(
        self,
        repository: ExceptionRepository,
        provider: ModelProvider,
        procedures: ProcedureSource,
        *,
        clock: Callable[[], datetime],
        maximum_attempts: int = 3,
    ) -> None:
        """Receive collaborators and a positive delivery-attempt limit."""
        if maximum_attempts < 1:
            raise ValueError("maximum_attempts must be positive")
        self._repository = repository
        self._provider = provider
        self._procedures = procedures
        self._clock = clock
        self._maximum_attempts = maximum_attempts

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> ProcessingDisposition:
        """Process one delivery and tell the queue whether it can be acknowledged.

        Completed or failed identities are safe replays and need no new model
        call. In-flight work is retried until the third delivery. A successful
        provider result is persisted before ``ACK`` is returned. A provider
        failure the provider itself classified as terminal fails immediately,
        on the first delivery, without spending a redelivery on an outcome
        that cannot change. Any other provider failure, and a retrieval
        backend that cannot answer, returns ``RETRY`` unless the delivery
        limit is exhausted. A missing record returns a distinct
        acknowledgement so the runtime can expose the broken
        persistence-before-publish invariant.
        """
        LOGGER.info(
            "reading job exception_id=%s shipment_id=%s handling_note=%s",
            job.exception_id,
            job.reading.shipment_id,
            job.reading.handling_note,
        )
        record = await self._repository.get(job.exception_id)
        if record is None:
            return ProcessingDisposition.ACK_MISSING
        if record.state in {ExceptionState.COMPLETED, ExceptionState.FAILED}:
            return ProcessingDisposition.ACK_EXISTING
        if record.state is ExceptionState.PROCESSING:
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="processing_attempts_exhausted",
                )
                return ProcessingDisposition.ACK
            return ProcessingDisposition.RETRY

        # PROCESSING is durable before the provider call starts. Recovery can
        # therefore distinguish work that never started from interrupted work.
        await self._repository.transition(
            job.exception_id,
            {ExceptionState.QUEUED},
            ExceptionState.PROCESSING,
        )

        try:
            procedure = await self._procedures.find(job.reading)
        except RetrievalUnavailable:
            # The corpus store did not answer. That is this attempt failing,
            # not the provider, so it spends one processing attempt and is
            # otherwise retried like any interrupted attempt.
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="processing_attempts_exhausted",
                )
                return ProcessingDisposition.ACK
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.QUEUED,
            )
            return ProcessingDisposition.RETRY

        try:
            answer = await self._provider.summarize(
                ModelRequest(
                    exception_id=job.exception_id,
                    shipment_id=job.reading.shipment_id,
                    temperature_c=job.reading.temperature_c,
                    allowed_min_c=job.reading.allowed_min_c,
                    allowed_max_c=job.reading.allowed_max_c,
                    handling_note=job.reading.handling_note,
                    procedure_id=procedure.document_id,
                    procedure_excerpt=procedure.text,
                )
            )
        except TerminalProviderError:
            # The provider already decided a retry cannot succeed. Recording
            # the failure now, instead of after wasted redeliveries, is the
            # whole point of classifying it at the provider boundary.
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.FAILED,
                failure_reason="model_provider_terminal_failure",
            )
            return ProcessingDisposition.ACK
        except Exception:
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="model_provider_exhausted",
                )
                return ProcessingDisposition.ACK
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.QUEUED,
            )
            return ProcessingDisposition.RETRY

        summary = parse_summary(answer)
        # Terminal persistence happens before the transport loop acknowledges.
        await self._repository.transition(
            job.exception_id,
            {ExceptionState.PROCESSING},
            ExceptionState.COMPLETED,
            summary=summary.summary,
        )
        return ProcessingDisposition.ACK
