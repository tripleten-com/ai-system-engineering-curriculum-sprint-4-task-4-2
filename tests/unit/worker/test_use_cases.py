"""Coldline.

===================

File:              tests/unit/worker/test_use_cases.py
Component:         Unit tests — Test Use Cases
Purpose:           Unit tests for exception-worker application behavior.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, failure paths, state invariants, retrieval-augmented requests
Tools:             Python 3.12, pytest
"""

import json
import logging
from datetime import UTC, datetime

import pytest

from domain.contracts import (
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    ModelAnswer,
    ModelRequest,
    SensorReading,
)
from domain.errors import TerminalProviderError
from domain.failures import RetrievalUnavailable
from worker.procedures import ProcedureExcerpt
from worker.use_cases import ProcessingDisposition, WorkerApplication, parse_summary


class MemoryRepository:
    """Store one exception record for worker tests."""

    def __init__(self, record: ExceptionRecord) -> None:
        """Initialize the repository with one durable record."""
        self.record = record

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return the record when identities match."""
        return self.record if exception_id == self.record.exception_id else None

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Reject unexpected creation in worker tests."""
        raise AssertionError("worker must not create exception records")

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
    ) -> ExceptionRecord:
        """Apply one state transition."""
        assert self.record.state in expected
        self.record = self.record.model_copy(
            update={
                "state": target,
                "summary": summary if summary is not None else self.record.summary,
                "failure_reason": failure_reason,
                "updated_at": NOW,
            }
        )
        return self.record


class RecordingProvider:
    """Return a fixed raw answer or raise a fixed error, recording each request."""

    def __init__(self, *, fail: bool = False, text: str | None = None) -> None:
        """Configure a recording or failing provider with an optional raw answer."""
        self.fail = fail
        self.calls = 0
        self.requests: list[ModelRequest] = []
        self.text = text if text is not None else DEFAULT_ANSWER

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Record one provider call."""
        self.calls += 1
        self.requests.append(request)
        if self.fail:
            raise TimeoutError("provider timeout")
        return ModelAnswer(provider="deterministic-local", text=self.text)


class TerminalRecordingProvider:
    """Raise a pre-classified terminal failure, as a bounded resilience wrapper would."""

    def __init__(self) -> None:
        """Track how many times the worker called the provider."""
        self.calls = 0

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Record one call and raise a terminal, non-retryable failure."""
        self.calls += 1
        raise TerminalProviderError("request rejected as permanently invalid")


class StaticProcedures:
    """Return one fixed excerpt, or fail the way an unreachable corpus store does."""

    def __init__(self, *, fail: bool = False) -> None:
        """Configure a fixed or failing lookup."""
        self.fail = fail
        self.readings: list[SensorReading] = []

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Record the reading and answer with the fixed excerpt."""
        self.readings.append(reading)
        if self.fail:
            raise RetrievalUnavailable("retrieval backend is unreachable")
        return EXCERPT


NOW = datetime(2026, 8, 28, tzinfo=UTC)
NOTE = "Call Priya Natarajan on +1 555 0142 before the pallet moves."
DEFAULT_ANSWER = json.dumps({"summary": "bounded synthetic summary"})
READING = SensorReading(
    reading_id="reading-syn-001",
    shipment_id="shipment-syn-001",
    temperature_c=9.2,
    allowed_min_c=2.0,
    allowed_max_c=8.0,
    recorded_at=NOW,
    handling_note=NOTE,
)
JOB = ExceptionJob(exception_id="exc-001", reading=READING, accepted_at=NOW)
EXCERPT = ProcedureExcerpt(
    document_id="playbook-thermal-excursion",
    chunk_id="playbook-thermal-excursion#0000",
    text="A thermal excursion begins the moment a probe reports a reading outside the range.",
    window_minutes=None,
)


def queued_record() -> ExceptionRecord:
    """Return the durable starting record for a worker test."""
    return ExceptionRecord(
        exception_id=JOB.exception_id,
        reading=READING,
        state=ExceptionState.QUEUED,
        accepted_at=NOW,
        updated_at=NOW,
    )


def _application(
    repository: MemoryRepository,
    provider: object,
    procedures: object | None = None,
) -> WorkerApplication:
    """Compose the worker application around one repository and provider."""
    return WorkerApplication(
        repository,
        provider,  # type: ignore[arg-type] - focused boundary fake
        procedures if procedures is not None else StaticProcedures(),  # type: ignore[arg-type]
        clock=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_successful_job_reaches_completed_terminal_state() -> None:
    """A provider success must be persisted before acknowledgement."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider())

    disposition = await application.process(JOB, delivery_count=1)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.COMPLETED
    assert repository.record.summary == "bounded synthetic summary"


@pytest.mark.asyncio
async def test_model_request_carries_the_reading_the_note_and_the_procedure() -> None:
    """The exception-resolution request is the reading, the raw note, and the excerpt."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    procedures = StaticProcedures()
    application = _application(repository, provider, procedures)

    await application.process(JOB, delivery_count=1)

    assert procedures.readings == [READING]
    request = provider.requests[0]
    assert request.exception_id == JOB.exception_id
    assert request.shipment_id == READING.shipment_id
    assert request.temperature_c == READING.temperature_c
    assert request.handling_note == NOTE
    assert request.procedure_id == EXCERPT.document_id
    assert request.procedure_excerpt == EXCERPT.text


@pytest.mark.asyncio
async def test_worker_logs_the_handling_note_as_it_reads_the_job(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One log line names the job and carries the note exactly as the reading holds it."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider())

    with caplog.at_level(logging.INFO, logger="worker.use_cases"):
        await application.process(JOB, delivery_count=1)

    messages = [record.getMessage() for record in caplog.records]
    lines = [message for message in messages if message.startswith("reading job")]
    assert len(lines) == 1
    assert f"exception_id={JOB.exception_id}" in lines[0]
    assert f"handling_note={NOTE}" in lines[0]


@pytest.mark.asyncio
async def test_summary_is_the_summary_field_of_the_raw_json_answer() -> None:
    """The worker reads one field out of the provider's JSON and stores it."""
    repository = MemoryRepository(queued_record())
    text = json.dumps({"summary": "parsed from json", "next_step": "operational_review"})
    application = _application(repository, RecordingProvider(text=text))

    await application.process(JOB, delivery_count=1)

    assert repository.record.summary == "parsed from json"


@pytest.mark.parametrize(
    "text",
    ["not json at all", json.dumps({"verdict": "no summary field"}), json.dumps({"summary": 7})],
    ids=["not-json", "no-summary", "summary-not-a-string"],
)
@pytest.mark.asyncio
async def test_an_answer_without_a_summary_string_is_stored_as_returned(text: str) -> None:
    """Nothing validates the answer yet: whatever the provider returned becomes the summary."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider(text=text))

    disposition = await application.process(JOB, delivery_count=1)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.COMPLETED
    assert repository.record.summary == text


def test_parse_summary_keeps_the_provider_name() -> None:
    """The parsed summary names the provider the raw answer came from."""
    parsed = parse_summary(ModelAnswer(provider="deterministic-local", text='{"summary": "s"}'))

    assert parsed.summary == "s"
    assert parsed.provider == "deterministic-local"


@pytest.mark.asyncio
async def test_completed_duplicate_is_acknowledged_without_provider_call() -> None:
    """A duplicate delivery must not repeat a completed provider effect."""
    record = queued_record().model_copy(
        update={"state": ExceptionState.COMPLETED, "summary": "already complete"}
    )
    repository = MemoryRepository(record)
    provider = RecordingProvider()
    procedures = StaticProcedures()
    application = _application(repository, provider, procedures)

    disposition = await application.process(JOB, delivery_count=2)

    assert disposition is ProcessingDisposition.ACK_EXISTING
    assert provider.calls == 0
    assert procedures.readings == []


@pytest.mark.asyncio
async def test_delivery_without_a_durable_record_is_named_explicitly() -> None:
    """A broken persistence-before-publish invariant must not look like a safe replay."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    application = _application(repository, provider)
    missing_job = JOB.model_copy(update={"exception_id": "exc-missing"})

    disposition = await application.process(missing_job, delivery_count=1)

    assert disposition is ProcessingDisposition.ACK_MISSING
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_inflight_duplicate_waits_without_repeating_provider_work() -> None:
    """A second delivery must not run the provider while the first is processing."""
    repository = MemoryRepository(
        queued_record().model_copy(update={"state": ExceptionState.PROCESSING})
    )
    provider = RecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=2)

    assert disposition is ProcessingDisposition.RETRY
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_third_inflight_delivery_records_terminal_failure() -> None:
    """A crash-stranded processing record must not remain pending forever."""
    repository = MemoryRepository(
        queued_record().model_copy(update={"state": ExceptionState.PROCESSING})
    )
    provider = RecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "processing_attempts_exhausted"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_provider_failure_retries_before_terminal_attempt() -> None:
    """A non-final provider failure must leave the message pending for retry."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider(fail=True))

    disposition = await application.process(JOB, delivery_count=2)

    assert disposition is ProcessingDisposition.RETRY
    assert repository.record.state is ExceptionState.QUEUED


@pytest.mark.asyncio
async def test_third_provider_failure_is_recorded_and_acknowledged() -> None:
    """The third failure must become an observable terminal outcome."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider(fail=True))

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "model_provider_exhausted"


@pytest.mark.asyncio
async def test_unreachable_corpus_store_retries_without_calling_the_provider() -> None:
    """A retrieval failure spends the attempt and leaves the job for redelivery."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    application = _application(repository, provider, StaticProcedures(fail=True))

    disposition = await application.process(JOB, delivery_count=1)

    assert disposition is ProcessingDisposition.RETRY
    assert repository.record.state is ExceptionState.QUEUED
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_unreachable_corpus_store_at_the_final_delivery_exhausts_the_attempts() -> None:
    """At the last delivery a retrieval failure is the attempts running out, nothing else."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    application = _application(repository, provider, StaticProcedures(fail=True))

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "processing_attempts_exhausted"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_terminal_provider_failure_is_recorded_on_the_first_delivery() -> None:
    """A terminal failure must not wait for the retryable-exhaustion budget."""
    repository = MemoryRepository(queued_record())
    provider = TerminalRecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=1)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "model_provider_terminal_failure"
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_terminal_provider_failure_at_the_final_delivery_is_still_distinct() -> None:
    """Even at the last delivery, a terminal outcome keeps its own failure reason.

    A retryable failure exhausted at the final delivery also reaches FAILED/ACK,
    so disposition and state alone cannot tell the two outcomes apart there. The
    failure reason is the only observable that must still distinguish them.
    """
    repository = MemoryRepository(queued_record())
    provider = TerminalRecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "model_provider_terminal_failure"
    assert repository.record.failure_reason != "model_provider_exhausted"
