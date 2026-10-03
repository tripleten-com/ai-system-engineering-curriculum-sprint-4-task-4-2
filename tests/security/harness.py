"""Coldline.

===================

File:              tests/security/harness.py
Component:         Security tooling — In-process access harness
Purpose:           Build the API from src/ in this process, with a memory store and the real
                    verifier.
Interacts With:    src/api/routes.py, src/api/security, config/auth.yaml,
                    tests/fixtures/tokens/fixtures.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Deterministic access tests, in-process HTTP, mutation-checkable routes
Tools:             Python 3.12, httpx, FastAPI

The student's access tests run against this harness rather than the running container,
for one reason: `poe verify` reruns them against mutated copies of ``src/api/routes.py``
and ``src/api/security/access.py``, and only an application built in-process from ``src/``
can be pointed at such a copy. The route code, the access rule, and the token verifier are
the real ones; the exception store, queue, retriever, and document repository are memory
doubles, so a test needs PostgreSQL for nothing. The verifier is configured from
``config/auth.yaml`` and fetches the key set from the ``jwks_url`` it names, so the issuer
container must be up.

When the assessed checks run the student file they set ``COLDLINE_ACCESS_TRACE``, and every
request made through ``bearer_client`` is then recorded against the pytest case that made
it: the fixture, the path, and whether the requested exception is one this harness holds
with a stored summary (``tests/security/trace.py``). That record, not the test's source,
is how the checks tell the allowed test from the seven rejection tests.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI

from api.document_service import DocumentService
from api.retrieval_workflow import RetrievalWorkflow
from api.routes import create_app
from api.security.tokens import TokenVerifier
from api.use_cases import ReadingApplication
from domain.contracts import (
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    JobDelivery,
    SensorReading,
)
from tests.doubles import StubRetriever, candidate
from tests.security import trace
from tests.security.fixtures import FIXTURES_PATH, token

TASK_ROOT = Path(__file__).resolve().parents[2]
AUTH_CONFIG_PATH = TASK_ROOT / "config/auth.yaml"
NOW = datetime(2026, 9, 1, tzinfo=UTC)


class MemoryRepository:
    """Hold exception records in a dictionary, with the repository contract's shape."""

    def __init__(self) -> None:
        """Start empty."""
        self.records: dict[str, ExceptionRecord] = {}

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return one stored record, or None."""
        return self.records.get(exception_id)

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Create a record or return the existing one."""
        return self.records.setdefault(record.exception_id, record)

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
    ) -> ExceptionRecord:
        """Apply one state transition to the stored record."""
        current = self.records[exception_id]
        if current.state not in expected:
            raise RuntimeError(f"{exception_id} is {current.state}, not in {expected}")
        updated = current.model_copy(
            update={
                "state": target,
                "summary": summary if summary is not None else current.summary,
                "failure_reason": failure_reason,
                "updated_at": NOW,
            }
        )
        self.records[exception_id] = updated
        return updated


class MemoryQueue:
    """Count publications instead of sending them anywhere; the rest of the port is inert."""

    def __init__(self) -> None:
        """Start at zero."""
        self.count = 0

    async def publish(self, job: ExceptionJob) -> str:
        """Record one publication and return a synthetic message id."""
        self.count += 1
        return f"memory-{self.count}"

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Deliver nothing: no worker consumes from this harness."""
        return None

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Recover nothing: nothing was delivered."""
        return None

    async def acknowledge(self, message_id: str) -> None:
        """Accept any acknowledgement."""

    async def queue_depth(self) -> int:
        """Report the publications that were never consumed."""
        return self.count

    async def pending_count(self) -> int:
        """Report no in-flight delivery."""
        return 0


async def _no_objects(prefix: str) -> list[str]:
    """Stand in for the object store: the access tests list nothing."""
    return []


def build_app(
    repository: MemoryRepository,
    queue: MemoryQueue,
    *,
    token_verifier: TokenVerifier,
    clock: Callable[[], datetime] = lambda: NOW,
) -> FastAPI:
    """Compose the HTTP application from src/ around memory doubles and the given verifier."""
    application = ReadingApplication(repository, queue, clock=clock)
    retrieval = RetrievalWorkflow(
        StubRetriever((candidate("sop-harness#0000", 1),)),
        top_k=3,
        dense_weight=0.5,
        token_budget=64,
    )
    return create_app(
        application,
        repository,
        retrieval,
        _no_objects,
        DocumentService(lambda: None),
        token_verifier=token_verifier,
    )


class AccessHarness:
    """One in-process API, its memory store, and the token fixtures, for one test."""

    def __init__(
        self,
        root: Path = TASK_ROOT,
        *,
        token_verifier: TokenVerifier | None = None,
        trace_path: Path | None = None,
    ) -> None:
        """Build the application; the verifier defaults to the one config/auth.yaml configures.

        ``trace_path`` defaults to the file ``COLDLINE_ACCESS_TRACE`` names, or to no
        recording at all when the variable is unset.
        """
        self.root = root
        self.repository = MemoryRepository()
        self.queue = MemoryQueue()
        self.verifier = (
            TokenVerifier.from_config(root / "config/auth.yaml")
            if token_verifier is None
            else token_verifier
        )
        self.app = build_app(self.repository, self.queue, token_verifier=self.verifier)
        self._fixtures = root / FIXTURES_PATH.relative_to(TASK_ROOT)
        self._trace = trace.trace_path() if trace_path is None else trace_path

    def token(self, name: str) -> str:
        """Return one fixture's compact token by its name."""
        return token(name, path=self._fixtures)

    def bearer_client(self, name: str | None = None) -> httpx.AsyncClient:
        """Return an async client against the in-process API, sending one fixture as a bearer token.

        ``None`` sends no Authorization header at all. Every request the client sends is
        recorded when a trace file is configured: the fixture, the method and path, and
        whether the path names an exception this harness holds with a stored summary.
        """
        headers = {} if name is None else {"Authorization": f"Bearer {self.token(name)}"}

        async def record_request(request: httpx.Request) -> None:
            """Record one request against the pytest case now running."""
            exception_id = trace.exception_id_of(request.url.path)
            stored = self.repository.records.get(exception_id) if exception_id else None
            trace.record(
                self._trace,
                {
                    "fixture": name,
                    "method": request.method,
                    "path": request.url.path,
                    "exception_id": exception_id,
                    "stored_summary": bool(stored is not None and stored.summary),
                },
            )

        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://coldline.test",
            headers=headers,
            event_hooks={"request": [record_request]},
        )

    def stored_exception(self, summary: str | None = None) -> tuple[str, str]:
        """Create one COMPLETED exception with a stored summary; return its id and that summary.

        Each call makes a fresh record with a unique id and a unique summary text, so a
        test can assert the exact summary it stored and depends on no earlier run.
        """
        suffix = uuid4().hex
        text = (
            summary
            if summary is not None
            else (
                f"Shipment shipment-{suffix[:8]} recorded 9.2 C against an allowed 2.0 to 8.0 C; "
                f"hold the pallet at the Dover relay. Summary {suffix}."
            )
        )
        reading = SensorReading(
            reading_id=f"reading-{suffix}",
            shipment_id=f"shipment-{suffix}",
            temperature_c=9.2,
            allowed_min_c=2.0,
            allowed_max_c=8.0,
            recorded_at=NOW,
            handling_note="Re-ice at the Dover relay before the pallet moves.",
        )
        exception_id = f"exc-{suffix}"
        self.repository.records[exception_id] = ExceptionRecord(
            exception_id=exception_id,
            reading=reading,
            state=ExceptionState.COMPLETED,
            accepted_at=NOW,
            updated_at=NOW,
            summary=text,
        )
        return exception_id, text
