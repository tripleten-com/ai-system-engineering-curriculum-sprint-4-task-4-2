"""Coldline.

===================

File:              tests/security/live_record.py
Component:         Security tooling — Stored exception through the running stack
Purpose:           Create one exception with a stored summary for the assessed live rows,
                    and confirm it reached COMPLETED through a trusted path that no
                    student setting can refuse.
Interacts With:    The running API, worker, and PostgreSQL (Docker Compose),
                    tests/e2e/baseline-exception.json, tests/contract/test_exception_access.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Assessment preconditions, trusted evidence, authorization-independent wait
Tools:             Python 3.12, httpx, Docker Compose, psql

The live assessed rows request one exception once per fixture and judge the status and
the body, so they need an exception that **has** a stored summary before the first request
is made. Waiting for it through the API's own status URL would read the very route the
Task protects: with a wrong ``config/auth.yaml`` the dispatcher's read is refused, the wait
would learn nothing, and the rows would run against a record whose state is unknown. The
wait here is independent of the API's authorization: it submits the reading through the
intake (which is open) and then polls the ``exceptions`` table inside the ``postgres``
container (``docker compose exec -T postgres psql``, the pattern the smoke checks use) until
the record is ``COMPLETED`` with a non-empty summary. ``FAILED``, a timeout, or a poll
that cannot run raises ``StoredRecordError``, which the assessed fixture lets propagate, so
the live rows ERROR rather than judge an unprepared record.

``poe auth-checks`` (``tests/security/auth_checks.py``) keeps its own API-side wait on
purpose: its table shows the student the refusal for every fixture, including the
dispatcher's, which is the diagnosis that tool exists for.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

if TYPE_CHECKING:
    import httpx

TASK_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = TASK_ROOT / "tests/e2e/baseline-exception.json"
STORED_SUMMARY_WAIT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.5
POLL_TIMEOUT_SECONDS = 30
COMPLETED = "COMPLETED"
FAILED = "FAILED"
COMPOSE: tuple[str, ...] = (
    "docker",
    "compose",
    "--profile",
    "observability",
    "--profile",
    "localstack",
)
# The API mints `exc-<hex>` identities; anything else never reaches the query.
_IDENTITY = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")


class StoredRecordError(RuntimeError):
    """Report that no exception with a stored summary could be established."""


def unique_reading() -> dict[str, Any]:
    """Return the supplied out-of-range reading with a fresh identity."""
    fixture = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    reading = cast(dict[str, Any], fixture["reading"])
    suffix = uuid4().hex
    reading["reading_id"] = f"reading-auth-{suffix}"
    reading["shipment_id"] = f"shipment-auth-{suffix}"
    reading["recorded_at"] = datetime.now(UTC).isoformat()
    return reading


def submit_reading(client: httpx.Client) -> str:
    """Submit one fresh reading through the open intake and return its exception id."""
    accepted = client.post("/api/v1/readings", json=unique_reading())
    accepted.raise_for_status()
    body = accepted.json()
    exception_id = body.get("exception_id") if isinstance(body, dict) else None
    if not isinstance(exception_id, str) or not _IDENTITY.match(exception_id):
        raise StoredRecordError(f"the intake returned no usable exception id: {body!r}")
    return exception_id


def _query(exception_id: str) -> str:
    """Return the SQL that reads one record's state and summary length."""
    if not _IDENTITY.match(exception_id):
        raise StoredRecordError(f"refusing to query an unexpected exception id {exception_id!r}")
    return (
        "SELECT state, coalesce(length(summary), 0) FROM exceptions "
        f"WHERE exception_id = '{exception_id}';"
    )


def stored_state(exception_id: str, root: Path = TASK_ROOT) -> tuple[str, int] | None:
    """Return ``(state, summary length)`` for one record from the database, or None if absent.

    The query runs inside the ``postgres`` container through Compose, as the smoke checks
    do, so it needs no published database port and no API authorization.
    """
    try:
        result = subprocess.run(
            [
                *COMPOSE,
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "coldline",
                "-d",
                "coldline",
                "-tAc",
                _query(exception_id),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=POLL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoredRecordError(f"the database poll could not run: {exc}") from exc
    if result.returncode != 0:
        raise StoredRecordError(
            f"the database poll failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    line = result.stdout.strip().splitlines()
    if not line:
        return None
    state, _, length = line[-1].partition("|")
    try:
        return state.strip(), int(length.strip() or "0")
    except ValueError as exc:
        raise StoredRecordError(f"unreadable database row {line[-1]!r}") from exc


def wait_for_stored_summary(
    exception_id: str,
    *,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> None:
    """Block until the record is COMPLETED with a non-empty summary, or raise saying why not."""
    deadline = time.monotonic() + wait_seconds
    last: tuple[str, int] | None = None
    while True:
        last = stored_state(exception_id, root)
        if last is not None:
            state, length = last
            if state == COMPLETED and length > 0:
                return
            if state == FAILED:
                raise StoredRecordError(
                    f"exception {exception_id} reached FAILED, so it has no stored summary; "
                    "run `poe reset` and `poe start`, then retry"
                )
        if time.monotonic() >= deadline:
            seen = (
                "not yet visible" if last is None else f"state {last[0]}, summary length {last[1]}"
            )
            raise StoredRecordError(
                f"exception {exception_id} did not reach COMPLETED with a stored summary within "
                f"{wait_seconds:g} s ({seen}); is the worker running?"
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def create_stored_exception(
    client: httpx.Client,
    *,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> str:
    """Submit one reading and return its exception id once the summary is stored, or raise."""
    exception_id = submit_reading(client)
    wait_for_stored_summary(exception_id, wait_seconds=wait_seconds, root=root)
    return exception_id
