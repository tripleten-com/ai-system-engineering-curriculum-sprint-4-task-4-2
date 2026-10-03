"""Coldline.

===================

File:              tests/security/trace.py
Component:         Security tooling — Executed-request trace
Purpose:           Record which fixture each student test actually sent, and which exception it
                    requested, for the assessed checks to read.
Interacts With:    tests/security/harness.py (writes), tests/security/mutation.py (reads), pytest
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Evidence from executed requests, not from source text
Tools:             Python 3.12, json

When the assessed checks run the student's ``tests/student/test_exception_access.py``, they
set ``COLDLINE_ACCESS_TRACE`` to a file and the harness appends one JSON line per request a
test makes through ``harness.bearer_client(...)``: the pytest case that made it (from
``PYTEST_CURRENT_TEST``), the fixture the client carried, the path, and whether the
requested exception is one the harness holds with a stored summary. The checks then know,
per collected test, what the test really did, which is how the allowed test and the seven
rejection tests are told apart. Outside such a run the variable is unset and nothing is
written.

A case is identified by its full pytest node id: the student file, the class chain if the
test is a method, and the function name with its parameter id
(``tests/student/test_exception_access.py::TestWeak::test_expired[a]``). The trace builds
it from ``PYTEST_CURRENT_TEST`` and the junit reader rebuilds the same id from a test
case's ``classname`` and ``name``, so two tests that share a method name in different
classes stay two cases, as do two parameters of one function.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

TRACE_VARIABLE = "COLDLINE_ACCESS_TRACE"
CURRENT_TEST_VARIABLE = "PYTEST_CURRENT_TEST"
SUMMARY_ROUTE = "/api/v1/exceptions/"
# The one file the checks run; every case id starts with it.
STUDENT_TEST = "tests/student/test_exception_access.py"
_STUDENT_MODULE_STEM = STUDENT_TEST.rsplit("/", 1)[-1].removesuffix(".py")


def trace_path() -> Path | None:
    """Return the trace file the environment names, or None when no run is recording."""
    value = os.environ.get(TRACE_VARIABLE)
    return Path(value) if value else None


def case_id(node_id: str) -> str:
    """Return the full case identity for one pytest node id, or "" for no node id.

    The file component is replaced by the student file's fixed path, so the id does not
    depend on the directory pytest took as its root; the class chain, the name, and the
    parameter id are kept exactly.
    """
    if "::" not in node_id:
        return ""
    return f"{STUDENT_TEST}::{node_id.split('::', 1)[1]}"


def junit_case_id(classname: str, name: str) -> str:
    """Return the same identity from a junit ``testcase``'s ``classname`` and ``name``.

    pytest writes ``classname`` as the module's dotted path followed by the class chain
    (``tests.student.test_exception_access.TestWeak``) and ``name`` as the function with its
    parameter id. The components after the module's are the class chain. A ``classname``
    that does not name the student module is kept whole, so it matches no traced case and
    is reported rather than mistaken for one.
    """
    parts = classname.split(".") if classname else []
    if _STUDENT_MODULE_STEM in parts:
        chain = parts[parts.index(_STUDENT_MODULE_STEM) + 1 :]
        return "::".join([STUDENT_TEST, *chain, name])
    return f"{classname}::{name}" if classname else name


def current_case() -> str:
    """Return the full case identity of the collected test now running.

    pytest sets ``PYTEST_CURRENT_TEST`` to ``<node id> (<phase>)`` for the duration of each
    test; the phase is dropped and the node id is normalised by ``case_id``.
    """
    value = os.environ.get(CURRENT_TEST_VARIABLE, "")
    return case_id(value.rsplit(" (", 1)[0])


def exception_id_of(path: str) -> str | None:
    """Return the exception id a summary-route path names, or None for any other path."""
    if not path.startswith(SUMMARY_ROUTE):
        return None
    remainder = path[len(SUMMARY_ROUTE) :]
    exception_id = remainder.split("/", 1)[0]
    return exception_id or None


def record(path: Path | None, event: Mapping[str, object]) -> None:
    """Append one event to the trace file, tagged with the current test; no file, no write."""
    if path is None:
        return
    line = json.dumps({"case": current_case(), **event}, sort_keys=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_events(path: Path) -> list[dict[str, object]]:
    """Return every recorded event, in order; a missing file is an empty trace."""
    if not path.is_file():
        return []
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            events.append(loaded)
    return events
