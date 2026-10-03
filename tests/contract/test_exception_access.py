"""Coldline.

===================

File:              tests/contract/test_exception_access.py
Component:         Contract tests — Exception summary access
Purpose:           One assessed check per public Check-list row, over config/auth.yaml, the running
                    API, and the student's tests/student/test_exception_access.py.
Interacts With:    config/auth.yaml, docs/security/access-policy.md, the issuer, the running API,
                    tests/student/test_exception_access.py, tests/security/*
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Pinned verification settings, 401 versus 403, least privilege, mutation testing
Tools:             Python 3.12, pytest, httpx

Assessed: a fresh starter has a blank ``config/auth.yaml``, an open summary route, and no
student tests, so most checks here fail until the three files are complete. ``poe contract``
deselects them; ``poe access-contract`` and ``poe verify`` run them. The checks marked
``runtime`` need the stack (``poe start``): the live rows request the API's summary endpoint
for an exception they create with a stored summary (confirmed through the database, not
through the route under test), and the student-file rows run the student tests, which
verify tokens against the issuer's key set, as written and under the mutations. The rest
are static, including the route guard and the principal-parameter row, which parse
``src/api/routes.py`` without importing it, and the student-guard row, which parses the
student file without importing it and must pass before any row executes that file;
``poe verify`` also runs both guards on their own, right after recording its integrity
snapshot and before any process imports either module.

The ``no token`` row is not a Check-list row and not a fixture: it is the one request every
protected endpoint must refuse, so ``poe verify`` asserts it alongside the eight fixtures.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

import httpx
import pytest

from api.security.tokens import AuthConfigError, AuthSettings, load_auth_settings
from tests.contract.submission_validation import SubmissionError, validate_submission
from tests.runtime_config import host_port
from tests.security import auth_config, live_record, mutation, policy, route_guard, student_guard
from tests.security.fixtures import INVALID, UNAUTHORIZED, bearer_headers
from tests.security.harness import TASK_ROOT

pytestmark = pytest.mark.assessed
AUTH_CONFIG_PATH = TASK_ROOT / "config/auth.yaml"
ROUTE = "/api/v1/exceptions/{exception_id}"


def _settings() -> AuthSettings:
    """Return config/auth.yaml's values, or fail the row with the file's defect."""
    try:
        return load_auth_settings(AUTH_CONFIG_PATH)
    except AuthConfigError as exc:
        pytest.fail(str(exc))


def _detail(response: httpx.Response) -> str:
    """Return the refusal's reason, or the status line, for an assertion message."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return str(body)[:200]


# --- Step 1: config/auth.yaml against the policy and the discovery document ---------------


def test_auth_config_pins_exactly_one_algorithm() -> None:
    """`config/auth.yaml` names one algorithm: a list holding only the one the key set declares."""
    findings = auth_config.algorithm_findings(_settings())
    assert findings == [], "; ".join(findings)


def test_auth_config_leeway_is_inside_the_policy_range() -> None:
    """`leeway_seconds` is a whole number inside the range the access policy allows."""
    low, high = policy.leeway_range()
    findings = auth_config.leeway_findings(_settings(), low, high)
    assert findings == [], "; ".join(findings)


def test_auth_config_audience_is_the_access_policy_audience() -> None:
    """`audience` is the API audience in docs/security/access-policy.md, not the issuer's URL."""
    findings = auth_config.audience_findings(_settings(), policy.audience())
    assert findings == [], "; ".join(findings)


@pytest.mark.runtime
def test_auth_config_matches_the_live_discovery_document() -> None:
    """`issuer` and `jwks_url` equal the live discovery document's; the algorithm is declared."""
    try:
        discovery = auth_config.fetch_discovery()
    except RuntimeError as exc:
        pytest.fail(str(exc))
    findings = auth_config.discovery_findings(_settings(), discovery)
    assert findings == [], "; ".join(findings)


# --- Step 2: the route module, and the protected endpoint, one request per fixture ---------


def test_routes_module_changed_only_the_access_rule_on_get_exception() -> None:
    """`src/api/routes.py` differs from the supplied file only by the rule on `get_exception`.

    A static comparison of syntax trees against the shipped starter, never an import: the
    file is read as bytes with its source encoding validated (UTF-8 only), and the
    permitted differences are the rule's imports, one `Depends(require_access(...))` on
    `get_exception`, and docstrings. Every other route, the route's body, and every
    module-level statement must be the starter's. `poe route-guard` is the same check,
    run inside `poe verify` before any step imports the module.
    """
    try:
        found = route_guard.findings()
    except route_guard.RouteGuardError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)


def test_get_exception_receives_the_principal_through_the_rule_parameter() -> None:
    """`get_exception` takes the verified `Principal` as the parameter that applies the rule.

    The completion the Task asks for (T23: the route takes the principal as a parameter):
    `principal: Annotated[Principal, Depends(require_access(...))]` or
    `principal: Principal = Depends(require_access(...))`, applied once. The untouched
    starter fails this row, as does `dependencies=[Depends(require_access(...))]` on the
    decorator, which protects the route but hands it no principal. Static, over the same
    bytes the route guard parses; never an import.
    """
    try:
        found = route_guard.completion()
    except route_guard.RouteGuardError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)


@pytest.fixture(scope="module")
def api() -> Iterator[httpx.Client]:
    """Return a client for the running API on the host."""
    port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{port}", timeout=10.0) as client:
        yield client


@pytest.fixture(scope="module")
def stored_exception(api: httpx.Client) -> str:
    """Create one exception and wait, through the database, until its summary is stored.

    The wait is independent of the API's authorization (`tests/security/live_record.py`
    polls the `exceptions` table inside the `postgres` container), so a wrong setting
    cannot leave the record's state unknown. `FAILED` or a timeout raises here, which
    pytest reports as an ERROR on every live row, never as a row's own failure.
    """
    try:
        return live_record.create_stored_exception(api)
    except live_record.StoredRecordError as exc:
        raise RuntimeError(f"the live rows' precondition was not met: {exc}") from exc


@pytest.mark.runtime
def test_dispatcher_valid_receives_200_with_the_stored_summary(
    api: httpx.Client, stored_exception: str
) -> None:
    """`dispatcher-valid` receives `200` from the protected endpoint, with the stored summary."""
    response = api.get(
        ROUTE.format(exception_id=stored_exception), headers=bearer_headers("dispatcher-valid")
    )
    assert response.status_code == 200, _detail(response)
    body = cast(dict[str, Any], response.json())
    assert body["exception_id"] == stored_exception
    assert body["state"] == "COMPLETED", f"the worker had not stored a summary: {body['state']}"
    assert isinstance(body.get("summary"), str) and body["summary"]


@pytest.mark.runtime
@pytest.mark.parametrize("fixture", INVALID)
def test_invalid_token_fixtures_receive_401(
    api: httpx.Client, stored_exception: str, fixture: str
) -> None:
    """`bad-signature`, `wrong-issuer`, `wrong-audience`, and `expired` each receive `401`."""
    response = api.get(ROUTE.format(exception_id=stored_exception), headers=bearer_headers(fixture))
    assert response.status_code == 401, f"{fixture}: {response.status_code} {_detail(response)}"
    assert "exception_id" not in response.text, f"{fixture}: the record was returned"


@pytest.mark.runtime
@pytest.mark.parametrize("fixture", UNAUTHORIZED)
def test_unauthorized_fixtures_receive_403(
    api: httpx.Client, stored_exception: str, fixture: str
) -> None:
    """`gateway-valid`, `wrong-role`, and `missing-scope` each receive `403`."""
    response = api.get(ROUTE.format(exception_id=stored_exception), headers=bearer_headers(fixture))
    assert response.status_code == 403, f"{fixture}: {response.status_code} {_detail(response)}"
    assert "exception_id" not in response.text, f"{fixture}: the record was returned"


@pytest.mark.runtime
def test_a_request_without_a_token_receives_401(api: httpx.Client, stored_exception: str) -> None:
    """A request with no `Authorization` header receives `401` from the protected endpoint."""
    response = api.get(ROUTE.format(exception_id=stored_exception))
    assert response.status_code == 401, f"{response.status_code} {_detail(response)}"
    assert "exception_id" not in response.text, "the record was returned without a token"


@pytest.mark.runtime
def test_no_other_endpoint_changed_its_access_behavior(api: httpx.Client) -> None:
    """The readings intake, the document reads, health, and version still answer without a token.

    An in-range reading reaching the intake's own validation (`422`) shows the intake took the
    request rather than refusing the caller; a listing and the two probes answer `200`.
    """
    in_range = {
        "reading_id": "reading-access-check",
        "shipment_id": "shipment-access-check",
        "temperature_c": 5.0,
        "allowed_min_c": 2.0,
        "allowed_max_c": 8.0,
        "recorded_at": "2026-09-01T00:00:00Z",
    }
    intake = api.post("/api/v1/readings", json=in_range)
    assert intake.status_code == 422, f"intake: {intake.status_code} {_detail(intake)}"
    documents = api.get("/api/v1/documents", params={"tenant_id": "tenant-access-check"})
    assert documents.status_code == 200, f"documents: {documents.status_code}"
    for path in ("/health/ready", "/version"):
        probe = api.get(path)
        assert probe.status_code == 200, f"{path}: {probe.status_code}"


# --- Step 3: the student's tests -----------------------------------------------------------


def _verdict(name: str) -> mutation.Verdict:
    """Run one mutation of the route or the rule against the student file, or fail with why not."""
    try:
        return mutation.check(name)
    except mutation.MutationError as exc:
        pytest.fail(str(exc))


def test_student_file_uses_only_the_harness_and_asserts_each_response() -> None:
    """The student file imports only the harness, inspects nothing, and asserts every response.

    Static, over the file's bytes, never an import, and the precondition of every row
    below that executes the file: the only imports are `pytest`, the annotations future,
    `typing` names and `AccessHarness`; no name, anywhere, reads the environment, the
    filesystem, or a module's internals (`__file__`, `sys`, `importlib`, `getattr`,
    `open`, any dunder, ...); `pytest` is used only for fixtures, marks, `param` and
    `raises`; no function takes a pytest built-in fixture such as `monkeypatch` or
    `request` as a parameter; every test asserts the `.status_code` of a response from the
    harness client, and a test that expects 401 or 403 also asserts something about its
    body or `.text`. The mutations then check that those assertions can fail.
    `poe student-guard` is the same check, run inside `poe verify` before anything
    executes the file.
    """
    try:
        found = student_guard.findings()
    except student_guard.StudentGuardError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)


@pytest.mark.runtime
def test_student_file_has_one_allowed_test_and_one_rejection_test_per_refused_fixture() -> None:
    """The student file executes one allowed case and one rejection case per refused fixture.

    The file is run once as written with the harness recording every request each test
    makes. A case is the allowed test when it requested an exception with a stored summary
    as `dispatcher-valid` alone, and the rejection test for a refused fixture when it
    requested such an exception as that fixture alone. Eight executed cases are required;
    what a test names in its source counts for nothing.
    """
    try:
        inventory = mutation.collect_inventory()
    except mutation.MutationError as exc:
        pytest.fail(str(exc))
    problems = inventory.problems()
    assert problems == [], "; ".join(problems) + "\n\n" + inventory.describe()


@pytest.mark.runtime
def test_the_allowed_test_asserts_the_exception_id_and_the_stored_summary() -> None:
    """The allowed case fails under the identity-swapped and the summary-withheld mutations."""
    for name in ("identity-swapped", "summary-withheld"):
        verdict = _verdict(name)
        assert verdict.ok, f"{name}: " + "; ".join(verdict.problems)


@pytest.mark.runtime
def test_each_rejection_test_asserts_the_exact_status_without_the_summary() -> None:
    """Every rejection case fails when 401 and 403 trade places and when a refusal leaks a summary.

    `status-swapped` proves each asserts its exact status; `rejection-summary-leaked` keeps
    every refusal's status and puts the requested record's stored summary in the body, so
    it proves each asserts that the summary is not returned. Together with
    `test_each_rejection_test_fails_when_the_access_rule_is_removed`, which returns the
    stored summary to every caller, this is the row's evidence.
    """
    for name in ("status-swapped", "rejection-summary-leaked"):
        verdict = _verdict(name)
        assert verdict.ok, f"{name}: " + "; ".join(verdict.problems)


@pytest.mark.runtime
def test_each_rejection_test_fails_when_the_access_rule_is_removed() -> None:
    """Every rejection case fails against a copy of routes.py with the access rule removed."""
    verdict = _verdict("rule-removed")
    assert verdict.ok, "; ".join(verdict.problems)


# --- The answer sheet ----------------------------------------------------------------------


def test_submission_records_no_answers() -> None:
    """`submission.yaml` still records `answers: {}` and passes the public format check."""
    try:
        validate_submission(
            TASK_ROOT / "submission.yaml",
            TASK_ROOT / "docs/contracts/submission.schema.json",
            task_root=TASK_ROOT,
        )
    except SubmissionError as exc:
        pytest.fail(str(exc))
