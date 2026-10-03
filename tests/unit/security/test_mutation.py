"""Coldline.

===================

File:              tests/unit/security/test_mutation.py
Component:         Unit tests — Access-rule mutations
Purpose:           Prove the mutation transforms, the executed-case inventory, and the judge
                    without a stack.
Interacts With:    tests/security/mutation.py, tests/security/trace.py, src/api/routes.py,
                    src/api/security/access.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Mutation testing, AST rewriting, evidence from executed requests
Tools:             Python 3.12, pytest, httpx, FastAPI

These tests spawn no pytest subprocess against the real student file: they feed sources
to the transforms, recorded events and junit-shaped outcomes to the inventory and the
judge, and run the leak mutation's rewritten access module in-process.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from fastapi import Depends, FastAPI

from api.security.tokens import AuthSettings, TokenVerifier
from tests.security import mutation, trace
from tests.security.fixtures import REFUSED, token

TASK_ROOT = Path(__file__).resolve().parents[3]
KEY_SET = TASK_ROOT / "infra/issuer/jwks.json"

ANNOTATED_FORM = """
@app.get("/api/v1/exceptions/{exception_id}", response_model=ExceptionRecord)
async def get_exception(
    exception_id: str,
    principal: Annotated[Principal, Depends(require_access(role="r", scope="s"))],
) -> ExceptionRecord:
    record = await repository.get(exception_id)
    if record is None:
        raise HTTPException(status_code=404, detail="exception not found")
    return record
"""

DEFAULT_FORM = """
@app.get("/api/v1/exceptions/{exception_id}", response_model=ExceptionRecord)
async def get_exception(
    exception_id: str,
    principal: Principal = Depends(require_access(role="r", scope="s")),
) -> ExceptionRecord:
    return await repository.get(exception_id)
"""

DECORATOR_FORM = """
@app.get(
    "/api/v1/exceptions/{exception_id}",
    response_model=ExceptionRecord,
    dependencies=[Depends(require_access(role="r", scope="s"))],
)
async def get_exception(exception_id: str) -> ExceptionRecord:
    return await repository.get(exception_id)
"""

KEYWORD_ONLY_FORM = """
@app.get("/api/v1/exceptions/{exception_id}")
async def get_exception(
    exception_id: str, *, principal: Principal = Depends(require_access(role="r", scope="s"))
) -> ExceptionRecord:
    return await repository.get(exception_id)
"""

OPEN_FORM = """
@app.get("/api/v1/exceptions/{exception_id}", response_model=ExceptionRecord)
async def get_exception(exception_id: str) -> ExceptionRecord:
    record = await repository.get(exception_id)
    if record is None:
        raise HTTPException(status_code=404, detail="exception not found")
    return record
"""

FACTORY_FORM = """
def create_app(application, repository, *, token_verifier=None):
    app = FastAPI()
    app.state.token_verifier = token_verifier

    @app.get("/api/v1/exceptions/{exception_id}")
    async def get_exception(exception_id: str):
        return await repository.get(exception_id)

    return app
"""


def _route_source(mutated: str) -> str:
    """Return the unparsed `get_exception` definition from a mutated module."""
    route = mutation._route(ast.parse(mutated))
    assert route is not None
    return ast.unparse(route)


@pytest.mark.parametrize(
    "source", [ANNOTATED_FORM, DEFAULT_FORM, DECORATOR_FORM, KEYWORD_ONLY_FORM]
)
def test_strip_access_rule_removes_the_rule_in_every_call_form(source: str) -> None:
    """Annotated, default, keyword-only, and decorator applications are all stripped."""
    mutated, removed = mutation.strip_access_rule(source)

    assert removed == 1
    assert "require_access" not in mutated
    assert "exception_id: str" in _route_source(mutated)


def test_strip_access_rule_reports_an_open_route() -> None:
    """A route without the rule is reported as zero removals, and the source is untouched."""
    mutated, removed = mutation.strip_access_rule(OPEN_FORM)

    assert removed == 0
    assert mutated == OPEN_FORM


def test_swap_status_codes_trades_401_and_403_in_the_real_module() -> None:
    """The shipped access module's status table is the one the mutation swaps."""
    source = (TASK_ROOT / "src/api/security/access.py").read_text(encoding="utf-8")

    mutated, count = mutation.swap_status_codes(source)

    assert count == 1
    table = next(
        node
        for node in ast.walk(ast.parse(mutated))
        if isinstance(node, ast.AnnAssign | ast.Assign)
        and isinstance(
            target := (node.target if isinstance(node, ast.AnnAssign) else node.targets[0]),
            ast.Name,
        )
        and target.id == "STATUS_BY_KIND"
    )
    assert table.value is not None
    assert ast.literal_eval(table.value) == {"unauthenticated": 403, "permission_denied": 401}


def test_withhold_summary_and_swap_identity_wrap_every_return() -> None:
    """Both record mutations rewrite the route's return into a model_copy with the update."""
    withheld, count = mutation.withhold_summary(ANNOTATED_FORM)
    assert count == 1
    assert "model_copy(update={'summary': None})" in withheld

    swapped, count = mutation.swap_identity(ANNOTATED_FORM)
    assert count == 1
    assert "model_copy(update={'exception_id': 'exc-mutation-identity'})" in swapped


def test_expose_repository_publishes_the_repository_beside_the_verifier() -> None:
    """The route half of the leak mutation adds one line after the verifier assignment."""
    mutated, count = mutation.expose_repository(FACTORY_FORM)

    assert count == 1
    factory = ast.parse(mutated).body[0]
    assert isinstance(factory, ast.FunctionDef)
    body = [ast.unparse(node) for node in factory.body]
    assert body[1:3] == [
        "app.state.token_verifier = token_verifier",
        "app.state.repository = repository",
    ]
    assert mutation.expose_repository("def create_app():\n    return 1\n") == (
        "def create_app():\n    return 1\n",
        0,
    )


def _verifier() -> TokenVerifier:
    """Return a verifier over the committed key set."""
    settings = AuthSettings(
        issuer="https://issuer.coldline.test",
        audience="coldline-api",
        jwks_url="http://localhost:8180/.well-known/jwks.json",
        algorithms=["RS256"],
        leeway_seconds=30,
    )
    return TokenVerifier(settings, fetch=lambda url: KEY_SET.read_bytes())


@dataclass(frozen=True)
class _Record:
    exception_id: str
    summary: str


class _Repository:
    """Hold one record, as the mutated rule looks it up through app.state.repository."""

    def __init__(self, record: _Record) -> None:
        self.record = record

    async def get(self, exception_id: str) -> _Record | None:
        """Return the one record for its id."""
        return self.record if exception_id == self.record.exception_id else None


async def test_leak_summary_in_refusals_keeps_the_status_and_adds_the_summary() -> None:
    """The rewritten access module answers 401 and 403 as before, with the summary in the body.

    The real module is rewritten and executed in this process: a rule from it guards one
    route of a small application whose state carries a repository, exactly as the
    mutated `create_app` publishes it.
    """
    source = (TASK_ROOT / "src/api/security/access.py").read_text(encoding="utf-8")
    mutated, count = mutation.leak_summary_in_refusals(source)
    assert count == 1
    namespace: dict[str, object] = {"__name__": "mutated_access"}
    exec(compile(mutated, "<access.py rejection-summary-leaked>", "exec"), namespace)
    require_access = namespace["require_access"]
    assert callable(require_access)

    record = _Record("exc-leak", "Shipment shipment-leak recorded 9.2 C; hold the pallet.")
    app = FastAPI()
    app.state.token_verifier = _verifier()
    app.state.repository = _Repository(record)

    @app.get("/api/v1/exceptions/{exception_id}")
    async def get_exception(
        exception_id: str,
        # A route defined inside a test cannot use the Annotated form: under postponed
        # annotations FastAPI resolves names at module scope, where `require_access` is absent.
        principal: object = Depends(  # noqa: B008
            require_access(role="dispatcher", scope="exceptions:read")
        ),
    ) -> dict[str, str]:
        """Return the record to an admitted caller."""
        return {"exception_id": exception_id, "summary": record.summary}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        refused = await client.get(
            "/api/v1/exceptions/exc-leak",
            headers={"Authorization": f"Bearer {token('bad-signature')}"},
        )
        forbidden = await client.get(
            "/api/v1/exceptions/exc-leak",
            headers={"Authorization": f"Bearer {token('gateway-valid')}"},
        )
        unknown = await client.get(
            "/api/v1/exceptions/exc-other",
            headers={"Authorization": f"Bearer {token('expired')}"},
        )
        admitted = await client.get(
            "/api/v1/exceptions/exc-leak",
            headers={"Authorization": f"Bearer {token('dispatcher-valid')}"},
        )

    assert refused.status_code == 401 and record.summary in refused.text
    assert refused.headers.get("www-authenticate") == "Bearer"
    assert forbidden.status_code == 403 and record.summary in forbidden.text
    assert unknown.status_code == 401 and record.summary not in unknown.text
    assert admitted.status_code == 200


def test_every_mutation_rewrites_at_least_one_shipped_file() -> None:
    """Each registered mutation has a transform table entry over a real module path."""
    assert set(mutation.TRANSFORMS) == set(mutation.MUTATIONS)
    for name, rewrites in mutation.TRANSFORMS.items():
        for relative, _ in rewrites:
            assert (TASK_ROOT / "src" / relative).is_file(), (name, relative)
    assert mutation.TARGETS_REJECTION == {
        "rule-removed",
        "status-swapped",
        "rejection-summary-leaked",
    }


# --- The inventory ------------------------------------------------------------------------


def _event(
    case: str, fixture: str | None, exception_id: str = "exc-1", stored: bool = True
) -> dict[str, object]:
    """Return one recorded request event, as the harness writes it."""
    return {
        "case": case,
        "fixture": fixture,
        "method": "GET",
        "path": f"{trace.SUMMARY_ROUTE}{exception_id}",
        "exception_id": exception_id,
        "stored_summary": stored,
    }


def _complete_inventory() -> mutation.Inventory:
    """Return an inventory with the eight required executed cases."""
    outcomes = {"test_dispatcher_reads": "passed"}
    events = [_event("test_dispatcher_reads", "dispatcher-valid")]
    for fixture in REFUSED:
        outcomes[f"test_refused[{fixture}]"] = "passed"
        events.append(_event(f"test_refused[{fixture}]", fixture))
    return mutation.Inventory.from_run(outcomes, events)


def test_the_inventory_counts_executed_requests_for_stored_exceptions_only() -> None:
    """A fixture counts for a case only when it requested an exception with a stored summary."""
    outcomes = {
        "test_dispatcher_reads": "passed",
        "test_names_only": "passed",
        "test_unstored": "passed",
        "test_two_fixtures": "passed",
        "test_no_token": "passed",
    }
    events = [
        _event("test_dispatcher_reads", "dispatcher-valid"),
        _event("test_unstored", "expired", exception_id="exc-missing", stored=False),
        _event("test_two_fixtures", "bad-signature"),
        _event("test_two_fixtures", "wrong-issuer"),
        _event("test_no_token", None),
        {**_event("test_dispatcher_reads", "dispatcher-valid"), "path": "/health/ready"},
    ]

    inventory = mutation.Inventory.from_run(outcomes, events)

    assert inventory.allowed == {"test_dispatcher_reads"}
    assert inventory.rejection == {"test_two_fixtures"}
    assert inventory.cases["test_names_only"].fixtures == frozenset()
    assert inventory.cases["test_unstored"].fixtures == frozenset()
    assert inventory.cases["test_no_token"].fixtures == frozenset()
    assert inventory.dedicated("bad-signature") == []
    assert inventory.allowed_problems() == []
    [problem] = inventory.rejection_problems()
    assert all(f"'{fixture}'" in problem for fixture in REFUSED)
    assert "(no stored summary)" in inventory.cases["test_unstored"].requests[0]


def test_the_inventory_requires_one_dedicated_case_per_refused_fixture_and_one_allowed() -> None:
    """Eight executed cases: the dispatcher's, and one per refused fixture using it alone."""
    inventory = _complete_inventory()

    assert inventory.problems() == []
    assert inventory.allowed == {"test_dispatcher_reads"}
    assert inventory.rejection == {f"test_refused[{fixture}]" for fixture in REFUSED}
    for fixture in REFUSED:
        assert inventory.dedicated(fixture) == [f"test_refused[{fixture}]"]

    without_dispatcher = mutation.Inventory.from_run(
        {name: "passed" for name in inventory.cases if name != "test_dispatcher_reads"},
        [_event(f"test_refused[{fixture}]", fixture) for fixture in REFUSED],
    )
    assert without_dispatcher.problems() == [
        "no test requested an exception with a stored summary as 'dispatcher-valid' alone: "
        "write the allowed test"
    ]
    assert mutation.Inventory.from_run({}, []).problems() == [
        "tests/student/test_exception_access.py ran no test; write the eight tests the "
        "template marks"
    ]


def test_a_test_that_uses_dispatcher_valid_and_a_refused_fixture_is_a_rejection_case() -> None:
    """A mixed case is neither the allowed test nor a dedicated rejection test."""
    inventory = mutation.Inventory.from_run(
        {"test_mixed": "passed"},
        [_event("test_mixed", "dispatcher-valid"), _event("test_mixed", "gateway-valid")],
    )

    assert inventory.allowed == set()
    assert inventory.rejection == {"test_mixed"}
    assert inventory.dedicated("gateway-valid") == []


def test_the_inventory_renders_as_a_table() -> None:
    """`poe access-mutation` prints what each case requested, for the student to read."""
    table = _complete_inventory().describe()

    assert table.splitlines()[0] == "| Case | Requested a stored exception as | Outcome |"
    assert "| `test_refused[expired]` | expired | passed |" in table


# --- The judge ----------------------------------------------------------------------------


def test_judge_counts_only_failed_and_reports_errors_as_an_invalid_run() -> None:
    """A passing, skipped, or errored required case is each named; only `failed` satisfies."""
    inventory = _complete_inventory()
    outcomes = {name: "failed" for name in inventory.cases}
    outcomes["test_dispatcher_reads"] = "passed"
    outcomes["test_refused[wrong-issuer]"] = "passed"
    outcomes["test_refused[wrong-role]"] = "error"
    outcomes["test_refused[expired]"] = "skipped"

    result = mutation.RunResult("rule-removed", outcomes)
    verdict = mutation.judge("rule-removed", inventory, result)

    assert not verdict.ok
    assert verdict.problems == [
        "the run under rule-removed is invalid: test_refused[wrong-role] errored; a fixture, "
        "setup, or collection error is not a failing assertion",
        "test_refused[expired] was skipped under rule-removed",
        "test_refused[wrong-issuer] still passes with rule-removed",
    ]

    outcomes["test_refused[wrong-issuer]"] = "failed"
    outcomes["test_refused[wrong-role]"] = "failed"
    outcomes["test_refused[expired]"] = "failed"
    assert mutation.judge("rule-removed", inventory, result).ok


def test_judge_requires_the_allowed_case_to_fail_under_the_record_mutations() -> None:
    """The record mutations look at the allowed case only."""
    inventory = _complete_inventory()

    passing = mutation.judge(
        "summary-withheld",
        inventory,
        mutation.RunResult("summary-withheld", {"test_dispatcher_reads": "passed"}),
    )
    assert passing.problems == ["test_dispatcher_reads still passes with summary-withheld"]

    failing = mutation.judge(
        "identity-swapped",
        inventory,
        mutation.RunResult("identity-swapped", {"test_dispatcher_reads": "failed"}),
    )
    assert failing.ok


def test_rejection_tests_without_a_body_assertion_are_insufficient() -> None:
    """A student file whose rejection tests assert the status alone passes the leak mutation.

    Under `rejection-summary-leaked` every refusal keeps its status and carries the
    summary, so such tests stay green, and the judge reports each of them by name.
    """
    inventory = _complete_inventory()
    outcomes = {name: "passed" for name in inventory.cases}

    verdict = mutation.judge(
        "rejection-summary-leaked",
        inventory,
        mutation.RunResult("rejection-summary-leaked", outcomes),
    )

    assert not verdict.ok
    assert verdict.required == inventory.rejection
    assert verdict.problems == [
        f"test_refused[{fixture}] still passes with rejection-summary-leaked"
        for fixture in sorted(REFUSED)
    ]
    assert "test_dispatcher_reads" not in " ".join(verdict.problems)


def test_a_missing_case_in_the_mutated_run_is_reported() -> None:
    """A required case that produced no junit case under the mutation is a problem."""
    inventory = _complete_inventory()
    outcomes = {name: "failed" for name in inventory.cases if name != "test_refused[expired]"}

    result = mutation.RunResult("status-swapped", outcomes)
    verdict = mutation.judge("status-swapped", inventory, result)

    assert verdict.problems == ["test_refused[expired] produced no test case under status-swapped"]


def test_required_tests_follow_the_mutation_side() -> None:
    """Rejection mutations require the rejection cases; record mutations the allowed case."""
    inventory = _complete_inventory()

    for name in mutation.TARGETS_REJECTION:
        assert mutation.required_tests(name, inventory) == (inventory.rejection, [])
    for name in set(mutation.MUTATIONS) - mutation.TARGETS_REJECTION:
        assert mutation.required_tests(name, inventory) == (inventory.allowed, [])


def test_check_reports_an_empty_student_file_without_mutating_anything(tmp_path: Path) -> None:
    """On a file with no tests the inventory is the whole verdict: no mutated run is made."""
    root = tmp_path
    (root / "tests/student").mkdir(parents=True)
    (root / "tests/student/test_exception_access.py").write_text("", encoding="utf-8")

    verdict = mutation.check("rule-removed", root=root)

    assert not verdict.ok
    assert verdict.problems == [
        "no test requested an exception with a stored summary as 'bad-signature', "
        "'wrong-issuer', 'wrong-audience', 'expired', 'gateway-valid', 'wrong-role', "
        "'missing-scope' alone: write one rejection test per refused fixture"
    ]
    assert not (root / "src").exists()


def test_collect_inventory_refuses_a_missing_or_invalid_student_file(tmp_path: Path) -> None:
    """A missing file and a syntax error are tooling errors with the file named."""
    with pytest.raises(mutation.MutationError, match="does not exist"):
        mutation.collect_inventory(tmp_path)
    (tmp_path / "tests/student").mkdir(parents=True)
    (tmp_path / "tests/student/test_exception_access.py").write_text("def (:\n", encoding="utf-8")
    with pytest.raises(mutation.MutationError, match="not valid Python"):
        mutation.collect_inventory(tmp_path)


def test_a_student_file_the_guard_rejects_is_never_executed(tmp_path: Path) -> None:
    """Astra's round-3 counterexample is refused by the inventory and by every mutation.

    Eight tests make the required requests and then assert only that `api.routes.__file__`
    is the original checkout's: they would pass as written and fail under every mutation
    without asserting anything about a response. The static guard names the import, the
    attribute, and the missing status assertions, and nothing runs: no pytest subprocess,
    no mutated copy of `src/`.
    """
    root = tmp_path
    (root / "tests/student").mkdir(parents=True)
    tests = ["import pytest\nimport api.routes\n\nORIGINAL = api.routes.__file__\n"]
    for fixture in ("dispatcher-valid", *REFUSED):
        tests.append(
            f"\n\nasync def test_{fixture.replace('-', '_')}(harness):\n"
            "    exception_id, _ = harness.stored_exception()\n"
            f'    async with harness.bearer_client("{fixture}") as client:\n'
            '        await client.get(f"/api/v1/exceptions/{exception_id}")\n'
            "    assert api.routes.__file__ == ORIGINAL\n"
        )
    (root / "tests/student/test_exception_access.py").write_text("".join(tests), encoding="utf-8")

    with pytest.raises(mutation.MutationError, match="was not run") as refused:
        mutation.collect_inventory(root)
    message = str(refused.value)
    assert "`import api.routes` is not permitted" in message
    assert "`__file__` is not permitted" in message
    assert "`test_expired` has no `assert` comparing a response's `.status_code`" in message
    for name in mutation.MUTATIONS:
        with pytest.raises(mutation.MutationError, match="was not run"):
            mutation.check(name, root=root)
    assert not (root / "src").exists()
    assert not list(root.glob("**/report.xml"))


def test_every_mutation_applies_to_a_bom_bearing_completed_route(tmp_path: Path) -> None:
    """Astra's round-3 regression: a UTF-8 BOM the route guard permits must not break a mutation.

    The transforms parse decoded text, and `ast.parse` rejects a leading U+FEFF in a
    string, so the copy's files are read with `utf-8-sig`. All five mutations are applied
    to a completed route module and the real access module, both saved with a BOM.
    """
    bom = b"\xef\xbb\xbf"
    source_root = tmp_path / "src"
    (source_root / "api/security").mkdir(parents=True)
    route = "\n".join(f"    {line}" if line else "" for line in ANNOTATED_FORM.strip().splitlines())
    completed = (
        "from typing import Annotated\n"
        "from fastapi import Depends, FastAPI, HTTPException\n"
        "from api.security.access import require_access\n"
        "from api.security.tokens import Principal\n"
        "from domain.contracts import ExceptionRecord\n"
        "\n\n"
        "def create_app(application, repository, *, token_verifier=None):\n"
        "    app = FastAPI()\n"
        "    app.state.token_verifier = token_verifier\n"
        "\n"
        f"{route}\n"
        "\n"
        "    return app\n"
    ).encode()
    access = (TASK_ROOT / "src/api/security/access.py").read_bytes()
    assert not access.startswith(bom)
    originals = {"api/routes.py": completed, "api/security/access.py": access}
    # The failure this guards against: decoded as plain UTF-8, the BOM is U+FEFF and the
    # parser rejects it; the route guard accepts the same bytes.
    with pytest.raises(SyntaxError):
        ast.parse((bom + completed).decode("utf-8"))

    for name in mutation.MUTATIONS:
        for relative, original in originals.items():
            (source_root / relative).write_bytes(bom + original)
        mutation.apply_mutation(name, source_root)
        for relative, _ in mutation.TRANSFORMS[name]:
            rewritten = (source_root / relative).read_bytes()
            assert not rewritten.startswith(bom), (name, relative)
            ast.parse(rewritten)
            assert rewritten != originals[relative], (name, relative)
        if name == "rule-removed":
            stripped = (source_root / "api/routes.py").read_text("utf-8")
            assert "Depends(require_access" not in stripped and "import require_access" in stripped


def test_trace_names_the_current_case_by_its_full_node_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The recorded case is the full node id: the student file, the class chain, the name and id."""
    file = trace.STUDENT_TEST
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, f"{file}::TestA::test_y[a-b] (call)")
    assert trace.current_case() == f"{file}::TestA::test_y[a-b]"
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, f"{file}::test_z (setup)")
    assert trace.current_case() == f"{file}::test_z"
    # pytest's root may make the file component relative to another directory; the id
    # is normalised onto the one student file either way.
    elsewhere = "test_exception_access.py::Outer::Inner::t (call)"
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, elsewhere)
    assert trace.current_case() == f"{file}::Outer::Inner::t"
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, f"{file}::test_p[x (y)] (teardown)")
    assert trace.current_case() == f"{file}::test_p[x (y)]"
    monkeypatch.delenv(trace.CURRENT_TEST_VARIABLE)
    assert trace.current_case() == ""

    assert trace.exception_id_of("/api/v1/exceptions/exc-1") == "exc-1"
    assert trace.exception_id_of("/api/v1/exceptions/") is None
    assert trace.exception_id_of("/health/ready") is None

    recorded = tmp_path / "trace.jsonl"
    trace.record(None, {"fixture": "expired"})
    trace.record(recorded, {"fixture": "expired", "path": "/api/v1/exceptions/exc-1"})
    [event] = trace.read_events(recorded)
    assert event == {"case": "", "fixture": "expired", "path": "/api/v1/exceptions/exc-1"}
    assert trace.read_events(tmp_path / "absent.jsonl") == []


def test_junit_identity_matches_the_trace_identity_including_class_and_parameter() -> None:
    """`classname` plus `name` from the report rebuilds exactly the node id the trace wrote."""
    file = trace.STUDENT_TEST
    module = "tests.student.test_exception_access"
    assert trace.junit_case_id(module, "test_z") == f"{file}::test_z"
    assert trace.junit_case_id(f"{module}.TestWeak", "test_expired") == (
        f"{file}::TestWeak::test_expired"
    )
    assert trace.junit_case_id(f"{module}.TestStrong", "test_expired") == (
        f"{file}::TestStrong::test_expired"
    )
    assert trace.junit_case_id(f"{module}.Outer.Inner", "t[a-b]") == (
        f"{file}::Outer::Inner::t[a-b]"
    )
    # Another root directory changes the module prefix, not the identity.
    assert trace.junit_case_id("test_exception_access.TestWeak", "test_expired") == (
        f"{file}::TestWeak::test_expired"
    )
    # A case from some other module is kept whole, so it matches no traced case.
    assert trace.junit_case_id("tests.other.test_x", "test_y") == "tests.other.test_x::test_y"
    assert trace.junit_case_id("", "test_y") == "test_y"
    for node in (f"{file}::TestWeak::test_expired", f"{file}::test_z[p]"):
        classname, name = _junit_pair(node)
        assert trace.junit_case_id(classname, name) == trace.case_id(node)


def _junit_pair(node_id: str) -> tuple[str, str]:
    """Return (classname, name) the way pytest's junitxml writes them for one node id."""
    path, _, params = node_id.partition("[")
    names = path.split("::")
    names[0] = names[0].replace("/", ".").removesuffix(".py")
    names[-1] += ("[" + params) if params else ""
    return ".".join(names[:-1]), names[-1]


def _junit_report(path: Path, cases: list[tuple[str, str, str]]) -> Path:
    """Write a junit report with (classname, name, outcome) rows; outcome is a child tag or ''."""
    rows = []
    for classname, name, outcome in cases:
        child = f"<{outcome} message='x' />" if outcome else ""
        rows.append(
            f"<testcase classname='{classname}' name='{name}' time='0.1'>{child}</testcase>"
        )
    path.write_text(
        "<?xml version='1.0'?><testsuites><testsuite name='pytest'>"
        + "".join(rows)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_parse_junit_keeps_same_named_methods_of_two_classes_apart(tmp_path: Path) -> None:
    """`TestWeak.test_expired` and `TestStrong.test_expired` are two outcomes, not one."""
    module = "tests.student.test_exception_access"
    report = _junit_report(
        tmp_path / "report.xml",
        [
            (f"{module}.TestWeak", "test_expired", ""),
            (f"{module}.TestStrong", "test_expired", "failure"),
            (module, "test_refused[expired]", "failure"),
            (module, "test_refused[wrong-role]", "error"),
            (module, "test_other", "skipped"),
        ],
    )

    outcomes = mutation._parse_junit(report)

    file = trace.STUDENT_TEST
    assert outcomes == {
        f"{file}::TestWeak::test_expired": "passed",
        f"{file}::TestStrong::test_expired": "failed",
        f"{file}::test_refused[expired]": "failed",
        f"{file}::test_refused[wrong-role]": "error",
        f"{file}::test_other": "skipped",
    }
    assert mutation._parse_junit(tmp_path / "absent.xml") == {}


def test_parse_junit_rejects_a_report_that_names_one_identity_twice(tmp_path: Path) -> None:
    """Two test cases with one classname and name would overwrite each other: a tooling error."""
    module = "tests.student.test_exception_access"
    report = _junit_report(
        tmp_path / "report.xml",
        [
            (f"{module}.TestWeak", "test_expired", ""),
            (f"{module}.TestWeak", "test_expired", "failure"),
        ],
    )

    with pytest.raises(mutation.MutationError, match="names .*TestWeak::test_expired twice"):
        mutation._parse_junit(report)


def test_two_classes_with_one_method_name_where_only_one_detects_the_mutation_is_insufficient() -> (
    None
):
    """Astra's round-2 regression: a weak `test_expired` cannot hide behind a strong one.

    Both classes request a stored exception as `expired`, so both are rejection cases for
    that fixture. Under `status-swapped` the strong one fails and the weak one (asserting
    `!= 200`) passes; keyed by full identity, the weak one is named and the verdict is not
    proven. Keyed by bare name, the two would have merged and the later outcome would have
    decided.
    """
    file = trace.STUDENT_TEST
    weak = f"{file}::TestWeak::test_expired"
    strong = f"{file}::TestStrong::test_expired"
    allowed = f"{file}::test_dispatcher_reads"
    outcomes = {allowed: "passed", weak: "passed", strong: "passed"}
    events = [
        _event(allowed, "dispatcher-valid"),
        _event(weak, "expired"),
        _event(strong, "expired"),
    ]
    for fixture in REFUSED:
        if fixture != "expired":
            outcomes[f"{file}::test_refused[{fixture}]"] = "passed"
            events.append(_event(f"{file}::test_refused[{fixture}]", fixture))
    inventory = mutation.Inventory.from_run(outcomes, events)
    assert inventory.problems() == []
    assert inventory.dedicated("expired") == [strong, weak]
    assert {weak, strong} <= inventory.rejection

    mutated = {name: "failed" for name in outcomes}
    mutated[allowed] = "passed"
    mutated[weak] = "passed"
    result = mutation.RunResult("status-swapped", mutated)
    verdict = mutation.judge("status-swapped", inventory, result)

    assert not verdict.ok
    assert verdict.problems == [f"{weak} still passes with status-swapped"]
    mutated[weak] = "failed"
    assert mutation.judge("status-swapped", inventory, result).ok
