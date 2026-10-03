"""Coldline.

===================

File:              tests/security/mutation.py
Component:         Security tooling — Access-rule mutations
Purpose:           Record what the student's access tests actually request, then rerun them
                    against mutated copies of the route and the rule.
Interacts With:    tests/student/test_exception_access.py, tests/security/harness.py,
                    tests/security/trace.py, src/api/routes.py, src/api/security/access.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Mutation testing, tests that can fail, exact status assertions, evidence
                    from executed requests
Tools:             Python 3.12, ast, pytest (as a subprocess)

A test proves something only if it can fail. This module first runs the student's
``tests/student/test_exception_access.py`` once as written, with the harness recording
every request each test makes (``tests/security/trace.py``): that run is the **inventory**
of executed cases, one per collected pytest case, with the fixture it sent and whether it
requested an exception that has a stored summary. A case counts as the allowed test when it
requested such an exception as ``dispatcher-valid`` and nothing else; it counts as the
rejection test for a refused fixture when it requested such an exception as that fixture
alone. Eight executed cases are required: one allowed case and one dedicated rejection
case per refused fixture. A name in the source, a constant, or a comment counts for
nothing; only the requests a test made do. A parametrized test is one case per parameter.

Cases are identified by their full pytest node id, the file, the class chain, and the
function name with its parameter id, on both sides: the trace records it from
``PYTEST_CURRENT_TEST`` and the junit report yields it from ``classname`` plus ``name``.
Two methods called ``test_expired`` in two classes are therefore two cases, each judged on
its own; a junit report that names one identity twice is rejected as a tooling error.

Then it copies ``src/`` to a temporary directory, changes one thing in the copy, runs the
student file against it (``PYTHONPATH`` puts the copy first), and requires every case the
mutation targets to have the junit outcome ``failed``. Five mutations:

| Mutation | Change in the copy | Must fail |
|---|---|---|
| rule-removed | require_access is stripped from get_exception | every rejection case |
| status-swapped | the rule answers 403 for 401 and 401 for 403 | every rejection case |
| rejection-summary-leaked | refusals keep their status, carry the summary | every rejection case |
| summary-withheld | get_exception returns the record with summary null | the allowed case |
| identity-swapped | get_exception returns the record under another id | the allowed case |

Only ``failed`` counts. A case that ``passed`` or was ``skipped`` did not notice the change;
a case that ``errored`` (a fixture, setup, or collection error) never reached its assertion
and makes the run invalid, which is reported by name. pytest's exit code is kept and
validated: an interrupted, internal, or usage failure is a tooling error, not a verdict.

Before any of these runs, the student file passes ``tests/security/student_guard.py``: a
static check, over the file's bytes and never an import, that it imports only ``pytest``,
``typing``, ``__future__`` and the harness class, names nothing that inspects or escapes
its environment (``__file__``, ``sys``, ``importlib``, ``getattr``, ``open``, any dunder,
...), takes no pytest built-in fixture such as ``monkeypatch`` or ``request`` as a
parameter, uses ``pytest`` only for fixtures, marks, ``param`` and ``raises``, and asserts
a ``.status_code`` in every test. A file the guard
rejects is never executed here: ``MutationError`` names the findings instead. A test that
could tell a mutated run from a plain one by looking at where ``api.routes`` was imported
from would otherwise pass every verdict while asserting nothing about the API.

Source files are read as UTF-8 with an optional BOM (``utf-8-sig``), which is what the
route guard permits, so a BOM-bearing ``routes.py`` is mutated like any other.

``python -m tests.security.mutation`` (``poe access-mutation``) prints the inventory and the
outcome of every mutation; ``tests/contract/test_exception_access.py`` asserts the same
verdicts, one per Check-list row.
"""

from __future__ import annotations

import ast
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from tests.security import student_guard, trace
from tests.security.fixtures import ALLOWED, REFUSED

TASK_ROOT = Path(__file__).resolve().parents[2]
STUDENT_TEST = Path("tests/student/test_exception_access.py")
ROUTES = Path("src/api/routes.py")
ACCESS = Path("src/api/security/access.py")
ROUTE_FUNCTION = "get_exception"
APP_FACTORY = "create_app"
RULE_NAME = "require_access"
STATUS_TABLE = "STATUS_BY_KIND"
MUTATIONS: tuple[str, ...] = (
    "rule-removed",
    "status-swapped",
    "rejection-summary-leaked",
    "summary-withheld",
    "identity-swapped",
)
# Which side of the student file each mutation must make fail.
TARGETS_REJECTION = {"rule-removed", "status-swapped", "rejection-summary-leaked"}
PYTEST_TIMEOUT_SECONDS = 300
# pytest's exit codes that are verdicts: 0 all passed, 1 some failed, 5 nothing collected.
# 2 (interrupted, a collection error included), 3 (internal error), and 4 (usage error) are
# not: the run did not happen as asked.
PYTEST_VERDICT_EXITS = frozenset({0, 1, 5})
Transform = Callable[[str], tuple[str, int]]


class MutationError(RuntimeError):
    """Report that a mutation could not be applied or run, as opposed to a test verdict."""


# --- The inventory: what each collected test actually requested ---------------------------


@dataclass(frozen=True)
class ExecutedCase:
    """Describe one collected pytest case by the requests it made through the harness.

    ``name`` is the case's full node id (``tests/student/test_exception_access.py::...``),
    the identity the trace and the junit report share.
    """

    name: str
    fixtures: frozenset[str]
    outcome: str
    requests: tuple[str, ...] = ()

    @property
    def dedicated_fixture(self) -> str | None:
        """Return the one fixture this case requested a stored exception with, if exactly one."""
        if len(self.fixtures) == 1:
            return next(iter(self.fixtures))
        return None


@dataclass(frozen=True)
class Inventory:
    """Hold the executed cases of one run of the student file as written."""

    cases: dict[str, ExecutedCase]

    @classmethod
    def from_run(cls, outcomes: dict[str, str], events: list[dict[str, object]]) -> Inventory:
        """Join junit outcomes with the harness's recorded requests, per full case id."""
        fixtures: dict[str, set[str]] = {name: set() for name in outcomes}
        requests: dict[str, list[str]] = {name: [] for name in outcomes}
        for event in events:
            case = event.get("case")
            if not isinstance(case, str) or case not in outcomes:
                continue
            fixture = event.get("fixture")
            path = str(event.get("path", ""))
            stored = bool(event.get("stored_summary"))
            label = f"{event.get('method', 'GET')} {path} as {fixture or 'no token'}"
            requests[case].append(label if stored else f"{label} (no stored summary)")
            if (
                isinstance(fixture, str)
                and event.get("method", "GET") == "GET"
                and trace.exception_id_of(path) is not None
                and stored
            ):
                fixtures[case].add(fixture)
        return cls(
            {
                name: ExecutedCase(name, frozenset(fixtures[name]), outcome, tuple(requests[name]))
                for name, outcome in outcomes.items()
            }
        )

    @property
    def allowed(self) -> set[str]:
        """Return the cases that requested a stored exception as the allowed fixture alone."""
        return {name for name, case in self.cases.items() if case.fixtures == frozenset(ALLOWED)}

    @property
    def rejection(self) -> set[str]:
        """Return the cases that requested a stored exception with any refused fixture."""
        return {name for name, case in self.cases.items() if case.fixtures & set(REFUSED)}

    def dedicated(self, fixture: str) -> list[str]:
        """Return the cases that requested a stored exception with ``fixture`` and no other."""
        return sorted(
            name for name, case in self.cases.items() if case.dedicated_fixture == fixture
        )

    def allowed_problems(self) -> list[str]:
        """Return why the allowed case is missing."""
        if self.allowed:
            return []
        return [
            "no test requested an exception with a stored summary as 'dispatcher-valid' "
            "alone: write the allowed test"
        ]

    def rejection_problems(self) -> list[str]:
        """Return the refused fixtures that have no dedicated executed case, in the Task's order."""
        missing = [fixture for fixture in REFUSED if not self.dedicated(fixture)]
        if not missing:
            return []
        return [
            "no test requested an exception with a stored summary as "
            + ", ".join(f"'{fixture}'" for fixture in missing)
            + " alone: write one rejection test per refused fixture"
        ]

    def problems(self) -> list[str]:
        """Return everything the student file lacks for the eight required cases."""
        if not self.cases:
            return [
                f"{STUDENT_TEST.as_posix()} ran no test; write the eight tests the template marks"
            ]
        return self.allowed_problems() + self.rejection_problems()

    def describe(self) -> str:
        """Render the inventory as a Markdown table, for `poe access-mutation` and messages."""
        lines = ["| Case | Requested a stored exception as | Outcome |", "|---|---|---|"]
        for name in sorted(self.cases):
            case = self.cases[name]
            fixtures = ", ".join(sorted(case.fixtures)) or "-"
            lines.append(f"| `{name}` | {fixtures} | {case.outcome} |")
        return "\n".join(lines)


@dataclass(frozen=True)
class RunResult:
    """What one run of the student file reported, per junit test case."""

    mutation: str
    outcomes: dict[str, str]
    returncode: int = 1


@dataclass(frozen=True)
class Verdict:
    """Whether one mutation made every required case fail, and why not."""

    mutation: str
    required: set[str]
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Return whether the mutation is proven by the student's tests."""
        return not self.problems


# --- The transforms ----------------------------------------------------------------------


def _callee(func: ast.expr) -> str | None:
    """Return the simple name a call targets, if it has one."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _calls(node: ast.AST, name: str) -> bool:
    """Return whether ``node`` contains a call to ``name``."""
    return any(
        isinstance(child, ast.Call) and _callee(child.func) == name for child in ast.walk(node)
    )


def _route(tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the ``get_exception`` function definition, wherever it is nested."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == ROUTE_FUNCTION:
            return node
    return None


def _mentions_rule(argument: ast.arg, default: ast.expr | None) -> bool:
    """Return whether a parameter's annotation or default applies the access rule."""
    if argument.annotation is not None and _calls(argument.annotation, RULE_NAME):
        return True
    return default is not None and _calls(default, RULE_NAME)


def strip_access_rule(source: str) -> tuple[str, int]:
    """Remove every ``require_access`` application from ``get_exception``.

    Handles the three ways a route can carry the rule: an ``Annotated[...,
    Depends(require_access(...))]`` parameter, a ``= Depends(require_access(...))``
    default, and a ``dependencies=[Depends(require_access(...))]`` decorator keyword.
    Returns the mutated source and how many applications were removed; zero means the
    route carries no rule.
    """
    tree = ast.parse(source)
    route = _route(tree)
    if route is None:
        return source, 0
    removed = 0
    arguments = route.args
    positional = list(arguments.posonlyargs) + list(arguments.args)
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(arguments.defaults))
    defaults.extend(arguments.defaults)
    kept_positional: list[tuple[ast.arg, ast.expr | None, bool]] = []
    for index, (argument, default) in enumerate(zip(positional, defaults, strict=True)):
        if _mentions_rule(argument, default):
            removed += 1
            continue
        kept_positional.append((argument, default, index < len(arguments.posonlyargs)))
    arguments.posonlyargs = [arg for arg, _, only in kept_positional if only]
    arguments.args = [arg for arg, _, only in kept_positional if not only]
    arguments.defaults = [default for _, default, _ in kept_positional if default is not None]
    kept_keyword = [
        (argument, default)
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True)
        if not _mentions_rule(argument, default)
    ]
    removed += len(arguments.kwonlyargs) - len(kept_keyword)
    arguments.kwonlyargs = [argument for argument, _ in kept_keyword]
    arguments.kw_defaults = [default for _, default in kept_keyword]
    for decorator in route.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        kept = [
            keyword
            for keyword in decorator.keywords
            if not (keyword.arg == "dependencies" and _calls(keyword.value, RULE_NAME))
        ]
        removed += len(decorator.keywords) - len(kept)
        decorator.keywords = kept
    if removed == 0:
        # Nothing to strip: hand back the student's source byte for byte, not a re-render.
        return source, 0
    return ast.unparse(ast.fix_missing_locations(tree)), removed


def swap_status_codes(source: str) -> tuple[str, int]:
    """Swap the two values of ``STATUS_BY_KIND`` so 401 and 403 trade places."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        target = node.targets[0] if isinstance(node, ast.Assign) else node.target
        if not (isinstance(target, ast.Name) and target.id == STATUS_TABLE):
            continue
        value = node.value
        if isinstance(value, ast.Dict) and len(value.values) == 2:
            value.values = [value.values[1], value.values[0]]
            return ast.unparse(ast.fix_missing_locations(tree)), 1
    return source, 0


def expose_repository(source: str) -> tuple[str, int]:
    """Make ``create_app`` keep the exception repository on ``app.state`` beside the verifier.

    Half of the ``rejection-summary-leaked`` mutation: the rule's dependency has the request
    and the application state but no repository, so the route module's composition is
    changed to publish the one it closes over. The line is inserted right after the
    supplied ``app.state.token_verifier = token_verifier`` assignment.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name != APP_FACTORY:
            continue
        for index, statement in enumerate(node.body):
            if not (isinstance(statement, ast.Assign) and len(statement.targets) == 1):
                continue
            target = statement.targets[0]
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "token_verifier"
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "state"
            ):
                exposure = ast.parse("app.state.repository = repository").body[0]
                node.body.insert(index + 1, exposure)
                return ast.unparse(ast.fix_missing_locations(tree)), 1
    return source, 0


_LEAK_TEMPLATE = """
async def _template(request, exc):
    leaked = exc.reason
    repository = getattr(request.app.state, "repository", None)
    exception_id = request.path_params.get("exception_id")
    if repository is not None and exception_id is not None:
        record = await repository.get(exception_id)
        if record is not None and record.summary:
            leaked = f"{exc.reason} [summary: {record.summary}]"
    headers = {"WWW-Authenticate": "Bearer"} if exc.kind == "unauthenticated" else None
    raise HTTPException(
        status_code=STATUS_BY_KIND[exc.kind], detail=leaked, headers=headers
    ) from exc
"""


def leak_summary_in_refusals(source: str) -> tuple[str, int]:
    """Make the rule's refusals keep their status but carry the requested record's summary.

    The other half of ``rejection-summary-leaked``: inside ``require_access``'s dependency,
    the ``except AccessDenied`` handler is replaced by one that looks the requested
    exception up in ``app.state.repository`` (see ``expose_repository``) and appends its
    stored summary to the refusal's ``detail``. The status is untouched, so a rejection
    test that asserts the exact status and nothing about the body still passes, which is
    what this mutation exists to show.
    """
    tree = ast.parse(source)
    template = ast.parse(_LEAK_TEMPLATE).body[0]
    assert isinstance(template, ast.AsyncFunctionDef)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == RULE_NAME):
            continue
        for inner in ast.walk(node):
            if not (isinstance(inner, ast.AsyncFunctionDef) and inner.args.args):
                continue
            if inner.args.args[0].arg != "request":
                continue
            for handler in ast.walk(inner):
                if not (
                    isinstance(handler, ast.ExceptHandler)
                    and isinstance(handler.type, ast.Name)
                    and handler.type.id == "AccessDenied"
                ):
                    continue
                handler.name = "exc"
                handler.body = list(template.body)
                return ast.unparse(ast.fix_missing_locations(tree)), 1
    return source, 0


def _rewrite_returns(source: str, update: dict[str, str | None]) -> tuple[str, int]:
    """Wrap every ``return <record>`` in ``get_exception`` with ``model_copy(update=...)``."""
    tree = ast.parse(source)
    route = _route(tree)
    if route is None:
        return source, 0
    count = 0
    for node in ast.walk(route):
        if isinstance(node, ast.Return) and node.value is not None:
            node.value = ast.Call(
                func=ast.Attribute(value=node.value, attr="model_copy", ctx=ast.Load()),
                args=[],
                keywords=[
                    ast.keyword(
                        arg="update",
                        value=ast.Dict(
                            keys=[ast.Constant(key) for key in update],
                            values=[ast.Constant(value) for value in update.values()],
                        ),
                    )
                ],
            )
            count += 1
    return ast.unparse(ast.fix_missing_locations(tree)), count


def withhold_summary(source: str) -> tuple[str, int]:
    """Make ``get_exception`` return the record without its stored summary."""
    return _rewrite_returns(source, {"summary": None})


def swap_identity(source: str) -> tuple[str, int]:
    """Make ``get_exception`` return the record under another exception id."""
    return _rewrite_returns(source, {"exception_id": "exc-mutation-identity"})


# Each mutation's rewrites, as (file under the temporary `src` copy, transform).
TRANSFORMS: dict[str, tuple[tuple[str, Transform], ...]] = {
    "rule-removed": (("api/routes.py", strip_access_rule),),
    "status-swapped": (("api/security/access.py", swap_status_codes),),
    "rejection-summary-leaked": (
        ("api/routes.py", expose_repository),
        ("api/security/access.py", leak_summary_in_refusals),
    ),
    "summary-withheld": (("api/routes.py", withhold_summary),),
    "identity-swapped": (("api/routes.py", swap_identity),),
}


def apply_mutation(name: str, source_root: Path) -> None:
    """Rewrite the files of one mutation under the temporary ``src`` copy, or raise."""
    if name not in TRANSFORMS:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    for relative, transform in TRANSFORMS[name]:
        path = source_root / relative
        # `utf-8-sig` drops a leading BOM, which the route guard permits and `ast.parse`
        # rejects in an already-decoded string; the copy is written back without one.
        mutated, count = transform(path.read_text(encoding="utf-8-sig"))
        if count == 0:
            if name == "rule-removed":
                raise MutationError(
                    f"no access rule to remove: {ROUTES.as_posix()} applies no "
                    f"`{RULE_NAME}(...)` dependency on `{ROUTE_FUNCTION}`"
                )
            raise MutationError(f"mutation {name} found nothing to change in {path.name}")
        path.write_text(mutated, encoding="utf-8")


# --- Running the student file -------------------------------------------------------------


def _parse_junit(report: Path) -> dict[str, str]:
    """Return each junit test case's outcome, keyed by its full case id.

    The key is ``trace.junit_case_id(classname, name)``, the same identity the trace
    records, so a method name shared by two classes and the parameters of one function
    stay distinct. Two test cases with one identity make the report unusable: the later
    one would silently overwrite the earlier, so the run is rejected instead.
    """
    outcomes: dict[str, str] = {}
    if not report.is_file():
        return outcomes
    for case in ET.parse(report).iter("testcase"):
        identity = trace.junit_case_id(
            case.attrib.get("classname", ""), case.attrib.get("name", "")
        )
        if identity in outcomes:
            raise MutationError(
                f"the junit report for {STUDENT_TEST.as_posix()} names {identity} twice; one "
                "outcome per collected case is required"
            )
        if case.find("error") is not None:
            outcomes[identity] = "error"
        elif case.find("failure") is not None:
            outcomes[identity] = "failed"
        elif case.find("skipped") is not None:
            outcomes[identity] = "skipped"
        else:
            outcomes[identity] = "passed"
    return outcomes


def guard_student_file(root: Path = TASK_ROOT) -> None:
    """Refuse to execute a student file the static guard rejects, naming every finding.

    Every execution of the file in this module goes through here first: the inventory run
    and each mutated run. The guard parses the file's bytes and never imports it.
    """
    try:
        found = student_guard.findings(root / STUDENT_TEST)
    except student_guard.StudentGuardError as exc:
        raise MutationError(str(exc)) from exc
    if found:
        raise MutationError(
            f"{STUDENT_TEST.as_posix()} was not run: it must use only the supplied harness "
            "and assert each response (`poe student-guard`):\n- " + "\n- ".join(found)
        )


def _run_student_file(
    root: Path, mutation: str | None
) -> tuple[RunResult, list[dict[str, object]]]:
    """Run the student file once, as written or against one mutated copy of ``src``.

    The static guard runs first and the file is not executed when it has findings. The
    run records every request made through the harness. Under a mutation the copy is
    put first on ``PYTHONPATH`` for the pytest subprocess, and the subprocess is asked where
    it imports ``api.routes`` from before the tests run, so a run against the unmutated code
    can never pass as a mutated one. pytest's exit code is validated: only a verdict exit
    (all passed, some failed, nothing collected) is accepted, and a verdict exit must come
    with a junit report.
    """
    guard_student_file(root)
    label = mutation or "as written"
    with tempfile.TemporaryDirectory(prefix="coldline-mutation-") as temporary:
        environment = os.environ.copy()
        if mutation is not None:
            source_root = Path(temporary) / "src"
            shutil.copytree(
                root / "src", source_root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
            )
            apply_mutation(mutation, source_root)
            existing = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = (
                str(source_root) if not existing else os.pathsep.join([str(source_root), existing])
            )
            probe = subprocess.run(
                [sys.executable, "-c", "import api.routes; print(api.routes.__file__)"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            imported = (
                Path(probe.stdout.strip()) if probe.returncode == 0 and probe.stdout else None
            )
            if imported is None or not imported.resolve().is_relative_to(source_root.resolve()):
                raise MutationError(
                    "the mutated copy was not the one imported: "
                    f"{probe.stdout.strip() or probe.stderr.strip()}"
                )
        report = Path(temporary) / "report.xml"
        recorded = Path(temporary) / "trace.jsonl"
        environment[trace.TRACE_VARIABLE] = str(recorded)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(root / STUDENT_TEST),
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={report}",
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )
        if completed.returncode not in PYTEST_VERDICT_EXITS:
            tail = (completed.stdout + completed.stderr).strip().splitlines()[-12:]
            raise MutationError(
                f"pytest exited {completed.returncode} running {STUDENT_TEST.as_posix()} "
                f"{label}, which is not a verdict (collection, usage, or internal error):\n"
                + "\n".join(tail)
            )
        if completed.returncode != 5 and not report.is_file():
            raise MutationError(
                f"pytest exited {completed.returncode} running {STUDENT_TEST.as_posix()} "
                f"{label} but wrote no junit report"
            )
        outcomes = _parse_junit(report)
        return RunResult(label, outcomes, completed.returncode), trace.read_events(recorded)


_INVENTORIES: dict[tuple[Path, str], Inventory] = {}


def collect_inventory(root: Path = TASK_ROOT, *, refresh: bool = False) -> Inventory:
    """Run the student file as written and return what each collected case requested.

    The result is kept per process for the student file's current content, so the
    assessed rows that share one pytest process run the inventory once.
    """
    path = root / STUDENT_TEST
    if not path.is_file():
        raise MutationError(f"{STUDENT_TEST.as_posix()} does not exist")
    content = path.read_bytes()
    try:
        ast.parse(content)
    except SyntaxError as exc:
        raise MutationError(f"{STUDENT_TEST.as_posix()} is not valid Python: {exc}") from exc
    key = (root.resolve(), hashlib.sha256(content).hexdigest())
    if refresh or key not in _INVENTORIES:
        result, events = _run_student_file(root, None)
        _INVENTORIES[key] = Inventory.from_run(result.outcomes, events)
    return _INVENTORIES[key]


def run_mutation(name: str, *, root: Path = TASK_ROOT) -> RunResult:
    """Copy ``src``, apply one mutation, run the student file against the copy, and report."""
    if name not in MUTATIONS:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    result, _ = _run_student_file(root, name)
    return result


# --- Judging ------------------------------------------------------------------------------


def required_tests(name: str, inventory: Inventory) -> tuple[set[str], list[str]]:
    """Return the cases one mutation must make fail, and why that set is not yet complete."""
    if name in TARGETS_REJECTION:
        return inventory.rejection, inventory.rejection_problems()
    return inventory.allowed, inventory.allowed_problems()


def judge(name: str, inventory: Inventory, result: RunResult) -> Verdict:
    """Decide whether one mutation made every required case fail, and only count `failed`."""
    required, problems = required_tests(name, inventory)
    if not result.outcomes:
        problems.append(f"{STUDENT_TEST.as_posix()} produced no test cases under {name}")
    errored = sorted(case for case, outcome in result.outcomes.items() if outcome == "error")
    if errored:
        problems.append(
            f"the run under {name} is invalid: {', '.join(errored)} errored; a fixture, "
            "setup, or collection error is not a failing assertion"
        )
    for case in sorted(required):
        outcome = result.outcomes.get(case)
        if outcome is None:
            problems.append(f"{case} produced no test case under {name}")
        elif outcome == "passed":
            problems.append(f"{case} still passes with {name}")
        elif outcome == "skipped":
            problems.append(f"{case} was skipped under {name}")
    return Verdict(name, required, problems)


def check(name: str, *, root: Path = TASK_ROOT) -> Verdict:
    """Collect the inventory, then run one mutation against the student file and judge it.

    The structural precondition (the cases the mutation must make fail were executed and
    requested their exceptions) is checked first, so a file without them is reported
    without a mutated run.
    """
    inventory = collect_inventory(root)
    required, problems = required_tests(name, inventory)
    if problems:
        return Verdict(name, required, problems)
    return judge(name, inventory, run_mutation(name, root=root))


def main() -> int:
    """Print the inventory, then run every mutation and print what each one proved."""
    exit_code = 0
    try:
        inventory = collect_inventory()
    except MutationError as exc:
        print(f"## executed cases\n\nnot run: {exc}\n")
        return 1
    print("## executed cases\n")
    print(inventory.describe())
    print()
    for problem in inventory.problems():
        exit_code = 1
        print(f"- {problem}")
    if inventory.problems():
        print()
    for name in MUTATIONS:
        try:
            verdict = check(name)
        except MutationError as exc:
            print(f"## {name}\n\nnot run: {exc}\n")
            exit_code = 1
            continue
        side = "rejection cases" if name in TARGETS_REJECTION else "allowed case"
        print(f"## {name}\n")
        print(f"must fail: {', '.join(sorted(verdict.required)) or '(none found)'} ({side})")
        if verdict.ok:
            print("verdict: every required case failed under this mutation\n")
        else:
            exit_code = 1
            print("verdict: NOT proven")
            for problem in verdict.problems:
                print(f"- {problem}")
            print()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
