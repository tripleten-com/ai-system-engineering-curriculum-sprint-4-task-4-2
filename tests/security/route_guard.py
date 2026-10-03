"""Coldline.

===================

File:              tests/security/route_guard.py
Component:         Security tooling — Static route guard
Purpose:           Prove, without importing it, that src/api/routes.py changed nothing but the
                    access rule on get_exception.
Interacts With:    src/api/routes.py, src/api/security/access.py, pyproject.toml (`poe verify`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Trusted static analysis, student-editable code, a check that runs before any
                    import
Tools:             Python 3.12, ast, hashlib

``src/api/routes.py`` is student-editable, and every later step of ``poe verify`` imports
it: the student tests, the mutation reruns, and the API image. A module that ran code at
import time could therefore decide what those steps report. This guard is the first step
of ``poe verify`` and never imports the file: it parses it with ``ast`` and compares it
with the shipped starter, whose shape is embedded below as one digest per top-level
statement (``STARTER_BASELINE``), so the comparison depends on no git history.

What may differ from the starter:

- added imports, limited to what the rule needs: ``Annotated`` from ``typing``,
  ``Depends`` from ``fastapi``, ``require_access`` from ``api.security.access``, and
  ``Principal`` from ``api.security.tokens``, in any order and grouping;
- on ``get_exception``, one application of ``Depends(require_access(role=..., scope=...))``
  in one of its three forms: an ``Annotated[Principal, Depends(...)]`` parameter, a
  parameter with a ``= Depends(...)`` default, or ``dependencies=[Depends(...)]`` on the
  route decorator;
- docstrings (the module's and the route's), which run nothing.

Everything else must be the starter's: every other route, ``create_app`` around the route,
``get_exception``'s body and its ``exception_id: str`` parameter, and every module-level
statement. A new module-level call, conditional, or assignment is rejected by position.
Formatting is invisible here: the comparison is over the syntax tree, so ``ruff format``
and comment edits change nothing.

The file is read as bytes and its source encoding is detected the way the interpreter
detects it (``tokenize.detect_encoding``): only UTF-8 is accepted, with or without a BOM or
a ``coding`` line that says so, and the validated bytes are what is parsed. Any other
declared encoding is rejected before anything is compared, because an import would decode
the file under that declaration while a text-mode read would not, and the two could
disagree about where a comment ends.

Two checks share this parsing. The **structural guard** above is what ``poe route-guard``
runs, early in ``poe verify``, and it accepts the untouched starter, so a fresh checkout
passes it. The **completion check** (``completion_findings``, read by the assessed row that
requires the principal parameter in ``tests/contract/test_exception_access.py``) additionally
requires the rule to be applied as a parameter that hands the route the verified
``Principal``: ``principal: Annotated[Principal, Depends(require_access(...))]`` or
``principal: Principal = Depends(require_access(...))``. ``dependencies=[...]`` on the
decorator protects the route but gives it no principal, so the guard permits it
structurally and the completion check names it as incomplete.

``python -m tests.security.route_guard`` (``poe route-guard``) prints the findings and exits
1 when there is one; ``--print-baseline`` prints the ``STARTER_BASELINE`` literal for the
file it is given, for the author who changes the starter route module.
"""

from __future__ import annotations

import argparse
import ast
import codecs
import copy
import difflib
import hashlib
import io
import sys
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

TASK_ROOT = Path(__file__).resolve().parents[2]
ROUTES = Path("src/api/routes.py")
ROUTE_FUNCTION = "get_exception"
APP_FACTORY = "create_app"
RULE_NAME = "require_access"
DEPENDS_NAME = "Depends"
ANNOTATED_NAME = "Annotated"
PRINCIPAL_NAME = "Principal"
# The only imports a student may add, as (module, imported name) pairs. Aliases are not
# permitted: the call form in src/api/security/access.py uses the plain names.
PERMITTED_IMPORTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("typing", ANNOTATED_NAME),
        ("fastapi", DEPENDS_NAME),
        ("api.security.access", RULE_NAME),
        ("api.security.tokens", PRINCIPAL_NAME),
    }
)
# Fields that carry no meaning for this comparison. Positions are node attributes, not
# fields, so they never enter; `type_comment` and `ctx` are fields and are skipped.
_SKIPPED_FIELDS = frozenset({"type_comment", "ctx"})
# The source encodings the file may declare or imply, as `codecs` normalises their names.
PERMITTED_ENCODINGS: frozenset[str] = frozenset({"utf-8", "utf-8-sig"})
# The forms of the rule that hand the route the verified principal: the completion check
# accepts these two and no other.
PRINCIPAL_FORMS: frozenset[str] = frozenset({"annotated", "default"})
PRINCIPAL_PARAMETER_HINT = (
    f"`{ROUTE_FUNCTION}` must receive the verified `{PRINCIPAL_NAME}` through a parameter: "
    f"`principal: {ANNOTATED_NAME}[{PRINCIPAL_NAME}, {DEPENDS_NAME}({RULE_NAME}(...))]` or "
    f"`principal: {PRINCIPAL_NAME} = {DEPENDS_NAME}({RULE_NAME}(...))`"
)


class RouteBaseline(TypedDict):
    """Hold the digests of the parts of ``get_exception`` a student must not change."""

    decorator: str
    parameter: str
    returns: str
    body: str


class Baseline(TypedDict):
    """Hold the shape of the shipped starter route module."""

    imports: tuple[str, ...]
    statements: tuple[tuple[str, str, str], ...]
    route: RouteBaseline


# The shipped starter's shape. `imports` are its `from <module> import <name>` bindings;
# `statements` are its top-level statements after the module docstring, in order, each as
# (node type, name, digest), with `create_app` digested after `get_exception` is replaced
# by a placeholder; `route` digests the parts of `get_exception` that must not change.
# Regenerate with `python -m tests.security.route_guard --print-baseline src/api/routes.py`
# after editing the starter route module; the authoring suite checks that the two agree.
STARTER_BASELINE: Baseline = {
    "imports": (
        "api.document_service:DocumentService",
        "api.document_service:DocumentsUnavailable",
        "api.experiment:ExperimentRetrieval",
        "api.experiment:TOP_K_LIMIT",
        "api.retrieval_workflow:RetrievalWorkflow",
        "api.security.tokens:TokenVerifier",
        "api.use_cases:InRangeReading",
        "api.use_cases:QueueUnavailable",
        "api.use_cases:ReadingApplication",
        "api.use_cases:TerminalExceptionConflict",
        "collections.abc:Awaitable",
        "collections.abc:Callable",
        "domain.contracts:AccessTier",
        "domain.contracts:AuthorizationContext",
        "domain.contracts:Candidate",
        "domain.contracts:ChunkRecord",
        "domain.contracts:DocumentRecord",
        "domain.contracts:ExceptionRecord",
        "domain.contracts:SensorReading",
        "domain.contracts:StageEvidence",
        "domain.failures:ObjectStoreUnavailable",
        "domain.failures:RetrievalUnavailable",
        "domain.repositories:ExceptionRepository",
        "domain.repositories:RepositoryError",
        "fastapi:APIRouter",
        "fastapi:FastAPI",
        "fastapi:HTTPException",
        "fastapi:Query",
        "fastapi:Request",
        "fastapi:Response",
        "fastapi:status",
        "opentelemetry:trace",
        "prometheus_client:CONTENT_TYPE_LATEST",
        "prometheus_client:Counter",
        "prometheus_client:Histogram",
        "prometheus_client:generate_latest",
        "pydantic:BaseModel",
        "pydantic:ConfigDict",
        "pydantic:Field",
        "starlette.types:Lifespan",
        "time:perf_counter",
    ),
    "statements": (
        ("Assign", "_REQUESTS", "9ccd4aa7730efed77a55"),
        ("Assign", "_REQUEST_DURATION", "e53134466828ae6f05d0"),
        ("Assign", "_KNOWN_ROUTES", "33b45ac75e9b4a774f20"),
        ("ClassDef", "AcceptedReading", "7be2c624bff6b88c210a"),
        ("ClassDef", "SearchRequest", "69bee479ca25142a174b"),
        ("ClassDef", "ExperimentRequest", "b88fcd725bbfe48bea58"),
        ("ClassDef", "ExperimentResponse", "853eb44477c5b03e6503"),
        ("ClassDef", "SearchResponse", "3b6dfddb6f8192497eb8"),
        ("ClassDef", "CorpusObjects", "7de1f90bb960560cd46a"),
        ("ClassDef", "StoredDocument", "fa9322b7916704f46105"),
        ("ClassDef", "DocumentListing", "9c763171ba399de9eda2"),
        ("ClassDef", "ChunkListing", "be8c5c26a0088b8c14cc"),
        ("AsyncFunctionDef", "_ready_by_default", "db6ba89e1cf36924c026"),
        ("FunctionDef", "create_app", "872f8f2c05f1ecefb857"),
        ("FunctionDef", "_route_label", "7b30f2081e5379d45a81"),
    ),
    "route": {
        "decorator": "5d2baddccb3a8cf62cf1",
        "parameter": "372e98dccf685ce0fa94",
        "returns": "11d9a8a24e1b7cd45bc2",
        "body": "c3a6db1022092e7f5119",
    },
}


class RouteGuardError(ValueError):
    """Report that the route module could not be read or has no starter shape at all."""


def canonical(node: object) -> str:
    """Return a position-free rendering of one syntax tree, stable across formatting."""
    if isinstance(node, ast.AST):
        fields = ",".join(
            f"{name}={canonical(value)}"
            for name, value in ast.iter_fields(node)
            if name not in _SKIPPED_FIELDS
        )
        return f"{type(node).__name__}({fields})"
    if isinstance(node, list):
        return "[" + ",".join(canonical(item) for item in node) + "]"
    return repr(node)


def digest(node: object) -> str:
    """Return a short digest of ``canonical(node)``."""
    return hashlib.sha256(canonical(node).encode("utf-8")).hexdigest()[:20]


def _is_docstring(node: ast.stmt) -> bool:
    """Return whether a statement is a bare string expression, which runs nothing."""
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Return a body without its leading docstring."""
    return body[1:] if body and _is_docstring(body[0]) else list(body)


def _import_bindings(tree: ast.Module) -> tuple[set[str], list[str]]:
    """Return the module's `from` bindings as `module:name`, and findings for other forms."""
    bindings: set[str] = set()
    findings: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            names = ", ".join(alias.name for alias in node.names)
            findings.append(f"`import {names}` is not a permitted import")
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.asname is not None:
                    findings.append(
                        f"`from {module} import {alias.name} as {alias.asname}` is aliased"
                    )
                bindings.add(f"{module}:{alias.name}")
    return bindings, findings


def _label(node: ast.stmt) -> str:
    """Return a short name for one top-level statement, for a finding."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return node.name
    if isinstance(node, ast.Assign) and node.targets and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return "-"


def _factories(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Return every top-level ``create_app`` definition."""
    return [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == APP_FACTORY
    ]


def _routes_in(factory: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AsyncFunctionDef]:
    """Return every ``get_exception`` definition nested anywhere in ``create_app``."""
    return [
        node
        for node in ast.walk(factory)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == ROUTE_FUNCTION
    ]


def _with_route_excised(
    factory: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Return a copy of ``create_app`` with ``get_exception`` replaced by a placeholder."""
    duplicate = copy.deepcopy(factory)
    for parent in ast.walk(duplicate):
        body = getattr(parent, "body", None)
        if not isinstance(body, list):
            continue
        for index, child in enumerate(body):
            if isinstance(child, ast.AsyncFunctionDef) and child.name == ROUTE_FUNCTION:
                body[index] = ast.Pass()
    return duplicate


def _statements(tree: ast.Module) -> list[tuple[str, str, str]]:
    """Return (type, name, digest) for every top-level statement that is not an import."""
    rows: list[tuple[str, str, str]] = []
    for node in _without_docstring(tree.body):
        if isinstance(node, ast.Import | ast.ImportFrom):
            continue
        target: ast.AST = node
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == APP_FACTORY:
            target = _with_route_excised(node)
        rows.append((type(node).__name__, _label(node), digest(target)))
    return rows


@dataclass(frozen=True)
class RuleApplication:
    """Record one place the route applies the rule, its form, and why it is malformed.

    ``form`` is ``annotated`` (an ``Annotated[Principal, Depends(...)]`` parameter),
    ``default`` (a ``Principal``-annotated parameter whose default is the rule),
    ``default-unannotated`` (the same without the annotation), or ``decorator``
    (``dependencies=[...]`` on the route decorator). Only the first two hand the route the
    verified principal.
    """

    where: str
    form: str
    problems: list[str] = field(default_factory=list)


def _rule_problems(call: ast.expr, where: str) -> list[str]:
    """Return why ``call`` is not exactly ``Depends(require_access(role="..", scope=".."))``."""
    problems: list[str] = []
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == DEPENDS_NAME
    ):
        return [f"{where}: expected `{DEPENDS_NAME}(...)`, found `{ast.unparse(call)}`"]
    if len(call.args) != 1 or call.keywords:
        return [f"{where}: `{DEPENDS_NAME}` takes exactly one positional argument, the rule"]
    rule = call.args[0]
    if not (
        isinstance(rule, ast.Call) and isinstance(rule.func, ast.Name) and rule.func.id == RULE_NAME
    ):
        return [f"{where}: expected `{RULE_NAME}(...)` inside `{DEPENDS_NAME}`"]
    if rule.args:
        problems.append(f"{where}: `{RULE_NAME}` takes `role=` and `scope=` as keywords")
    keywords = {keyword.arg: keyword.value for keyword in rule.keywords}
    if set(keywords) != {"role", "scope"} or len(keywords) != len(rule.keywords):
        problems.append(f"{where}: `{RULE_NAME}` takes exactly `role=` and `scope=`")
    for name, value in keywords.items():
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value):
            problems.append(f"{where}: `{name}=` must be a non-empty string literal")
    return problems


def _annotated_rule(annotation: ast.expr | None) -> ast.expr | None:
    """Return the second element of an ``Annotated[Principal, ...]`` annotation, if that is it."""
    if not (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == ANNOTATED_NAME
        and isinstance(annotation.slice, ast.Tuple)
        and len(annotation.slice.elts) == 2
    ):
        return None
    first, second = annotation.slice.elts
    if not (isinstance(first, ast.Name) and first.id == PRINCIPAL_NAME):
        return None
    return second


def _mentions_rule(node: ast.AST | None) -> bool:
    """Return whether ``node`` contains a call to the rule or to ``Depends``."""
    if node is None:
        return False
    return any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id in {RULE_NAME, DEPENDS_NAME}
        for child in ast.walk(node)
    )


def _parameter_applications(
    route: ast.AsyncFunctionDef, starter_parameter: str
) -> tuple[list[RuleApplication], list[str]]:
    """Validate the route's parameters: the starter's first, then at most one rule parameter."""
    findings: list[str] = []
    applications: list[RuleApplication] = []
    arguments = route.args
    if arguments.posonlyargs or arguments.vararg or arguments.kwarg:
        findings.append(
            f"`{ROUTE_FUNCTION}` gained positional-only, `*args`, or `**kwargs` parameters"
        )
    positional = list(arguments.args)
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(arguments.defaults))
    defaults.extend(arguments.defaults)
    if not positional or digest(positional[0]) != starter_parameter or defaults[0] is not None:
        findings.append(
            f"`{ROUTE_FUNCTION}`'s first parameter must stay the starter's `exception_id: str`"
        )
    extras = list(zip(positional[1:], defaults[1:], strict=True)) + list(
        zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True)
    )
    for argument, default in extras:
        where = f"parameter `{argument.arg}`"
        annotated = _annotated_rule(argument.annotation)
        if annotated is not None:
            problems = _rule_problems(annotated, where)
            if default is not None:
                problems.append(f"{where}: an `{ANNOTATED_NAME}` rule parameter takes no default")
            applications.append(RuleApplication(where, "annotated", problems))
            continue
        if default is not None and _mentions_rule(default):
            problems = _rule_problems(default, where)
            annotation = argument.annotation
            form = "default-unannotated" if annotation is None else "default"
            if annotation is not None and not (
                isinstance(annotation, ast.Name) and annotation.id == PRINCIPAL_NAME
            ):
                problems.append(
                    f"{where}: the annotation must be `{PRINCIPAL_NAME}` or absent when the "
                    "rule is the default"
                )
            applications.append(RuleApplication(where, form, problems))
            continue
        findings.append(
            f"{where} is not a rule parameter; only `{DEPENDS_NAME}({RULE_NAME}(...))` may be "
            f"added to `{ROUTE_FUNCTION}`"
        )
    return applications, findings


def _decorator_applications(
    route: ast.AsyncFunctionDef, starter_decorator: str
) -> tuple[list[RuleApplication], list[str]]:
    """Validate the route decorator: the starter's call, plus at most `dependencies=[rule]`."""
    if len(route.decorator_list) != 1:
        return [], [f"`{ROUTE_FUNCTION}` must keep exactly one decorator, the starter's `@app.get`"]
    decorator = route.decorator_list[0]
    if not isinstance(decorator, ast.Call):
        return [], [f"`{ROUTE_FUNCTION}`'s decorator is not the starter's `@app.get(...)` call"]
    applications: list[RuleApplication] = []
    kept: list[ast.keyword] = []
    for keyword in decorator.keywords:
        if keyword.arg != "dependencies":
            kept.append(keyword)
            continue
        where = "decorator keyword `dependencies`"
        value = keyword.value
        if not (isinstance(value, ast.List | ast.Tuple) and len(value.elts) == 1):
            problems = [f"{where}: must be a one-element list holding the rule"]
            applications.append(RuleApplication(where, "decorator", problems))
            continue
        applications.append(
            RuleApplication(where, "decorator", _rule_problems(value.elts[0], where))
        )
    stripped = ast.Call(func=decorator.func, args=decorator.args, keywords=kept)
    findings: list[str] = []
    if digest(stripped) != starter_decorator:
        findings.append(
            f"`{ROUTE_FUNCTION}`'s decorator changed beyond adding `dependencies=[...]`"
        )
    return applications, findings


def _applications(
    route: ast.AsyncFunctionDef, baseline: RouteBaseline
) -> tuple[list[RuleApplication], list[str]]:
    """Return every rule application on the route, and the findings about its head."""
    parameter_rules, parameter_findings = _parameter_applications(route, baseline["parameter"])
    decorator_rules, decorator_findings = _decorator_applications(route, baseline["decorator"])
    return parameter_rules + decorator_rules, parameter_findings + decorator_findings


def _application_findings(applications: list[RuleApplication]) -> list[str]:
    """Return each application's problems, and one finding when the rule is applied twice."""
    findings: list[str] = []
    for application in applications:
        findings.extend(application.problems)
    if len(applications) > 1:
        places = ", ".join(application.where for application in applications)
        findings.append(
            f"`{ROUTE_FUNCTION}` applies the rule {len(applications)} times ({places}); "
            "apply it once"
        )
    return findings


def _route_findings(route: ast.AsyncFunctionDef, baseline: RouteBaseline) -> list[str]:
    """Return why ``get_exception`` differs from the starter beyond one rule application."""
    findings: list[str] = []
    if route.type_params:
        findings.append(f"`{ROUTE_FUNCTION}` gained type parameters")
    if digest(route.returns) != baseline["returns"]:
        findings.append(f"`{ROUTE_FUNCTION}`'s return annotation changed")
    if digest(_without_docstring(route.body)) != baseline["body"]:
        findings.append(f"`{ROUTE_FUNCTION}`'s body changed; only its docstring may differ")
    applications, head_findings = _applications(route, baseline)
    findings.extend(head_findings)
    findings.extend(_application_findings(applications))
    return findings


def _statement_findings(
    expected: tuple[tuple[str, str, str], ...], actual: list[tuple[str, str, str]]
) -> list[str]:
    """Return how the module's top-level statements differ from the starter's.

    The two statement lists are aligned as sequences, so one injected statement is
    reported once, as an addition, rather than as a shift of everything after it.
    """
    findings: list[str] = []
    matcher = difflib.SequenceMatcher(None, expected, actual, autojunk=False)
    for tag, start, end, begin, stop in matcher.get_opcodes():
        if tag == "equal":
            continue
        wanted, present = expected[start:end], actual[begin:stop]
        same_shape = len(wanted) == len(present) and all(
            want[:2] == have[:2] for want, have in zip(wanted, present, strict=True)
        )
        if tag == "replace" and same_shape:
            for offset, (kind, name, _) in enumerate(present, start=begin + 1):
                if name == APP_FACTORY:
                    findings.append(
                        f"statement {offset}: `{APP_FACTORY}` changed outside `{ROUTE_FUNCTION}`"
                    )
                elif name == "-":
                    findings.append(f"statement {offset}: the {kind} statement changed")
                else:
                    findings.append(f"statement {offset}: `{name}` changed")
            continue
        for kind, name, _ in wanted:
            findings.append(f"the starter's {kind} `{name}` was removed")
        for offset, (kind, name, _) in enumerate(present, start=begin + 1):
            label = f" `{name}`" if name != "-" else ""
            findings.append(f"statement {offset}: a module-level {kind}{label} was added")
    return findings


def encoding_findings(source: bytes) -> list[str]:
    """Return why the file's source encoding is not UTF-8, detected as the interpreter does.

    ``tokenize.detect_encoding`` reads the BOM and the ``coding`` declaration in the first
    two lines exactly as an import would. A UTF-8 BOM and a declaration naming UTF-8 are
    accepted; every other declared encoding is a finding, because the interpreter would
    decode the file under it and the comparison below must see the same text an import
    sees.
    """
    try:
        declared, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
    except SyntaxError as exc:
        return [f"{ROUTES.as_posix()} declares an unusable source encoding: {exc}"]
    try:
        name = codecs.lookup(declared).name
    except LookupError:
        name = declared
    if name not in PERMITTED_ENCODINGS:
        return [
            f"{ROUTES.as_posix()} declares the source encoding {declared!r}; only UTF-8 is "
            "permitted (remove the `coding` declaration)"
        ]
    return []


def _parse(source: str | bytes) -> tuple[ast.Module | None, list[str]]:
    """Parse the route module, validating a byte source's encoding first; or say why not."""
    if isinstance(source, bytes):
        rejected = encoding_findings(source)
        if rejected:
            return None, rejected
    try:
        return ast.parse(source), []
    except SyntaxError as exc:
        return None, [f"{ROUTES.as_posix()} is not valid Python: {exc}"]
    except ValueError as exc:
        return None, [f"{ROUTES.as_posix()} could not be decoded as UTF-8: {exc}"]


def findings_for_source(source: str | bytes, baseline: Baseline | None = None) -> list[str]:
    """Return every way ``source`` differs from the starter beyond the permitted edits.

    Bytes are what the file holds and are parsed as such after their encoding is validated;
    a string is already-decoded text, for callers that build modules in memory.
    """
    reference = STARTER_BASELINE if baseline is None else baseline
    tree, findings = _parse(source)
    if tree is None:
        return findings
    bindings, findings = _import_bindings(tree)
    expected_imports = set(reference["imports"])
    for binding in sorted(bindings - expected_imports):
        module, _, name = binding.partition(":")
        if (module, name) not in PERMITTED_IMPORTS:
            findings.append(f"`from {module} import {name}` is not a permitted import")
    for binding in sorted(expected_imports - bindings):
        module, _, name = binding.partition(":")
        findings.append(f"the starter's `from {module} import {name}` was removed")
    findings.extend(_statement_findings(reference["statements"], _statements(tree)))
    routes = [route for factory in _factories(tree) for route in _routes_in(factory)]
    if len(routes) != 1:
        findings.append(
            f"`{APP_FACTORY}` must define `{ROUTE_FUNCTION}` exactly once; found {len(routes)}"
        )
    else:
        findings.extend(_route_findings(routes[0], reference["route"]))
    return findings


def completion_findings(source: str | bytes, baseline: Baseline | None = None) -> list[str]:
    """Return why ``get_exception`` does not yet receive the principal through the rule.

    The completion the Task asks for is one application of the rule as a parameter of the
    route, so the handler is handed the verified ``Principal``: the ``Annotated`` form or the
    ``Principal``-annotated default form. The untouched starter (no rule), a decorator-only
    ``dependencies=[...]`` application, an unannotated default parameter, and a malformed or
    repeated application are each named. The structural guard accepts the first two of
    those; this check is the assessed completion row, and it never imports the file either.
    """
    reference = STARTER_BASELINE if baseline is None else baseline
    tree, findings = _parse(source)
    if tree is None:
        return findings
    routes = [route for factory in _factories(tree) for route in _routes_in(factory)]
    if len(routes) != 1:
        return [f"`{APP_FACTORY}` must define `{ROUTE_FUNCTION}` exactly once; found {len(routes)}"]
    applications, head_findings = _applications(routes[0], reference["route"])
    findings = list(head_findings) + _application_findings(applications)
    if not applications:
        findings.append(
            f"`{ROUTE_FUNCTION}` applies no `{DEPENDS_NAME}({RULE_NAME}(...))` yet; "
            + PRINCIPAL_PARAMETER_HINT
        )
    elif len(applications) == 1 and applications[0].form not in PRINCIPAL_FORMS:
        [application] = applications
        if application.form == "decorator":
            findings.append(
                f"{application.where}: the rule protects the route but hands it no principal; "
                + PRINCIPAL_PARAMETER_HINT
            )
        else:
            findings.append(
                f"{application.where}: the rule parameter is not annotated `{PRINCIPAL_NAME}`; "
                + PRINCIPAL_PARAMETER_HINT
            )
    return findings


def read_source(path: Path = TASK_ROOT / ROUTES) -> bytes:
    """Return the route module's bytes, or raise ``RouteGuardError`` if it cannot be read."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RouteGuardError(f"{ROUTES.as_posix()} could not be read: {exc}") from exc


def findings(path: Path = TASK_ROOT / ROUTES) -> list[str]:
    """Return the structural findings for the route module at ``path``, read as bytes."""
    return findings_for_source(read_source(path))


def completion(path: Path = TASK_ROOT / ROUTES) -> list[str]:
    """Return the completion findings for the route module at ``path``, read as bytes."""
    return completion_findings(read_source(path))


def baseline_of(source: str | bytes) -> Baseline:
    """Return the ``STARTER_BASELINE`` value for a route module shaped like the starter."""
    tree, problems = _parse(source)
    if tree is None:
        raise RouteGuardError("; ".join(problems))
    bindings, problems = _import_bindings(tree)
    if problems:
        raise RouteGuardError("; ".join(problems))
    routes = [route for factory in _factories(tree) for route in _routes_in(factory)]
    if len(routes) != 1:
        raise RouteGuardError(
            f"the module must define `{ROUTE_FUNCTION}` once inside `{APP_FACTORY}`"
        )
    route = routes[0]
    if len(route.decorator_list) != 1 or not isinstance(route.decorator_list[0], ast.Call):
        raise RouteGuardError(f"`{ROUTE_FUNCTION}` must carry one `@app.get(...)` decorator")
    if not route.args.args:
        raise RouteGuardError(f"`{ROUTE_FUNCTION}` must take `exception_id: str`")
    return {
        "imports": tuple(sorted(bindings)),
        "statements": tuple(_statements(tree)),
        "route": {
            "decorator": digest(route.decorator_list[0]),
            "parameter": digest(route.args.args[0]),
            "returns": digest(route.returns),
            "body": digest(_without_docstring(route.body)),
        },
    }


def render_baseline(baseline: Baseline) -> str:
    """Render a baseline as the Python literal this module embeds."""
    lines = ["STARTER_BASELINE: Baseline = {", '    "imports": (']
    lines.extend(f"        {binding!r}," for binding in baseline["imports"])
    lines.extend(["    ),", '    "statements": ('])
    lines.extend(f"        {row!r}," for row in baseline["statements"])
    lines.extend(["    ),", '    "route": {'])
    lines.extend(f"        {key!r}: {value!r}," for key, value in baseline["route"].items())
    lines.extend(["    },", "}"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Check the route module and print the findings, or print a baseline."""
    parser = argparse.ArgumentParser(description="Check src/api/routes.py against the starter.")
    parser.add_argument("path", nargs="?", type=Path, default=TASK_ROOT / ROUTES)
    parser.add_argument(
        "--print-baseline",
        action="store_true",
        help="print the STARTER_BASELINE literal for the given file instead of checking it",
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.print_baseline:
            print(render_baseline(baseline_of(read_source(arguments.path))))
            return 0
        found = findings(arguments.path)
    except (RouteGuardError, SyntaxError, OSError) as exc:
        print(f"route-guard: {exc}", file=sys.stderr)
        return 2
    if found:
        print(
            f"route-guard: {ROUTES.as_posix()} changed more than the access rule on "
            f"`{ROUTE_FUNCTION}`:",
            file=sys.stderr,
        )
        for finding in found:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print(
        f"route-guard: {ROUTES.as_posix()} changed nothing but the access rule on "
        f"`{ROUTE_FUNCTION}`."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
